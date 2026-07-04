import { Octokit } from "@octokit/rest";
import {
  buildSummaryComment,
  hasCriticalFindings,
  mapFindingsToReviewComments,
  runSecurityReview,
} from "./agent";
import {
  applyDependencyAutofixInSandbox,
  formatAutofixCommitMessage,
  isDependencyAutofixEnabled,
} from "./dependency-autofix";
import {
  commitFilesToBranch,
  createCheckRun,
  fetchPullRequestDiff,
  fetchPullRequestFiles,
  formatFindingComment,
  postPullRequestReview,
  updateCheckRun,
} from "./github";
import { withSandbox } from "./sandbox";
import { PullRequestContext, ReviewResult } from "./types";

export async function runPullRequestReview(
  octokit: Octokit,
  ctx: PullRequestContext,
  signal?: AbortSignal,
): Promise<void> {
  const checkRunId = await createCheckRun(octokit, {
    owner: ctx.owner,
    repo: ctx.repo,
    headSha: ctx.headSha,
    status: "in_progress",
    output: {
      title: "SecureReview in progress",
      summary: "Running AI security review (triage → OSV → agent tools)…",
    },
    externalId: ctx.deliveryId,
  });

  try {
    const [diff, files] = await Promise.all([
      fetchPullRequestDiff(octokit, ctx.owner, ctx.repo, ctx.pullNumber),
      fetchPullRequestFiles(octokit, ctx.owner, ctx.repo, ctx.pullNumber),
    ]);

    const { data: repoData } = await octokit.repos.get({
      owner: ctx.owner,
      repo: ctx.repo,
    });

    const { data: tokenData } = await octokit.apps.createInstallationAccessToken({
      installation_id: ctx.installationId,
    });

    const cloneUrl = repoData.clone_url.replace(
      "https://",
      `https://x-access-token:${tokenData.token}@`,
    );

    let reviewHeadSha = ctx.headSha;
    let autofixNote = "";
    const degradedLayers: string[] = [];

    const { result: review, degraded } = await withSandbox(
      {
        cloneUrl,
        revision: ctx.headSha,
        username: "x-access-token",
        password: tokenData.token,
      },
      async (sandbox) => {
        const reviewResult = await runSecurityReview({
          diff,
          files,
          sandbox,
          signal,
        });

        if (!isDependencyAutofixEnabled()) {
          return reviewResult;
        }

        const autofix = await applyDependencyAutofixInSandbox(sandbox, reviewResult.findings);
        if (!autofix.applied) {
          if (autofix.error && autofix.packages.length > 0) {
            degradedLayers.push("autofix");
            autofixNote = `\n\n> Dependency autofix skipped: ${autofix.error}`;
          }
          return reviewResult;
        }

        try {
          const { commitSha } = await commitFilesToBranch(octokit, {
            owner: ctx.owner,
            repo: ctx.repo,
            branch: ctx.headRef,
            message: formatAutofixCommitMessage(autofix.packages),
            files: autofix.files,
          });

          reviewHeadSha = commitSha;
          autofixNote = `\n\n### Dependency autofix\n\nSecureReview committed patched versions to this branch (\`${commitSha.slice(0, 7)}\`):\n${autofix.packages
            .map((u) => `- \`${u.name}\`: ${u.fromVersion ?? "?"} → \`${u.toVersion}\``)
            .join("\n")}`;

          return {
            ...reviewResult,
            metadata: {
              ...reviewResult.metadata,
              autofixCommitSha: commitSha,
              autofixPackages: autofix.packages.map((u) => u.name),
            },
          } satisfies ReviewResult;
        } catch (err) {
          degradedLayers.push("autofix");
          const message = err instanceof Error ? err.message : "commit failed";
          autofixNote = `\n\n> Dependency autofix failed: ${message}`;
          return reviewResult;
        }
      },
    );

    degradedLayers.push(...review.degradedLayers);
    if (degraded) degradedLayers.push("sandbox");

    const reviewResult = { ...review, degradedLayers };
    const inlineComments = mapFindingsToReviewComments(reviewResult.findings, files);

    let summaryBody = buildSummaryComment(reviewResult);
    if (autofixNote) summaryBody += autofixNote;

    const event = hasCriticalFindings(reviewResult.findings) ? "REQUEST_CHANGES" : "COMMENT";

    await postPullRequestReview(octokit, {
      owner: ctx.owner,
      repo: ctx.repo,
      pullNumber: ctx.pullNumber,
      commitId: reviewHeadSha,
      body: summaryBody,
      comments: inlineComments,
      event,
    });

    const conclusion = hasCriticalFindings(reviewResult.findings) ? "failure" : "success";
    const detailLines = reviewResult.findings.map((f) => formatFindingComment(f));

    await updateCheckRun(octokit, {
      owner: ctx.owner,
      repo: ctx.repo,
      checkRunId,
      status: "completed",
      conclusion,
      output: {
        title: reviewResult.summary,
        summary: summaryBody,
        text: detailLines.join("\n\n---\n\n"),
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    await updateCheckRun(octokit, {
      owner: ctx.owner,
      repo: ctx.repo,
      checkRunId,
      status: "completed",
      conclusion: "failure",
      output: {
        title: "SecureReview failed",
        summary: `Review failed: ${message}`,
      },
    });
    throw err;
  }
}
