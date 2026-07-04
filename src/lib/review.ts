import { Octokit } from "@octokit/rest";
import {
  buildSummaryComment,
  hasCriticalFindings,
  mapFindingsToReviewComments,
  runSecurityReview,
} from "./agent";
import {
  applyDependencyAutofixInSandbox,
  DependencyAutofixResult,
  formatAutofixCommitMessage,
  formatAutofixStatusNote,
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

interface ReviewWithAutofix {
  review: ReviewResult;
  autofix: DependencyAutofixResult | null;
}

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
    let autofixCommitSha: string | undefined;
    let autofixCommitError: string | undefined;
    const degradedLayers: string[] = [];
    const autofixEnabled = isDependencyAutofixEnabled();

    const { result: payload, degraded } = await withSandbox<ReviewWithAutofix>(
      {
        cloneUrl,
        revision: ctx.headSha,
        username: "x-access-token",
        password: tokenData.token,
      },
      async (sandbox) => {
        const review = await runSecurityReview({
          diff,
          files,
          sandbox,
          signal,
        });

        if (!autofixEnabled) {
          return { review, autofix: null };
        }

        const autofix = await applyDependencyAutofixInSandbox(sandbox, review.findings);
        console.error(
          "Autofix sandbox result:",
          autofix.applied,
          autofix.error ?? "",
          autofix.packages.map((p) => p.name).join(","),
        );
        return { review, autofix };
      },
    );

    if (autofixEnabled && payload.autofix?.applied) {
      try {
        const { commitSha } = await commitFilesToBranch(octokit, {
          owner: ctx.headOwner,
          repo: ctx.headRepo,
          branch: ctx.headRef,
          message: formatAutofixCommitMessage(payload.autofix.packages),
          files: payload.autofix.files,
        });
        autofixCommitSha = commitSha;
        reviewHeadSha = commitSha;
        payload.review = {
          ...payload.review,
          metadata: {
            ...payload.review.metadata,
            autofixCommitSha: commitSha,
            autofixPackages: payload.autofix.packages.map((u) => u.name),
          },
        };
        console.error("Autofix commit:", commitSha);
      } catch (err) {
        autofixCommitError = err instanceof Error ? err.message : "commit failed";
        degradedLayers.push("autofix");
        console.error("Autofix commit failed:", autofixCommitError);
      }
    } else if (autofixEnabled && payload.autofix?.error && (payload.autofix.packages.length ?? 0) > 0) {
      degradedLayers.push("autofix");
    }

    degradedLayers.push(...payload.review.degradedLayers);
    if (degraded) degradedLayers.push("sandbox");

    const reviewResult = { ...payload.review, degradedLayers };
    const inlineComments = mapFindingsToReviewComments(reviewResult.findings, files);

    let summaryBody = buildSummaryComment(reviewResult);
    summaryBody += formatAutofixStatusNote({
      enabled: autofixEnabled,
      result: payload.autofix,
      commitSha: autofixCommitSha,
      commitError: autofixCommitError,
    });

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
