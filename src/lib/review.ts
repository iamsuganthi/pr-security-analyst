import { Octokit } from "@octokit/rest";
import {
  buildSummaryComment,
  hasCriticalFindings,
  mapFindingsToReviewComments,
  runSecurityReview,
} from "./agent";
import {
  createCheckRun,
  fetchPullRequestDiff,
  fetchPullRequestFiles,
  formatFindingComment,
  postPullRequestReview,
  updateCheckRun,
} from "./github";
import { withSandbox } from "./sandbox";
import { PullRequestContext } from "./types";

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

    const { result: review, degraded } = await withSandbox(
      {
        cloneUrl,
        revision: ctx.headSha,
        username: "x-access-token",
        password: tokenData.token,
      },
      async (sandbox) =>
        runSecurityReview({
          diff,
          files,
          sandbox,
          signal,
        }),
    );

    const degradedLayers = [...review.degradedLayers];
    if (degraded) degradedLayers.push("sandbox");

    const reviewResult = { ...review, degradedLayers };
    const inlineComments = mapFindingsToReviewComments(reviewResult.findings, files);

    const summaryBody = buildSummaryComment(reviewResult);
    const event = hasCriticalFindings(reviewResult.findings) ? "REQUEST_CHANGES" : "COMMENT";

    await postPullRequestReview(octokit, {
      owner: ctx.owner,
      repo: ctx.repo,
      pullNumber: ctx.pullNumber,
      commitId: ctx.headSha,
      body: summaryBody,
      comments: inlineComments,
      event,
    });

    const conclusion = hasCriticalFindings(reviewResult.findings) ? "failure" : "success";
    const detailLines = reviewResult.findings.map((f) =>
      formatFindingComment(f),
    );

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
