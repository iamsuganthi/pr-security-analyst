import { formatAutofixStatusNote } from "../lib/dependency-autofix";
import {
  createCheckRun,
  fetchPullRequestReviewInputs,
  postPullRequestReview,
  updateCheckRun,
} from "../lib/github-steps";
import {
  buildSummaryComment,
  formatFindingMarkdown,
  hasBlockingFindings,
  mapFindingsToReviewComments,
} from "../lib/review-format";
import { PullRequestContext } from "../lib/types";
import { commitAutofixIfApplied, runSandboxReview } from "./review-steps";

export async function runPullRequestReview(ctx: PullRequestContext): Promise<void> {
  "use workflow";
  const { installationId } = ctx;

  const checkRunId = await createCheckRun(installationId, {
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
    const inputs = await fetchPullRequestReviewInputs(installationId, {
      owner: ctx.owner,
      repo: ctx.repo,
      pullNumber: ctx.pullNumber,
    });
    const { payload, sandboxDegraded } = await runSandboxReview(ctx, inputs);
    const autofixOutcome = await commitAutofixIfApplied(ctx, payload);

    const degradedLayers = [
      ...autofixOutcome.degradedLayers,
      ...autofixOutcome.review.degradedLayers,
    ];
    if (sandboxDegraded) degradedLayers.push("sandbox");

    const reviewResult = { ...autofixOutcome.review, degradedLayers };
    const inlineComments = mapFindingsToReviewComments(reviewResult.findings, inputs.files);

    let summaryBody = buildSummaryComment(reviewResult);
    summaryBody += formatAutofixStatusNote({
      result: payload.autofix,
      commitSha: autofixOutcome.autofixCommitSha,
      commitError: autofixOutcome.autofixCommitError,
    });

    const event = hasBlockingFindings(reviewResult.findings) ? "REQUEST_CHANGES" : "COMMENT";

    await postPullRequestReview(installationId, {
      owner: ctx.owner,
      repo: ctx.repo,
      pullNumber: ctx.pullNumber,
      commitId: autofixOutcome.reviewHeadSha,
      body: summaryBody,
      comments: inlineComments,
      event,
    });

    const conclusion = hasBlockingFindings(reviewResult.findings) ? "failure" : "success";
    const detailLines = reviewResult.findings.map((f) => formatFindingMarkdown(f, "check"));

    await updateCheckRun(installationId, {
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
    await updateCheckRun(installationId, {
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
