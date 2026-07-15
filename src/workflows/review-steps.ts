import {
  DependencyAutofixResult,
  formatAutofixCommitMessage,
} from "../lib/dependency-autofix";
import { commitFilesToBranch, PullRequestReviewInputs } from "../lib/github-steps";
import { PullRequestContext, ReviewResult } from "../lib/types";

interface ReviewWithAutofix {
  review: ReviewResult;
  autofix: DependencyAutofixResult;
}

export interface AutofixCommitOutcome {
  reviewHeadSha: string;
  autofixCommitSha?: string;
  autofixCommitError?: string;
  degradedLayers: string[];
  review: ReviewResult;
}

export async function runSandboxReview(
  ctx: PullRequestContext,
  inputs: PullRequestReviewInputs,
): Promise<{ payload: ReviewWithAutofix; sandboxDegraded: boolean }> {
  "use step";
  const { withSandbox } = await import("../lib/sandbox");
  const { runSecurityReview } = await import("../lib/agent");
  const { applyDependencyAutofixInSandbox } = await import("../lib/dependency-autofix");

  const { result, degraded } = await withSandbox<ReviewWithAutofix>(
    {
      cloneUrl: inputs.cloneUrl,
      revision: ctx.headSha,
      username: "x-access-token",
      password: inputs.installToken,
    },
    async (sandbox) => {
      const review = await runSecurityReview({
        diff: inputs.diff,
        files: inputs.files,
        sandbox,
      });

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

  return { payload: result, sandboxDegraded: degraded };
}

export async function commitAutofixIfApplied(
  ctx: PullRequestContext,
  payload: ReviewWithAutofix,
): Promise<AutofixCommitOutcome> {
  "use step";
  let reviewHeadSha = ctx.headSha;
  let autofixCommitSha: string | undefined;
  let autofixCommitError: string | undefined;
  const degradedLayers: string[] = [];
  let review = payload.review;

  if (payload.autofix.applied) {
    try {
      const { commitSha } = await commitFilesToBranch(ctx.installationId, {
        owner: ctx.headOwner,
        repo: ctx.headRepo,
        branch: ctx.headRef,
        message: formatAutofixCommitMessage(payload.autofix.packages),
        files: payload.autofix.files,
      });
      autofixCommitSha = commitSha;
      reviewHeadSha = commitSha;
      review = {
        ...review,
        metadata: {
          ...review.metadata,
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
  } else if (payload.autofix.error && payload.autofix.packages.length > 0) {
    degradedLayers.push("autofix");
  }

  return {
    reviewHeadSha,
    autofixCommitSha,
    autofixCommitError,
    degradedLayers,
    review,
  };
}
