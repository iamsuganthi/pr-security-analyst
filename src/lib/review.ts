import { Octokit } from "@octokit/rest";
import { runSecurityReview } from "./agent";
import {
  applyDependencyAutofixInSandbox,
  DependencyAutofixResult,
  formatAutofixCommitMessage,
  formatAutofixStatusNote,
} from "./dependency-autofix";
import {
  commitFilesToBranch,
  createCheckRun,
  fetchPullRequestReviewInputs,
  postPullRequestReview,
  PullRequestReviewInputs,
  updateCheckRun,
} from "./github";
import { withSandbox } from "./sandbox";
import { Finding, PullRequestContext, ReviewResult } from "./types";

function formatFindingMarkdown(
  finding: Finding,
  style: "inline" | "check" | "summary",
): string {
  if (style === "inline") {
    return [
      `**${finding.severity.toUpperCase()}** · ${finding.owaspCategory}`,
      finding.message,
      "",
      `**Fix:** ${finding.suggestedFix}`,
      `_Source: ${finding.source}_`,
    ].join("\n");
  }

  if (style === "summary") {
    return `- **${finding.severity.toUpperCase()}** \`${finding.file}:${finding.line}\` · ${finding.owaspCategory} · ${finding.message} _(source: ${finding.source})_`;
  }

  return [
    `**${finding.severity.toUpperCase()}** · ${finding.owaspCategory}${finding.cwe ? ` · ${finding.cwe}` : ""}`,
    "",
    finding.message,
    "",
    `**Suggested fix:** ${finding.suggestedFix}`,
    "",
    `_Source: ${finding.source}${finding.cveId ? ` · ${finding.cveId}` : ""}_`,
  ].join("\n");
}

function mapFindingsToReviewComments(
  findings: Finding[],
  files: Array<{ filename: string; patch?: string }>,
): Array<{ path: string; line: number; body: string }> {
  const patchLines = new Map<string, Set<number>>();

  for (const file of files) {
    if (!file.patch) continue;
    const lines = new Set<number>();
    let currentLine = 0;
    for (const line of file.patch.split("\n")) {
      if (line.startsWith("@@")) {
        const match = line.match(/\+(\d+)/);
        currentLine = match ? parseInt(match[1], 10) : currentLine;
        continue;
      }
      if (line.startsWith("+") && !line.startsWith("+++")) {
        lines.add(currentLine);
        currentLine++;
      } else if (line.startsWith(" ")) {
        currentLine++;
      }
    }
    patchLines.set(file.filename, lines);
  }

  const comments: Array<{ path: string; line: number; body: string }> = [];

  for (const finding of findings) {
    const lines = patchLines.get(finding.file);
    if (lines?.has(finding.line)) {
      comments.push({
        path: finding.file,
        line: finding.line,
        body: formatFindingMarkdown(finding, "inline"),
      });
    }
  }

  return comments;
}

function buildSummaryComment(result: ReviewResult): string {
  const { findings, summary, degradedLayers } = result;

  if (findings.length === 0) {
    let body = `## SecureReview\n\n${summary}\n\nNo security issues detected.`;
    if (degradedLayers.length > 0) {
      body += `\n\n> Note: Some layers were degraded (${degradedLayers.join(", ")}). Results may be incomplete.`;
    }
    return body;
  }

  const lines = [`## SecureReview\n`, summary, "", "### Findings", ""];

  for (const finding of findings) {
    lines.push(formatFindingMarkdown(finding, "summary"));
  }

  if (degradedLayers.length > 0) {
    lines.push("", `> Degraded layers: ${degradedLayers.join(", ")}`);
  }

  return lines.join("\n");
}

function hasBlockingFindings(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === "critical" || f.severity === "high");
}

interface ReviewWithAutofix {
  review: ReviewResult;
  autofix: DependencyAutofixResult;
}

interface AutofixCommitOutcome {
  reviewHeadSha: string;
  autofixCommitSha?: string;
  autofixCommitError?: string;
  degradedLayers: string[];
  review: ReviewResult;
}

async function runSandboxReview(
  ctx: PullRequestContext,
  inputs: PullRequestReviewInputs,
  signal?: AbortSignal,
): Promise<{ payload: ReviewWithAutofix; sandboxDegraded: boolean }> {
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
        signal,
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

async function commitAutofixIfApplied(
  octokit: Octokit,
  ctx: PullRequestContext,
  payload: ReviewWithAutofix,
): Promise<AutofixCommitOutcome> {
  let reviewHeadSha = ctx.headSha;
  let autofixCommitSha: string | undefined;
  let autofixCommitError: string | undefined;
  const degradedLayers: string[] = [];
  let review = payload.review;

  if (payload.autofix.applied) {
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
    const inputs = await fetchPullRequestReviewInputs(octokit, ctx);
    const { payload, sandboxDegraded } = await runSandboxReview(ctx, inputs, signal);
    const autofixOutcome = await commitAutofixIfApplied(octokit, ctx, payload);

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

    await postPullRequestReview(octokit, {
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
