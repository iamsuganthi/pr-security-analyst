import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";
import crypto from "node:crypto";

export function verifyGitHubWebhookSignature(
  payload: string,
  signature: string | null,
  secret: string,
): boolean {
  if (!signature?.startsWith("sha256=")) return false;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  const received = signature.slice("sha256=".length);
  if (expected.length !== received.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));
}

export function createInstallationOctokit(installationId: number): Octokit {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g, "\n");

  if (!appId || !privateKey) {
    throw new Error("GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY are required");
  }

  return new Octokit({
    authStrategy: createAppAuth,
    auth: {
      appId,
      privateKey,
      installationId,
    },
  });
}

export interface PullRequestPayload {
  action: string;
  installation?: { id: number };
  pull_request: {
    number: number;
    head: { sha: string; ref: string };
    base: { sha: string; ref: string };
  };
  repository: {
    name: string;
    owner: { login: string };
    clone_url: string;
  };
}

export function parsePullRequestPayload(body: unknown): PullRequestPayload | null {
  if (!body || typeof body !== "object") return null;
  const payload = body as PullRequestPayload;
  if (!payload.pull_request || !payload.repository) return null;
  return payload;
}

export function isReviewablePullRequestAction(action: string): boolean {
  return action === "opened" || action === "synchronize" || action === "reopened";
}

const processedDeliveries = new Map<string, number>();
const DEDUPE_TTL_MS = 60 * 60 * 1000;

export function isDuplicateDelivery(deliveryId: string): boolean {
  const now = Date.now();
  for (const [id, ts] of processedDeliveries) {
    if (now - ts > DEDUPE_TTL_MS) processedDeliveries.delete(id);
  }
  if (processedDeliveries.has(deliveryId)) return true;
  processedDeliveries.set(deliveryId, now);
  return false;
}

const activeRuns = new Map<string, AbortController>();

export function registerRun(key: string): AbortController {
  const existing = activeRuns.get(key);
  if (existing) existing.abort();
  const controller = new AbortController();
  activeRuns.set(key, controller);
  return controller;
}

export function clearRun(key: string): void {
  activeRuns.delete(key);
}

export function runKey(owner: string, repo: string, pullNumber: number): string {
  return `${owner}/${repo}#${pullNumber}`;
}

export async function fetchPullRequestDiff(
  octokit: Octokit,
  owner: string,
  repo: string,
  pullNumber: number,
): Promise<string> {
  const { data } = await octokit.pulls.get({
    owner,
    repo,
    pull_number: pullNumber,
    mediaType: { format: "diff" },
  });
  return data as unknown as string;
}

export async function fetchPullRequestFiles(
  octokit: Octokit,
  owner: string,
  repo: string,
  pullNumber: number,
) {
  const { data } = await octokit.pulls.listFiles({
    owner,
    repo,
    pull_number: pullNumber,
    per_page: 300,
  });
  return data;
}

export async function createCheckRun(
  octokit: Octokit,
  params: {
    owner: string;
    repo: string;
    headSha: string;
    name?: string;
    status: "queued" | "in_progress" | "completed";
    conclusion?: "success" | "failure" | "neutral";
    output?: { title: string; summary: string; text?: string };
    externalId?: string;
  },
): Promise<number> {
  const { data } = await octokit.checks.create({
    owner: params.owner,
    repo: params.repo,
    name: params.name ?? "SecureReview",
    head_sha: params.headSha,
    status: params.status,
    conclusion: params.conclusion,
    output: params.output,
    external_id: params.externalId,
  });
  return data.id;
}

export async function updateCheckRun(
  octokit: Octokit,
  params: {
    owner: string;
    repo: string;
    checkRunId: number;
    status: "queued" | "in_progress" | "completed";
    conclusion?: "success" | "failure" | "neutral";
    output?: { title: string; summary: string; text?: string };
  },
): Promise<void> {
  await octokit.checks.update({
    owner: params.owner,
    repo: params.repo,
    check_run_id: params.checkRunId,
    status: params.status,
    conclusion: params.conclusion,
    output: params.output,
  });
}

export async function postPullRequestReview(
  octokit: Octokit,
  params: {
    owner: string;
    repo: string;
    pullNumber: number;
    commitId: string;
    body: string;
    comments: Array<{ path: string; line: number; body: string; side?: "RIGHT" }>;
    event: "COMMENT" | "REQUEST_CHANGES";
  },
): Promise<void> {
  if (params.comments.length > 0) {
    await octokit.pulls.createReview({
      owner: params.owner,
      repo: params.repo,
      pull_number: params.pullNumber,
      commit_id: params.commitId,
      body: params.body,
      event: params.event,
      comments: params.comments.map((c) => ({
        path: c.path,
        line: c.line,
        body: c.body,
        side: c.side ?? "RIGHT",
      })),
    });
    return;
  }

  await octokit.issues.createComment({
    owner: params.owner,
    repo: params.repo,
    issue_number: params.pullNumber,
    body: params.body,
  });
}

export async function commitFilesToBranch(
  octokit: Octokit,
  params: {
    owner: string;
    repo: string;
    branch: string;
    message: string;
    files: Array<{ path: string; content: string }>;
  },
): Promise<{ commitSha: string }> {
  const { data: ref } = await octokit.git.getRef({
    owner: params.owner,
    repo: params.repo,
    ref: `heads/${params.branch}`,
  });

  const parentSha = ref.object.sha;
  const { data: parentCommit } = await octokit.git.getCommit({
    owner: params.owner,
    repo: params.repo,
    commit_sha: parentSha,
  });

  const blobs = await Promise.all(
    params.files.map(async (file) => {
      const { data } = await octokit.git.createBlob({
        owner: params.owner,
        repo: params.repo,
        content: Buffer.from(file.content, "utf-8").toString("base64"),
        encoding: "base64",
      });
      return { path: file.path, sha: data.sha };
    }),
  );

  const { data: tree } = await octokit.git.createTree({
    owner: params.owner,
    repo: params.repo,
    base_tree: parentCommit.tree.sha,
    tree: blobs.map((blob) => ({
      path: blob.path,
      mode: "100644" as const,
      type: "blob" as const,
      sha: blob.sha,
    })),
  });

  const { data: commit } = await octokit.git.createCommit({
    owner: params.owner,
    repo: params.repo,
    message: params.message,
    tree: tree.sha,
    parents: [parentSha],
  });

  await octokit.git.updateRef({
    owner: params.owner,
    repo: params.repo,
    ref: `heads/${params.branch}`,
    sha: commit.sha,
  });

  return { commitSha: commit.sha };
}

export function formatFindingComment(finding: {
  severity: string;
  owaspCategory: string;
  message: string;
  suggestedFix: string;
  source: string;
  cwe?: string;
  cveId?: string;
}): string {
  const lines = [
    `**${finding.severity.toUpperCase()}** · ${finding.owaspCategory}${finding.cwe ? ` · ${finding.cwe}` : ""}`,
    "",
    finding.message,
    "",
    `**Suggested fix:** ${finding.suggestedFix}`,
    "",
    `_Source: ${finding.source}${finding.cveId ? ` · ${finding.cveId}` : ""}_`,
  ];
  return lines.join("\n");
}
