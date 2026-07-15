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

export interface PullRequestPayload {
  action: string;
  installation?: { id: number };
  pull_request: {
    number: number;
    head: {
      sha: string;
      ref: string;
      repo: { name: string; owner: { login: string } };
    };
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

export function runKey(owner: string, repo: string, pullNumber: number): string {
  return `${owner}/${repo}#${pullNumber}`;
}
