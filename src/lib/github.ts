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
  sender?: { login: string; type: string };
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

/**
 * Guards against self-triggered review loops: our autofix commits push to the PR's
 * head branch via the installation token, which GitHub reports back as a
 * `pull_request.synchronize` event with a bot `sender`. Without this check, a bot-authored
 * push (ours or another bot's) re-triggers a full review, which can push another commit,
 * ad infinitum. Human-authored synchronize events (and opened/reopened) are unaffected.
 */
export function isSelfTriggeredSynchronize(payload: PullRequestPayload): boolean {
  return payload.action === "synchronize" && payload.sender?.type === "Bot";
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
