import crypto from "node:crypto";
import { waitUntil } from "@vercel/functions";
import { NextRequest, NextResponse } from "next/server";
import {
  createInstallationOctokit,
  isDuplicateDelivery,
  isReviewablePullRequestAction,
  parsePullRequestPayload,
  registerRun,
  runKey,
  verifyGitHubWebhookSignature,
} from "@/lib/github";
import { runPullRequestReview } from "@/lib/review";

export const runtime = "nodejs";
export const maxDuration = 300;

export async function POST(request: NextRequest) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    return NextResponse.json({ error: "Webhook secret not configured" }, { status: 500 });
  }

  const payload = await request.text();
  const signature = request.headers.get("x-hub-signature-256");
  const deliveryId = request.headers.get("x-github-delivery") ?? crypto.randomUUID();
  const event = request.headers.get("x-github-event");

  if (!verifyGitHubWebhookSignature(payload, signature, secret)) {
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  if (isDuplicateDelivery(deliveryId)) {
    return NextResponse.json({ ok: true, deduped: true });
  }

  if (event !== "pull_request") {
    return NextResponse.json({ ok: true, skipped: true });
  }

  const body = JSON.parse(payload) as unknown;
  const prPayload = parsePullRequestPayload(body);
  if (!prPayload || !isReviewablePullRequestAction(prPayload.action)) {
    return NextResponse.json({ ok: true, skipped: true });
  }

  const installationId = prPayload.installation?.id;
  if (!installationId) {
    return NextResponse.json({ error: "Missing installation id" }, { status: 400 });
  }

  const owner = prPayload.repository.owner.login;
  const repo = prPayload.repository.name;
  const pullNumber = prPayload.pull_request.number;
  const headSha = prPayload.pull_request.head.sha;
  const baseSha = prPayload.pull_request.base.sha;

  const key = runKey(owner, repo, pullNumber);
  const abortController = registerRun(key);

  const ctx = {
    owner,
    repo,
    pullNumber,
    headSha,
    headRef: prPayload.pull_request.head.ref,
    baseSha,
    installationId,
    deliveryId,
  };

  waitUntil(
    (async () => {
      try {
        const octokit = createInstallationOctokit(installationId);
        await runPullRequestReview(octokit, ctx, abortController.signal);
      } catch (err) {
        console.error("SecureReview failed:", err);
      }
    })(),
  );

  return NextResponse.json({ ok: true, queued: true });
}
