import { Octokit } from "@octokit/rest";
import { createInstallationOctokit } from "./github-auth";

async function fetchPullRequestDiff(
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

async function fetchPullRequestFiles(
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
  installationId: number,
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
  "use step";
  const octokit = createInstallationOctokit(installationId);
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
  installationId: number,
  params: {
    owner: string;
    repo: string;
    checkRunId: number;
    status: "queued" | "in_progress" | "completed";
    conclusion?: "success" | "failure" | "neutral";
    output?: { title: string; summary: string; text?: string };
  },
): Promise<void> {
  "use step";
  const octokit = createInstallationOctokit(installationId);
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
  installationId: number,
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
  "use step";
  const octokit = createInstallationOctokit(installationId);
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
}

export interface PullRequestReviewInputs {
  diff: string;
  files: Awaited<ReturnType<typeof fetchPullRequestFiles>>;
  cloneUrl: string;
  installToken: string;
}

export async function fetchPullRequestReviewInputs(
  installationId: number,
  ctx: {
    owner: string;
    repo: string;
    pullNumber: number;
  },
): Promise<PullRequestReviewInputs> {
  "use step";
  const octokit = createInstallationOctokit(installationId);
  const [diff, files, { data: repoData }, { data: tokenData }] = await Promise.all([
    fetchPullRequestDiff(octokit, ctx.owner, ctx.repo, ctx.pullNumber),
    fetchPullRequestFiles(octokit, ctx.owner, ctx.repo, ctx.pullNumber),
    octokit.repos.get({ owner: ctx.owner, repo: ctx.repo }),
    octokit.apps.createInstallationAccessToken({ installation_id: installationId }),
  ]);

  const cloneUrl = repoData.clone_url.replace(
    "https://",
    `https://x-access-token:${tokenData.token}@`,
  );

  return { diff, files, cloneUrl, installToken: tokenData.token };
}

export async function commitFilesToBranch(
  installationId: number,
  params: {
    owner: string;
    repo: string;
    branch: string;
    message: string;
    files: Array<{ path: string; content: string }>;
  },
): Promise<{ commitSha: string }> {
  "use step";
  const octokit = createInstallationOctokit(installationId);
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
