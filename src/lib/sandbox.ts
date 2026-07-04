export interface SandboxToolResult {
  content: string;
  error?: string;
}

export interface SandboxSession {
  readFile(path: string): Promise<SandboxToolResult>;
  grep(pattern: string, path?: string, glob?: string): Promise<SandboxToolResult>;
  runShell(script: string): Promise<{ exitCode: number; stdout: string; stderr: string }>;
  destroy(): Promise<void>;
}

export interface CreateSandboxOptions {
  cloneUrl: string;
  revision: string;
  username: string;
  password: string;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 8 * 60 * 1000;

type SandboxCommandRunner = {
  runCommand(params: {
    cmd: string;
    args?: string[];
    sudo?: boolean;
    env?: Record<string, string>;
  }): Promise<{ exitCode: number; stdout(): Promise<string>; stderr(): Promise<string> }>;
};

async function runSandboxShell(
  sandbox: SandboxCommandRunner,
  script: string,
  sudo = false,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const result = await sandbox.runCommand({
    cmd: "sh",
    args: ["-c", script],
    sudo,
  });
  return {
    exitCode: result.exitCode,
    stdout: await result.stdout(),
    stderr: await result.stderr(),
  };
}

async function installRipgrep(sandbox: SandboxCommandRunner, localBin: string): Promise<void> {
  await runSandboxShell(
    sandbox,
    `
set +e
mkdir -p "${localBin}"
TMP=$(mktemp -d)
curl -sL https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz | tar xz -C "$TMP"
RG=$(find "$TMP" -type f -name rg | head -1)
if [ -n "$RG" ]; then
  cp "$RG" "${localBin}/rg"
  chmod +x "${localBin}/rg"
fi
`,
    false,
  );
}

export async function createSandboxSession(
  options: CreateSandboxOptions,
): Promise<SandboxSession> {
  const { Sandbox } = await import("@vercel/sandbox");

  const teamId = process.env.VERCEL_TEAM_ID;
  const projectId = process.env.VERCEL_PROJECT_ID;
  const token = process.env.VERCEL_TOKEN;

  if (!teamId || !projectId || !token) {
    throw new Error("VERCEL_TEAM_ID, VERCEL_PROJECT_ID, and VERCEL_TOKEN are required for Sandbox");
  }

  const sandbox = await Sandbox.create({
    teamId,
    projectId,
    token,
    source: {
      type: "git",
      url: options.cloneUrl,
      username: options.username,
      password: options.password,
      revision: options.revision,
      depth: 1,
    },
    runtime: "node24",
    resources: { vcpus: 2 },
    timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  });

  const homeResult = await runSandboxShell(sandbox, 'printf "%s" "$HOME"', false);
  const home = homeResult.stdout.trim() || "/tmp";
  const localBin = `${home}/.local/bin`;

  await installRipgrep(sandbox, localBin);

  const workspace = await runSandboxShell(
    sandbox,
    "pwd && ls -la 2>/dev/null | head -25",
    false,
  );
  console.error(
    "Sandbox workspace:",
    workspace.stdout.trim() || workspace.stderr.trim() || "(empty)",
  );

  const toolEnv = {
    TMPDIR: `${home}/.tmp`,
    PATH: `${localBin}:/usr/bin:/bin`,
  };

  const session: SandboxSession = {
    async readFile(path: string): Promise<SandboxToolResult> {
      try {
        const result = await sandbox.runCommand({
          cmd: "cat",
          args: [path],
        });
        const content = await result.stdout();
        if (result.exitCode !== 0) {
          return { content: "", error: (await result.stderr()) || "File not found" };
        }
        return { content };
      } catch (err) {
        return { content: "", error: err instanceof Error ? err.message : "readFile failed" };
      }
    },

    async grep(pattern: string, path = ".", glob?: string): Promise<SandboxToolResult> {
      try {
        const args = ["--no-heading", "--line-number", "-C", "2", pattern, path];
        if (glob) args.splice(4, 0, "--glob", glob);
        const result = await sandbox.runCommand({ cmd: "rg", args, env: toolEnv });
        const content = await result.stdout();
        return { content: content || "(no matches)" };
      } catch (err) {
        return { content: "", error: err instanceof Error ? err.message : "grep failed" };
      }
    },

    async runShell(script: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
      return runSandboxShell(sandbox, script, false);
    },

    async destroy(): Promise<void> {
      try {
        await sandbox.stop();
      } catch {
        // Sandbox may already be stopped
      }
    },
  };

  return session;
}

export async function withSandbox<T>(
  options: CreateSandboxOptions,
  fn: (session: SandboxSession) => Promise<T>,
): Promise<{ result: T; degraded: boolean }> {
  let session: SandboxSession | null = null;
  try {
    session = await createSandboxSession(options);
    const result = await fn(session);
    return { result, degraded: false };
  } catch {
    return {
      result: await fn(createLocalFallbackSession()),
      degraded: true,
    };
  } finally {
    if (session) await session.destroy();
  }
}

function createLocalFallbackSession(): SandboxSession {
  return {
    async readFile() {
      return { content: "", error: "Sandbox unavailable — diff-only mode" };
    },
    async grep() {
      return { content: "", error: "Sandbox unavailable — diff-only mode" };
    },
    async runShell() {
      return { exitCode: 1, stdout: "", stderr: "Sandbox unavailable" };
    },
    async destroy() {},
  };
}
