import { SemgrepFinding, SemgrepFindingSchema } from "./types";

export interface SandboxToolResult {
  content: string;
  error?: string;
}

export interface SandboxSession {
  readFile(path: string): Promise<SandboxToolResult>;
  grep(pattern: string, path?: string, glob?: string): Promise<SandboxToolResult>;
  runSemgrep(ruleset?: string): Promise<{ findings: SemgrepFinding[]; raw: string }>;
  destroy(): Promise<void>;
}

export interface CreateSandboxOptions {
  cloneUrl: string;
  revision: string;
  username: string;
  password: string;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

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

/** Semgrep exits 1 when findings exist; 0 when clean; >=2 indicates failure. */
export function isSemgrepScanFailure(exitCode: number): boolean {
  return exitCode >= 2;
}

export function parseSemgrepOutput(raw: string, stderr: string): {
  findings: SemgrepFinding[];
  raw: string;
} {
  const combined = raw.trim() || stderr.trim();
  if (!combined) {
    return { findings: [], raw: stderr || raw };
  }

  try {
    const parsed = JSON.parse(combined) as { results?: unknown[]; errors?: unknown[] };
    const findings: SemgrepFinding[] = [];
    for (const item of parsed.results ?? []) {
      const parsedFinding = SemgrepFindingSchema.safeParse(item);
      if (parsedFinding.success) findings.push(parsedFinding.data);
    }
    return { findings, raw: combined };
  } catch {
    return { findings: [], raw: combined };
  }
}

/**
 * Install Semgrep inside the sandbox with several fallbacks (Amazon Linux / node24).
 * Returns argv prefix: ["semgrep"] or ["python3", "-m", "semgrep"].
 */
export async function installSemgrepInSandbox(
  sandbox: SandboxCommandRunner,
): Promise<string[]> {
  const installScript = `
set -eu
export PATH="/usr/local/bin:/root/.local/bin:$HOME/.local/bin:$PATH"

if ! command -v python3 >/dev/null 2>&1; then
  (dnf install -y python3 python3-pip 2>/dev/null || yum install -y python3 python3-pip 2>/dev/null || true)
fi

if ! python3 -m pip --version >/dev/null 2>&1; then
  python3 -m ensurepip --upgrade 2>/dev/null || true
  (dnf install -y python3-pip 2>/dev/null || yum install -y python3-pip 2>/dev/null || true)
fi

python3 -m pip install --upgrade pip setuptools wheel 2>/dev/null || true

install_semgrep() {
  python3 -m pip install "semgrep>=1.90.0" "$@" 2>&1
}

if ! install_semgrep --break-system-packages; then
  if ! install_semgrep; then
    if ! install_semgrep --user; then
      pip3 install "semgrep>=1.90.0" --break-system-packages || pip3 install "semgrep>=1.90.0" --user
    fi
  fi
fi

export PATH="/usr/local/bin:/root/.local/bin:$HOME/.local/bin:$PATH"

if command -v semgrep >/dev/null 2>&1; then
  semgrep --version
  echo "__SEMGREP_CMD__=semgrep"
  exit 0
fi

if python3 -m semgrep --version >/dev/null 2>&1; then
  echo "__SEMGREP_CMD__=python3 -m semgrep"
  exit 0
fi

echo "Semgrep installation failed" >&2
exit 1
`;

  const { exitCode, stdout, stderr } = await runSandboxShell(sandbox, installScript, true);
  const output = `${stdout}\n${stderr}`;

  if (exitCode !== 0) {
    console.error("Semgrep install failed:", output.slice(-2000));
    throw new Error(`Semgrep install failed (exit ${exitCode})`);
  }

  const marker = output
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line.startsWith("__SEMGREP_CMD__="));

  if (marker?.includes("python3 -m semgrep")) {
    return ["python3", "-m", "semgrep"];
  }
  if (marker?.includes("semgrep")) {
    return ["semgrep"];
  }

  // Fallback probe if marker missing but install exited 0
  const probe = await runSandboxShell(
    sandbox,
    'command -v semgrep >/dev/null && echo semgrep || (python3 -m semgrep --version >/dev/null 2>&1 && echo module)',
    false,
  );
  if (probe.stdout.includes("module")) return ["python3", "-m", "semgrep"];
  if (probe.stdout.includes("semgrep")) return ["semgrep"];

  throw new Error("Semgrep installed but binary not found on PATH");
}

async function installRipgrep(sandbox: SandboxCommandRunner): Promise<void> {
  await runSandboxShell(
    sandbox,
    "curl -sL https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz | tar xz -C /tmp && cp /tmp/ripgrep-14.1.1-x86_64-unknown-linux-musl/rg /usr/local/bin/rg 2>/dev/null || true",
    true,
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

  await installRipgrep(sandbox);
  const semgrepCmd = await installSemgrepInSandbox(sandbox);

  const semgrepEnv = {
    SEMGREP_SEND_METRICS: "off",
    SEMGREP_ENABLE_VERSION_CHECK: "0",
    PATH: "/usr/local/bin:/root/.local/bin:/home/user/.local/bin:/usr/bin:/bin",
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
        const result = await sandbox.runCommand({ cmd: "rg", args, env: semgrepEnv });
        const content = await result.stdout();
        return { content: content || "(no matches)" };
      } catch (err) {
        return { content: "", error: err instanceof Error ? err.message : "grep failed" };
      }
    },

    async runSemgrep(ruleset = "p/owasp-top-ten"): Promise<{ findings: SemgrepFinding[]; raw: string }> {
      const [cmd, ...cmdPrefix] = semgrepCmd;
      const args = [
        ...cmdPrefix,
        "--config",
        ruleset,
        "--json",
        "--quiet",
        "--metrics=off",
        "--timeout",
        "120",
        ".",
      ];

      try {
        const result = await sandbox.runCommand({
          cmd: cmd!,
          args,
          env: semgrepEnv,
        });
        const raw = await result.stdout();
        const stderr = await result.stderr();

        if (isSemgrepScanFailure(result.exitCode)) {
          const parsed = parseSemgrepOutput(raw, stderr);
          if (parsed.findings.length > 0) {
            return parsed;
          }
          throw new Error(
            `Semgrep scan failed (exit ${result.exitCode}): ${(stderr || raw).slice(0, 500)}`,
          );
        }

        return parseSemgrepOutput(raw, stderr);
      } catch (err) {
        if (err instanceof Error) throw err;
        throw new Error("Semgrep scan failed");
      }
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
    async runSemgrep() {
      return { findings: [], raw: "Sandbox unavailable" };
    },
    async destroy() {},
  };
}

export function semgrepToOwasp(checkId: string, metadata?: { owasp?: string | string[] }): string {
  if (metadata?.owasp) {
    const owasp = Array.isArray(metadata.owasp) ? metadata.owasp[0] : metadata.owasp;
    const match = owasp.match(/A\d{2}/);
    if (match) return match[0];
  }
  const id = checkId.toLowerCase();
  if (id.includes("sql") || id.includes("xss") || id.includes("injection")) return "A03";
  if (id.includes("ssrf")) return "A10";
  if (id.includes("cors") || id.includes("cookie") || id.includes("header")) return "A05";
  if (id.includes("secret") || id.includes("crypto") || id.includes("md5")) return "A02";
  if (id.includes("jwt") || id.includes("auth")) return "A07";
  if (id.includes("deserial")) return "A08";
  return "A03";
}

export function mapSemgrepSeverity(severity?: string): "critical" | "high" | "medium" | "low" | "info" {
  const s = (severity ?? "WARNING").toUpperCase();
  if (s === "ERROR") return "high";
  if (s === "WARNING") return "medium";
  if (s === "INFO") return "low";
  return "medium";
}
