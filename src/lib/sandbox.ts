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

  await sandbox.runCommand({
    cmd: "sh",
    args: [
      "-c",
      "curl -sL https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz | tar xz -C /tmp && cp /tmp/ripgrep-14.1.1-x86_64-unknown-linux-musl/rg /usr/local/bin/rg 2>/dev/null || true",
    ],
    sudo: true,
  });

  await sandbox.runCommand({
    cmd: "pip3",
    args: ["install", "--quiet", "semgrep"],
    sudo: true,
  });

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
        const result = await sandbox.runCommand({ cmd: "rg", args });
        const content = await result.stdout();
        return { content: content || "(no matches)" };
      } catch (err) {
        return { content: "", error: err instanceof Error ? err.message : "grep failed" };
      }
    },

    async runSemgrep(ruleset = "p/owasp-top-ten"): Promise<{ findings: SemgrepFinding[]; raw: string }> {
      const result = await sandbox.runCommand({
        cmd: "semgrep",
        args: ["--config", ruleset, "--json", "--quiet", "."],
      });
      const raw = await result.stdout();
      const stderr = await result.stderr();

      try {
        const parsed = JSON.parse(raw || stderr || "{}") as { results?: unknown[] };
        const findings: SemgrepFinding[] = [];
        for (const item of parsed.results ?? []) {
          const parsedFinding = SemgrepFindingSchema.safeParse(item);
          if (parsedFinding.success) findings.push(parsedFinding.data);
        }
        return { findings, raw: raw || stderr };
      } catch {
        return { findings: [], raw: raw || stderr };
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
