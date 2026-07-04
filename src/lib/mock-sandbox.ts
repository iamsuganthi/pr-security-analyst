import { SemgrepFinding } from "./types";
import { SandboxSession } from "./sandbox";

/** Lightweight mock repo for evals and local agent demos (no Vercel Sandbox). */
export function createMockSandbox(diff: string): SandboxSession {
  const fileContents = new Map<string, string>();

  for (const match of diff.matchAll(/^\+\+\+ b\/(.+)$/gm)) {
    fileContents.set(match[1]!, "");
  }

  return {
    async readFile(filePath: string) {
      return { content: fileContents.get(filePath) ?? `// mock content for ${filePath}` };
    },
    async grep(pattern: string) {
      if (diff.includes(pattern.replace(/\\/g, ""))) {
        return { content: diff.split("\n").filter((l) => l.includes("+")).join("\n") };
      }
      return { content: "(no matches)" };
    },
    async runSemgrep() {
      return { findings: mockSemgrepFindings(diff), raw: "" };
    },
    async runShell() {
      return { exitCode: 1, stdout: "", stderr: "mock sandbox" };
    },
    async destroy() {},
  };
}

function mockSemgrepFindings(diff: string): SemgrepFinding[] {
  const findings: SemgrepFinding[] = [];

  if (/SELECT.*\+.*id|query\s*=.*\+/.test(diff)) {
    findings.push({
      check_id: "javascript.lang.security.audit.sqli",
      path: "src/db/users.ts",
      start: { line: 13 },
      extra: {
        message: "Detected string concatenation in SQL query — possible SQL injection",
        severity: "ERROR",
        metadata: { cwe: "CWE-89", owasp: "A03" },
      },
    });
  }
  if (/AKIA[0-9A-Z]{16}/.test(diff)) {
    findings.push({
      check_id: "generic.secrets.security.detected-aws-access-key",
      path: "src/config/aws.ts",
      start: { line: 2 },
      extra: {
        message: "AWS access key detected",
        severity: "ERROR",
        metadata: { cwe: "CWE-798", owasp: "A02" },
      },
    });
  }
  if (/pickle\.loads/.test(diff)) {
    findings.push({
      check_id: "python.lang.security.deserialization",
      path: "api/process.py",
      start: { line: 5 },
      extra: {
        message: "Unsafe deserialization via pickle.loads",
        severity: "ERROR",
        metadata: { cwe: "CWE-502", owasp: "A08" },
      },
    });
  }
  if (/Access-Control-Allow-Origin.*\*/.test(diff)) {
    findings.push({
      check_id: "javascript.express.cors.permissive",
      path: "src/middleware/cors.ts",
      start: { line: 6 },
      extra: {
        message: "Permissive CORS policy",
        severity: "WARNING",
        metadata: { cwe: "CWE-942", owasp: "A05" },
      },
    });
  }
  if (/fetch\(url\)/.test(diff) && /proxyRequest/.test(diff)) {
    findings.push({
      check_id: "javascript.lang.security.audit.ssrf",
      path: "src/api/fetch.ts",
      start: { line: 2 },
      extra: {
        message: "User-controlled URL passed to fetch — possible SSRF",
        severity: "ERROR",
        metadata: { cwe: "CWE-918", owasp: "A10" },
      },
    });
  }
  if (/algorithms.*none/.test(diff)) {
    findings.push({
      check_id: "javascript.jwt.security.alg-none",
      path: "src/auth/jwt.ts",
      start: { line: 11 },
      extra: {
        message: "JWT algorithm 'none' allowed",
        severity: "ERROR",
        metadata: { cwe: "CWE-347", owasp: "A07" },
      },
    });
  }

  return findings;
}

export function parseDiffFiles(
  diff: string,
): Array<{ filename: string; patch?: string; status: string }> {
  const files: Array<{ filename: string; patch?: string; status: string }> = [];
  const chunks = diff.split(/^diff --git /m).filter(Boolean);

  for (const chunk of chunks) {
    const headerMatch = chunk.match(/^a\/(.+?) b\/(.+?)$/m);
    if (!headerMatch) continue;
    const filename = headerMatch[2]!;
    const status = chunk.includes("new file mode") ? "added" : "modified";
    files.push({ filename, patch: chunk, status });
  }

  return files;
}
