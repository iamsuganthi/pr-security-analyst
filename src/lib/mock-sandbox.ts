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
    async grep(pattern: string, path?: string, glob?: string) {
      void path;
      void glob;
      if (diff.includes(pattern.replace(/\\/g, ""))) {
        return { content: diff.split("\n").filter((l) => l.includes("+")).join("\n") };
      }
      return { content: "(no matches)" };
    },
    async runShell() {
      return { exitCode: 1, stdout: "", stderr: "mock sandbox" };
    },
    async writeFile() {
      return { error: "mock sandbox" };
    },
    async destroy() {},
  };
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
