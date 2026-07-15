import { Finding, ReviewResult } from "./types";

export function formatFindingMarkdown(
  finding: Finding,
  style: "inline" | "check" | "summary",
): string {
  if (style === "inline") {
    return [
      `**${finding.severity.toUpperCase()}** · ${finding.owaspCategory}`,
      finding.message,
      "",
      `**Fix:** ${finding.suggestedFix}`,
      `_Source: ${finding.source}_`,
    ].join("\n");
  }

  if (style === "summary") {
    return `- **${finding.severity.toUpperCase()}** \`${finding.file}:${finding.line}\` · ${finding.owaspCategory} · ${finding.message} _(source: ${finding.source})_`;
  }

  return [
    `**${finding.severity.toUpperCase()}** · ${finding.owaspCategory}${finding.cwe ? ` · ${finding.cwe}` : ""}`,
    "",
    finding.message,
    "",
    `**Suggested fix:** ${finding.suggestedFix}`,
    "",
    `_Source: ${finding.source}${finding.cveId ? ` · ${finding.cveId}` : ""}_`,
  ].join("\n");
}

export function mapFindingsToReviewComments(
  findings: Finding[],
  files: Array<{ filename: string; patch?: string }>,
): Array<{ path: string; line: number; body: string }> {
  const patchLines = new Map<string, Set<number>>();

  for (const file of files) {
    if (!file.patch) continue;
    const lines = new Set<number>();
    let currentLine = 0;
    for (const line of file.patch.split("\n")) {
      if (line.startsWith("@@")) {
        const match = line.match(/\+(\d+)/);
        currentLine = match ? parseInt(match[1], 10) : currentLine;
        continue;
      }
      if (line.startsWith("+") && !line.startsWith("+++")) {
        lines.add(currentLine);
        currentLine++;
      } else if (line.startsWith(" ")) {
        currentLine++;
      }
    }
    patchLines.set(file.filename, lines);
  }

  const comments: Array<{ path: string; line: number; body: string }> = [];

  for (const finding of findings) {
    const lines = patchLines.get(finding.file);
    if (lines?.has(finding.line)) {
      comments.push({
        path: finding.file,
        line: finding.line,
        body: formatFindingMarkdown(finding, "inline"),
      });
    }
  }

  return comments;
}

export function buildSummaryComment(result: ReviewResult): string {
  const { findings, summary, degradedLayers } = result;

  if (findings.length === 0) {
    let body = `## SecureReview\n\n${summary}\n\nNo security issues detected.`;
    if (degradedLayers.length > 0) {
      body += `\n\n> Note: Some layers were degraded (${degradedLayers.join(", ")}). Results may be incomplete.`;
    }
    return body;
  }

  const lines = [`## SecureReview\n`, summary, "", "### Findings", ""];

  for (const finding of findings) {
    lines.push(formatFindingMarkdown(finding, "summary"));
  }

  if (degradedLayers.length > 0) {
    lines.push("", `> Degraded layers: ${degradedLayers.join(", ")}`);
  }

  return lines.join("\n");
}

export function hasBlockingFindings(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === "critical" || f.severity === "high");
}
