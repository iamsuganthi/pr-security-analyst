import { Finding } from "./types";

export interface PackageChange {
  name: string;
  version: string;
  ecosystem: "npm";
}

export interface OsvVulnerability {
  id: string;
  summary: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package: { name: string; ecosystem: string };
    ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

export interface OsvQueryResult {
  vulns: OsvVulnerability[];
}

const OSV_API = "https://api.osv.dev/v1/query";

const DEPENDENCY_SECTIONS = new Set([
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
]);

export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i]! - pb[i]!;
  }
  return 0;
}

export function pickHighestVersion(versions: string[]): string {
  return versions.reduce((best, current) =>
    compareSemver(current, best) > 0 ? current : best,
  );
}

function parseSemver(version: string): [number, number, number] {
  const core = version.trim().replace(/^[^\d]*/, "").split("-")[0] ?? "";
  const [major = "0", minor = "0", patch = "0"] = core.split(".");
  return [Number(major) || 0, Number(minor) || 0, Number(patch) || 0];
}

export function parsePackageJsonDiff(patch: string): PackageChange[] {
  const changes: PackageChange[] = [];
  let currentSection: string | null = null;

  for (const line of patch.split("\n")) {
    if (line.startsWith("+++")) continue;

    const content = line.startsWith("+")
      ? line.slice(1)
      : line.startsWith(" ")
        ? line.slice(1)
        : line.startsWith("-")
          ? line.slice(1)
          : line;

    const sectionMatch = content.match(/^\s*"([^"]+)"\s*:\s*\{\s*$/);
    if (sectionMatch && DEPENDENCY_SECTIONS.has(sectionMatch[1]!)) {
      currentSection = sectionMatch[1]!;
      continue;
    }

    if (/^\s*\},?\s*$/.test(content)) {
      currentSection = null;
      continue;
    }

    if (!line.startsWith("+") || !currentSection) continue;

    const depMatch = content.match(/^\s*"([^"]+)":\s*"([^"]+)"/);
    if (depMatch) {
      changes.push({ name: depMatch[1]!, version: depMatch[2]!, ecosystem: "npm" });
    }
  }

  if (changes.length === 0) {
    for (const line of patch.split("\n")) {
      if (!line.startsWith("+") || line.startsWith("+++")) continue;
      const depMatch = line.match(/^\+\s*"([^"]+)":\s*"([^"]+)"/);
      if (depMatch) {
        changes.push({ name: depMatch[1]!, version: depMatch[2]!, ecosystem: "npm" });
      }
    }
  }

  return changes;
}

export function extractPackageChangesFromFiles(
  files: Array<{ filename: string; patch?: string }>,
): PackageChange[] {
  const changes: PackageChange[] = [];
  for (const file of files) {
    if (file.filename === "package.json" && file.patch) {
      changes.push(...parsePackageJsonDiff(file.patch));
    }
  }
  return dedupePackageChanges(changes);
}

function dedupePackageChanges(changes: PackageChange[]): PackageChange[] {
  const seen = new Set<string>();
  return changes.filter((c) => {
    const key = `${c.ecosystem}:${c.name}@${c.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function queryOsv(packageChange: PackageChange): Promise<OsvVulnerability[]> {
  const response = await fetch(OSV_API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      package: {
        name: packageChange.name,
        ecosystem: "npm",
      },
      version: packageChange.version,
    }),
  });

  if (!response.ok) {
    throw new Error(`OSV API error: ${response.status}`);
  }

  const data = (await response.json()) as OsvQueryResult;
  return data.vulns ?? [];
}

export async function lookupCvesForChanges(
  changes: PackageChange[],
): Promise<{ findings: Finding[]; cveIds: Set<string>; unavailable: boolean }> {
  const findings: Finding[] = [];
  const cveIds = new Set<string>();

  if (changes.length === 0) {
    return { findings, cveIds, unavailable: false };
  }

  let unavailable = false;

  for (const change of changes) {
    try {
      const vulns = await queryOsv(change);
      for (const vuln of vulns) {
        cveIds.add(vuln.id);
        const severity = mapOsvSeverity(vuln);
        const fixedVersion = extractFixedVersion(vuln, change.name);

        findings.push({
          file: "package.json",
          line: 1,
          owaspCategory: "A06",
          cwe: "CWE-1395",
          severity,
          message: `Known vulnerability ${vuln.id} in ${change.name}@${change.version}: ${vuln.summary}`,
          suggestedFix: fixedVersion
            ? `Upgrade ${change.name} to ${fixedVersion} or later.`
            : `Review advisory ${vuln.id} and upgrade ${change.name}.`,
          source: "osv",
          package: change.name,
          version: change.version,
          cveId: vuln.id,
          fixedVersion,
        });
      }
    } catch {
      unavailable = true;
    }
  }

  return { findings, cveIds, unavailable };
}

function mapOsvSeverity(vuln: OsvVulnerability): Finding["severity"] {
  const cvss = vuln.severity?.find((s) => s.type === "CVSS_V3");
  if (cvss?.score) {
    const score = parseFloat(cvss.score.split("/")[0] ?? cvss.score);
    if (score >= 9) return "critical";
    if (score >= 7) return "high";
    if (score >= 4) return "medium";
    return "low";
  }
  return "high";
}

function extractFixedVersion(vuln: OsvVulnerability, packageName: string): string | undefined {
  const fixed: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixed.push(event.fixed);
      }
    }
  }
  if (fixed.length === 0) return undefined;
  return pickHighestVersion(fixed);
}

export function validateCveIds(
  findings: Finding[],
  allowedCveIds: Set<string>,
): Finding[] {
  return findings.filter((f) => {
    if (f.source !== "osv" || !f.cveId) return true;
    return allowedCveIds.has(f.cveId);
  });
}
