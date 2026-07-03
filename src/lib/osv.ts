import { Finding, OwaspCategory } from "./types";

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

export function parsePackageJsonDiff(patch: string): PackageChange[] {
  const changes: PackageChange[] = [];
  const depSections = ["dependencies", "devDependencies", "peerDependencies"];

  for (const section of depSections) {
    const sectionRegex = new RegExp(`"${section}"\\s*:\\s*\\{([^}]*)\\}`, "s");
    const sectionMatch = patch.match(sectionRegex);
    if (!sectionMatch) continue;

    const addedLines = sectionMatch[1]
      .split("\n")
      .filter((line) => line.trim().startsWith("+") && !line.includes(`"${section}"`));

    for (const line of addedLines) {
      const match = line.match(/"([^"]+)"\s*:\s*"([^"]+)"/);
      if (match) {
        changes.push({ name: match[1], version: match[2], ecosystem: "npm" });
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
  for (const affected of vuln.affected ?? []) {
    if (affected.package.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return undefined;
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

export function mapOwaspFromCategory(category: string): OwaspCategory {
  const match = category.match(/A\d{2}/);
  return (match?.[0] ?? "A06") as OwaspCategory;
}
