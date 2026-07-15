import { Finding } from "./types";
import { pickHighestVersion } from "./osv";
import type { SandboxSession } from "./sandbox";

export interface PackageUpgrade {
  name: string;
  fromVersion?: string;
  toVersion: string;
  cveIds: string[];
}

export interface DependencyAutofixResult {
  applied: boolean;
  packages: PackageUpgrade[];
  files: Array<{ path: string; content: string }>;
  error?: string;
}

const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
] as const;

export function bumpPackageJson(
  packageJson: string,
  upgrades: PackageUpgrade[],
): { content: string; applied: PackageUpgrade[] } {
  const pkg = JSON.parse(packageJson) as Record<string, Record<string, string> | undefined>;
  const applied: PackageUpgrade[] = [];

  for (const upgrade of upgrades) {
    let changed = false;
    for (const section of DEPENDENCY_SECTIONS) {
      const deps = pkg[section];
      const current = deps?.[upgrade.name];
      // Skip if already absent or already at (or past) the target version — otherwise
      // this reports "applied" on every run even when nothing changes, which produces a
      // no-op commit that still gets a new SHA and re-triggers pull_request.synchronize.
      if (!current || current === upgrade.toVersion) continue;
      deps![upgrade.name] = upgrade.toVersion;
      changed = true;
    }
    if (changed) applied.push(upgrade);
  }

  return {
    content: `${JSON.stringify(pkg, null, 2)}\n`,
    applied,
  };
}

export function collectPackageUpgrades(findings: Finding[]): PackageUpgrade[] {
  const byPackage = new Map<
    string,
    { fixedVersions: string[]; cveIds: Set<string>; fromVersion?: string }
  >();

  for (const finding of findings) {
    if (finding.source !== "osv" || !finding.package || !finding.fixedVersion) continue;

    const entry = byPackage.get(finding.package) ?? {
      fixedVersions: [],
      cveIds: new Set<string>(),
      fromVersion: finding.version,
    };
    entry.fixedVersions.push(finding.fixedVersion);
    if (finding.cveId) entry.cveIds.add(finding.cveId);
    if (finding.version) entry.fromVersion = finding.version;
    byPackage.set(finding.package, entry);
  }

  return [...byPackage.entries()].map(([name, entry]) => ({
    name,
    fromVersion: entry.fromVersion,
    toVersion: pickHighestVersion(entry.fixedVersions),
    cveIds: [...entry.cveIds],
  }));
}

export async function applyDependencyAutofixInSandbox(
  sandbox: SandboxSession,
  findings: Finding[],
): Promise<DependencyAutofixResult> {
  const upgrades = collectPackageUpgrades(findings);
  if (upgrades.length === 0) {
    return { applied: false, packages: [], files: [] };
  }

  const pkgFile = await sandbox.readFile("package.json");
  if (pkgFile.error || !pkgFile.content.trim()) {
    return {
      applied: false,
      packages: upgrades,
      files: [],
      error: pkgFile.error ?? "package.json not found",
    };
  }

  const lockFile = await sandbox.readFile("package-lock.json");
  if (lockFile.error || !lockFile.content.trim()) {
    return {
      applied: false,
      packages: upgrades,
      files: [],
      error: "package-lock.json not found — autofix requires npm lockfile",
    };
  }

  const { content: updatedPkg, applied } = bumpPackageJson(pkgFile.content, upgrades);
  if (applied.length === 0) {
    return {
      applied: false,
      packages: upgrades,
      files: [],
      error: "No matching dependencies found in package.json",
    };
  }

  const writeResult = await sandbox.writeFile("package.json", updatedPkg);
  if (writeResult.error) {
    return {
      applied: false,
      packages: applied,
      files: [],
      error: writeResult.error,
    };
  }

  const installArgs = applied.map((u) => `${u.name}@${u.toVersion}`).join(" ");
  // --save-exact is required: npm's default save-prefix is "^", so without it
  // `npm install pkg@X --package-lock-only` rewrites package.json back to "^X",
  // silently undoing the exact pin bumpPackageJson just wrote. That caret then gets
  // picked up by the next review's OSV query (a range string, not an exact version),
  // which OSV matches broadly against the package's entire advisory history — producing
  // an identical "fix" forever and an infinite commit → synchronize → commit loop.
  const npmResult = await sandbox.runShell(
    `set -e
ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"
NPM=$(command -v npm || command -v npm.cmd || echo npm)
$NPM install ${installArgs} --save-exact --package-lock-only --ignore-scripts --no-audit --no-fund`,
  );
  if (npmResult.exitCode !== 0) {
    console.error("Autofix npm failed:", npmResult.stdout, npmResult.stderr);
    return {
      applied: false,
      packages: applied,
      files: [],
      error: `npm install failed: ${(npmResult.stderr || npmResult.stdout).slice(0, 500)}`,
    };
  }

  const finalLock = await sandbox.readFile("package-lock.json");
  if (finalLock.error) {
    return {
      applied: false,
      packages: applied,
      files: [],
      error: "Failed to read updated lockfile",
    };
  }

  // Commit our own exact-pinned package.json (updatedPkg) rather than re-reading it
  // from the sandbox — npm's own save behavior is not trusted to preserve the exact
  // version even with --save-exact across every npm version/config combination.
  return {
    applied: true,
    packages: applied,
    files: [
      { path: "package.json", content: updatedPkg },
      { path: "package-lock.json", content: finalLock.content },
    ],
  };
}

export function formatAutofixCommitMessage(upgrades: PackageUpgrade[]): string {
  const lines = upgrades.map(
    (u) => `- ${u.name}: ${u.fromVersion ?? "?"} → ${u.toVersion} (${u.cveIds.join(", ") || "OSV"})`,
  );
  return [
    "fix(deps): patch known vulnerabilities (SecureReview)",
    "",
    ...lines,
    "",
    "Automated dependency upgrade based on OSV advisories with available fixed versions.",
  ].join("\n");
}

export function formatAutofixStatusNote(params: {
  result: DependencyAutofixResult | null;
  commitSha?: string;
  commitError?: string;
}): string {
  const { result, commitSha, commitError } = params;
  if (!result) {
    return "\n\n> Dependency autofix: not run (sandbox unavailable).";
  }

  if (commitSha && result.applied) {
    return `\n\n### Dependency autofix\n\nSecureReview committed patched versions to this branch (\`${commitSha.slice(0, 7)}\`):\n${result.packages
      .map((u) => `- \`${u.name}\`: ${u.fromVersion ?? "?"} → \`${u.toVersion}\``)
      .join("\n")}`;
  }

  if (commitError) {
    return `\n\n> Dependency autofix failed to commit: ${commitError}`;
  }

  if (result.applied && !commitSha) {
    return "\n\n> Dependency autofix prepared files but no commit SHA was returned.";
  }

  if (result.packages.length === 0) {
    return "\n\n> Dependency autofix: no OSV advisories with a known fixed version in this PR.";
  }

  return `\n\n> Dependency autofix skipped: ${result.error ?? "unknown error"}`;
}
