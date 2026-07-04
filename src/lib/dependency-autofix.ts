import { Finding } from "./types";
import { SandboxSession } from "./sandbox";

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

export function isDependencyAutofixEnabled(): boolean {
  return process.env.SECUREREVIEW_AUTOFIX_DEPS !== "false";
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

export function pickHighestVersion(versions: string[]): string {
  return versions.reduce((best, current) =>
    compareSemver(current, best) > 0 ? current : best,
  );
}

export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i]! - pb[i]!;
  }
  return 0;
}

function parseSemver(version: string): [number, number, number] {
  const core = version.trim().replace(/^[^\d]*/, "").split("-")[0] ?? "";
  const [major = "0", minor = "0", patch = "0"] = core.split(".");
  return [Number(major) || 0, Number(minor) || 0, Number(patch) || 0];
}

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
      if (!deps?.[upgrade.name]) continue;
      deps[upgrade.name] = upgrade.toVersion;
      changed = true;
    }
    if (changed) applied.push(upgrade);
  }

  return {
    content: `${JSON.stringify(pkg, null, 2)}\n`,
    applied,
  };
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

  const writeResult = await sandbox.runShell(
    `cat > package.json <<'__PKG_EOF__'\n${updatedPkg}__PKG_EOF__`,
  );
  if (writeResult.exitCode !== 0) {
    return {
      applied: false,
      packages: applied,
      files: [],
      error: writeResult.stderr || "Failed to write package.json",
    };
  }

  const installArgs = applied.map((u) => `${u.name}@${u.toVersion}`).join(" ");
  const npmResult = await sandbox.runShell(
    `npm install ${installArgs} --package-lock-only --ignore-scripts --no-audit --no-fund 2>&1`,
  );
  if (npmResult.exitCode !== 0) {
    return {
      applied: false,
      packages: applied,
      files: [],
      error: `npm install failed: ${(npmResult.stderr || npmResult.stdout).slice(0, 500)}`,
    };
  }

  const [finalPkg, finalLock] = await Promise.all([
    sandbox.readFile("package.json"),
    sandbox.readFile("package-lock.json"),
  ]);

  if (finalPkg.error || finalLock.error) {
    return {
      applied: false,
      packages: applied,
      files: [],
      error: "Failed to read updated manifest files",
    };
  }

  return {
    applied: true,
    packages: applied,
    files: [
      { path: "package.json", content: finalPkg.content },
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
