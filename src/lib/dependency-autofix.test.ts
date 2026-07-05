import { describe, expect, it } from "vitest";
import {
  bumpPackageJson,
  collectPackageUpgrades,
  formatAutofixStatusNote,
} from "./dependency-autofix";
import { compareSemver, pickHighestVersion } from "./osv";
import { Finding } from "./types";

describe("collectPackageUpgrades", () => {
  it("dedupes packages and picks highest fixed version", () => {
    const findings: Finding[] = [
      {
        file: "package.json",
        line: 1,
        owaspCategory: "A06",
        severity: "high",
        message: "vuln 1",
        suggestedFix: "upgrade",
        source: "osv",
        package: "lodash",
        version: "4.17.4",
        cveId: "GHSA-a",
        fixedVersion: "4.17.20",
      },
      {
        file: "package.json",
        line: 1,
        owaspCategory: "A06",
        severity: "high",
        message: "vuln 2",
        suggestedFix: "upgrade",
        source: "osv",
        package: "lodash",
        version: "4.17.4",
        cveId: "GHSA-b",
        fixedVersion: "4.17.21",
      },
    ];

    const upgrades = collectPackageUpgrades(findings);
    expect(upgrades).toHaveLength(1);
    expect(upgrades[0]?.toVersion).toBe("4.17.21");
    expect(upgrades[0]?.cveIds).toEqual(["GHSA-a", "GHSA-b"]);
  });

  it("ignores findings without fixedVersion", () => {
    const findings: Finding[] = [
      {
        file: "package.json",
        line: 1,
        owaspCategory: "A06",
        severity: "high",
        message: "vuln",
        suggestedFix: "review",
        source: "osv",
        package: "lodash",
        version: "4.17.4",
        cveId: "GHSA-a",
      },
    ];
    expect(collectPackageUpgrades(findings)).toHaveLength(0);
  });
});

describe("pickHighestVersion", () => {
  it("compares semver segments", () => {
    expect(pickHighestVersion(["4.17.4", "4.17.21", "4.17.20"])).toBe("4.17.21");
    expect(compareSemver("2.0.0", "10.0.0")).toBeLessThan(0);
  });
});

describe("bumpPackageJson", () => {
  it("updates dependency version in package.json", () => {
    const pkg = JSON.stringify(
      {
        name: "demo",
        dependencies: { lodash: "4.17.4", express: "^4.18.0" },
      },
      null,
      2,
    );

    const { content, applied } = bumpPackageJson(pkg, [
      { name: "lodash", toVersion: "4.17.21", cveIds: ["GHSA-x"], fromVersion: "4.17.4" },
    ]);

    const parsed = JSON.parse(content) as { dependencies: Record<string, string> };
    expect(parsed.dependencies.lodash).toBe("4.17.21");
    expect(parsed.dependencies.express).toBe("^4.18.0");
    expect(applied).toHaveLength(1);
  });
});

describe("formatAutofixStatusNote", () => {
  it("explains when commit failed", () => {
    const note = formatAutofixStatusNote({
      result: {
        applied: true,
        packages: [{ name: "lodash", toVersion: "4.17.21", cveIds: ["GHSA-x"] }],
        files: [],
      },
      commitError: "Resource not accessible by integration",
    });
    expect(note).toContain("failed to commit");
  });
});
