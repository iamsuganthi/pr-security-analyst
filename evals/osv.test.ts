import { describe, expect, it } from "vitest";
import {
  extractPackageChangesFromFiles,
  normalizeVersionSpecifier,
  parsePackageJsonDiff,
} from "../src/lib/osv";

describe("parsePackageJsonDiff", () => {
  it("extracts added dependencies from patch", () => {
    const patch = `@@ -10,6 +10,7 @@
   "dependencies": {
+    "lodash": "4.17.4",
     "express": "^4.18.0"
   }`;

    const changes = parsePackageJsonDiff(patch);
    expect(changes).toEqual([
      { name: "lodash", version: "4.17.4", ecosystem: "npm" },
    ]);
  });

  it("extracts added deps from GitHub hunk without closing brace", () => {
    const patch = `@@ -9,6 +9,7 @@
     "lint": "eslint"
   },
   "dependencies": {
+    "lodash": "4.17.4",
     "next": "16.2.10",
     "react": "19.2.4",
     "react-dom": "19.2.4"`;

    const changes = parsePackageJsonDiff(patch);
    expect(changes).toEqual([
      { name: "lodash", version: "4.17.4", ecosystem: "npm" },
    ]);
  });

  it("strips semver range prefixes so OSV is queried with an exact version", () => {
    // Regression test: OSV.dev cannot parse a range specifier like "^4.18.0" as an
    // exact version and matches broadly across the package's whole advisory history
    // instead, which previously caused an already-fixed version to keep being flagged
    // as vulnerable and re-"fixed" every review — an infinite commit loop.
    const patch = `@@ -10,6 +10,7 @@
   "dependencies": {
+    "lodash": "^4.18.0",
     "express": "^4.18.0"
   }`;

    const changes = parsePackageJsonDiff(patch);
    expect(changes).toEqual([
      { name: "lodash", version: "4.18.0", ecosystem: "npm" },
    ]);
  });
});

describe("normalizeVersionSpecifier", () => {
  it("strips caret, tilde, and comparison operators", () => {
    expect(normalizeVersionSpecifier("^4.18.0")).toBe("4.18.0");
    expect(normalizeVersionSpecifier("~4.18.0")).toBe("4.18.0");
    expect(normalizeVersionSpecifier(">=4.18.0")).toBe("4.18.0");
    expect(normalizeVersionSpecifier("4.18.0")).toBe("4.18.0");
  });
});

describe("extractPackageChangesFromFiles", () => {
  it("finds package.json changes in file list", () => {
    const files = [
      {
        filename: "package.json",
        patch: `+    "lodash": "4.17.4",`,
      },
      { filename: "src/index.ts", patch: "+console.log('hi')" },
    ];

    const changes = extractPackageChangesFromFiles(files);
    expect(changes).toEqual([{ name: "lodash", version: "4.17.4", ecosystem: "npm" }]);
  });
});

describe("hallucination checks", () => {
  it("rejects fabricated CVE IDs not in OSV response", async () => {
    const { validateCveIds } = await import("../src/lib/osv");
    const allowed = new Set(["GHSA-real-id"]);
    const findings = [
      {
        file: "package.json",
        line: 1,
        owaspCategory: "A06" as const,
        severity: "high" as const,
        message: "test",
        suggestedFix: "fix",
        source: "osv" as const,
        cveId: "GHSA-fabricated",
      },
      {
        file: "package.json",
        line: 1,
        owaspCategory: "A06" as const,
        severity: "high" as const,
        message: "test",
        suggestedFix: "fix",
        source: "osv" as const,
        cveId: "GHSA-real-id",
      },
    ];

    const validated = validateCveIds(findings, allowed);
    expect(validated).toHaveLength(1);
    expect(validated[0]?.cveId).toBe("GHSA-real-id");
  });
});
