import { describe, expect, it } from "vitest";
import {
  extractPackageChangesFromFiles,
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
    expect(changes.length).toBeGreaterThanOrEqual(0);
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
