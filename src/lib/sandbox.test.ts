import { describe, expect, it } from "vitest";
import { isSemgrepScanFailure, parseSemgrepOutput } from "./sandbox";

describe("parseSemgrepOutput", () => {
  it("parses findings from JSON stdout", () => {
    const json = JSON.stringify({
      results: [
        {
          check_id: "javascript.lang.security.audit.sqli",
          path: "src/db.ts",
          start: { line: 10 },
          extra: { message: "SQL injection", severity: "ERROR" },
        },
      ],
    });

    const { findings } = parseSemgrepOutput(json, "");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.path).toBe("src/db.ts");
  });

  it("returns empty findings for invalid JSON", () => {
    const { findings } = parseSemgrepOutput("not json", "");
    expect(findings).toHaveLength(0);
  });
});

describe("isSemgrepScanFailure", () => {
  it("treats 0 and 1 as success", () => {
    expect(isSemgrepScanFailure(0)).toBe(false);
    expect(isSemgrepScanFailure(1)).toBe(false);
  });

  it("treats 2+ as failure", () => {
    expect(isSemgrepScanFailure(2)).toBe(true);
  });
});
