import { describe, expect, it } from "vitest";
import { isSemgrepScanFailure, parseSemgrepCommandMarker, parseSemgrepOutput } from "./sandbox";

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

  it("detects Python traceback as crash", () => {
    const traceback = `Traceback (most recent call last):
  File "/home/vercel-sandbox/.local/bin/pysemgrep", line 10, in <module>
    sys.exit(main())`;

    const { findings, crashed } = parseSemgrepOutput("", traceback);
    expect(findings).toHaveLength(0);
    expect(crashed).toBe(true);
  });

  it("parses venv semgrep binary marker", () => {
    expect(parseSemgrepCommandMarker("__SEMGREP_CMD__=/home/user/.local/semgrep-venv/bin/semgrep")).toEqual([
      "/home/user/.local/semgrep-venv/bin/semgrep",
    ]);
  });

  it("parses osemgrep binary marker", () => {
    expect(parseSemgrepCommandMarker("__SEMGREP_CMD__=/home/user/.local/bin/semgrep")).toEqual([
      "/home/user/.local/bin/semgrep",
    ]);
  });
});

describe("parseSemgrepCommandMarker", () => {
  it("parses uv-installed binary path", () => {
    expect(parseSemgrepCommandMarker("__SEMGREP_CMD__=/usr/local/bin/semgrep")).toEqual([
      "/usr/local/bin/semgrep",
    ]);
  });

  it("parses uvx invocation", () => {
    expect(parseSemgrepCommandMarker("__SEMGREP_CMD__=/home/user/.local/bin/uvx semgrep")).toEqual([
      "/home/user/.local/bin/uvx",
      "semgrep",
    ]);
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
