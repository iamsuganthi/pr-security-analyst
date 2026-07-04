import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { isSemgrepEnabled } from "./config";

describe("isSemgrepEnabled", () => {
  const original = process.env.SECUREREVIEW_ENABLE_SEMGREP;

  afterEach(() => {
    if (original === undefined) delete process.env.SECUREREVIEW_ENABLE_SEMGREP;
    else process.env.SECUREREVIEW_ENABLE_SEMGREP = original;
  });

  it("is false by default", () => {
    delete process.env.SECUREREVIEW_ENABLE_SEMGREP;
    expect(isSemgrepEnabled()).toBe(false);
  });

  it("is true only when explicitly enabled", () => {
    process.env.SECUREREVIEW_ENABLE_SEMGREP = "true";
    expect(isSemgrepEnabled()).toBe(true);
  });

  beforeEach(() => {
    delete process.env.SECUREREVIEW_ENABLE_SEMGREP;
  });
});
