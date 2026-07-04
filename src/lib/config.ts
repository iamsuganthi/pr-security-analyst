/** Semgrep is optional; off by default while we focus on the agent workflow. */
export function isSemgrepEnabled(): boolean {
  return process.env.SECUREREVIEW_ENABLE_SEMGREP === "true";
}
