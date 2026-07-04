/**
 * Live agent demo — shows the AI workflow without GitHub or Vercel Sandbox.
 *
 * Usage:
 *   npm run demo              # A01 (missing authz — pure LLM story)
 *   npm run demo -- --fixture A03   # SQLi + prompt injection
 *   npm run demo -- --all           # run highlight fixtures
 *
 * Requires AI_GATEWAY_API_KEY (or OPENAI_API_KEY) in .env.local
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { runSecurityReview } from "../src/lib/agent";
import { createMockSandbox, parseDiffFiles } from "../src/lib/mock-sandbox";

interface Fixture {
  name: string;
  owasp: string;
  description: string;
  expectedSources: string[];
  diff: string;
}

function loadEnvLocal(): void {
  const envPath = resolve(process.cwd(), ".env.local");
  if (!existsSync(envPath)) return;

  for (const line of readFileSync(envPath, "utf-8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = value;
  }
}

function parseArgs(): { fixtures: string[] } {
  const args = process.argv.slice(2);
  if (args.includes("--all")) {
    return { fixtures: ["A01", "A03", "A06", "A04", "clean-1"] };
  }
  const idx = args.indexOf("--fixture");
  if (idx !== -1 && args[idx + 1]) {
    return { fixtures: [args[idx + 1]!] };
  }
  return { fixtures: ["A01"] };
}

async function runDemo(fixtureId: string, fixture: Fixture): Promise<void> {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Fixture ${fixtureId}: ${fixture.name}`);
  console.log(`Story: ${fixture.description}`);
  console.log(`Expected sources: ${fixture.expectedSources.join(", ") || "none"}`);
  console.log(`${"=".repeat(60)}\n`);

  const files = parseDiffFiles(fixture.diff);
  const sandbox = createMockSandbox(fixture.diff);

  const result = await runSecurityReview({
    diff: fixture.diff,
    files,
    sandbox,
  });

  console.log("── Triage ──");
  console.log("  Files:", result.metadata?.triageFiles?.join(", ") || "(none)");

  console.log("\n── Deterministic layers ──");
  console.log("  OSV CVEs:", result.metadata?.osvCount ?? 0);

  console.log("\n── Agent loop ──");
  console.log("  Model:", result.metadata?.model ?? "unknown");
  console.log("  Steps:", result.metadata?.stepCount ?? 0);
  console.log("  Tools:", result.metadata?.toolsUsed?.join(" → ") || "(none recorded)");

  console.log("\n── Findings ──");
  if (result.findings.length === 0) {
    console.log("  (none)");
  }
  for (const f of result.findings) {
    console.log(
      `  • [${f.severity}] ${f.owaspCategory} ${f.file}:${f.line} — ${f.message} (${f.source})`,
    );
  }

  console.log("\n── Summary ──");
  console.log(`  ${result.summary}`);
  if (result.degradedLayers.length > 0) {
    console.log(`  Degraded: ${result.degradedLayers.join(", ")}`);
  }
  console.log(`  Latency: ${((result.metadata?.latencyMs ?? 0) / 1000).toFixed(1)}s`);
}

async function main(): Promise<void> {
  loadEnvLocal();

  if (!process.env.AI_GATEWAY_API_KEY && !process.env.OPENAI_API_KEY) {
    console.error("Set AI_GATEWAY_API_KEY in .env.local to run the live agent demo.");
    process.exit(1);
  }

  const manifestPath = resolve(process.cwd(), "evals/fixtures/manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf-8")) as Record<string, Fixture>;
  const { fixtures } = parseArgs();

  console.log("SecureReview — Agent Demo (local only; production uses GitHub PRs)");
  console.log("Sandbox: mock");

  for (const id of fixtures) {
    const fixture = manifest[id];
    if (!fixture) {
      console.error(`Unknown fixture: ${id}`);
      process.exit(1);
    }
    await runDemo(id, fixture);
  }

  console.log("\n✓ Demo complete");
  console.log("\nProduction path: open a PR on a repo with the GitHub App installed.");
  console.log("Run eval suite: npm run eval");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
