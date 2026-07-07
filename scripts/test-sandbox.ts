/**
 * Manual Sandbox smoke test — no GitHub webhook, no LLM.
 *
 * Usage:
 *   npm run sandbox:test
 *
 * Requires in .env.local (or shell env):
 *   VERCEL_TEAM_ID, VERCEL_PROJECT_ID, VERCEL_TOKEN
 *
 * Optional:
 *   SANDBOX_TEST_REPO   (default: https://github.com/iamsuganthi/demo.git)
 *   SANDBOX_TEST_REV    (default: main)
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { createSandboxSession } from "../src/lib/sandbox";

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

async function main(): Promise<void> {
  loadEnvLocal();

  for (const key of ["VERCEL_TEAM_ID", "VERCEL_PROJECT_ID", "VERCEL_TOKEN"]) {
    if (!process.env[key]) {
      console.error(`Missing ${key}. Set it in .env.local or your shell.`);
      process.exit(1);
    }
  }

  const cloneUrl =
    process.env.SANDBOX_TEST_REPO ?? "https://github.com/iamsuganthi/demo.git";
  const revision = process.env.SANDBOX_TEST_REV ?? "main";
  const token = process.env.GITHUB_TOKEN ?? process.env.SANDBOX_GITHUB_TOKEN;

  const authCloneUrl = token
    ? cloneUrl.replace("https://", `https://x-access-token:${token}@`)
    : cloneUrl;

  console.log("SecureReview Sandbox test");
  console.log("  repo:", cloneUrl);
  console.log("  rev:", revision);
  console.log("  auth:", token ? "token" : "none (public repo only)");
  console.log("");

  const started = Date.now();
  console.log("Creating sandbox…");

  const session = await createSandboxSession({
    cloneUrl: authCloneUrl,
    revision,
    username: token ? "x-access-token" : "",
    password: token ?? "",
  });

  try {
    console.log(`\nSandbox ready in ${((Date.now() - started) / 1000).toFixed(1)}s\n`);

    console.log("--- readFile build.gradle (demo has no README.md) ---");
    const buildFile = await session.readFile("build.gradle");
    if (buildFile.error) {
      console.log("error:", buildFile.error);
      console.log(
        "Tip: check stderr above for 'Sandbox workspace:' — if empty, clone failed (wrong branch?).",
      );
    } else {
      console.log(buildFile.content.slice(0, 300) || "(empty)");
    }

    console.log("\n--- grep src/ (Java) ---");
    const grep = await session.grep("password|secret|Runtime\\.getRuntime|exec\\(", "src");
    console.log(grep.content.slice(0, 600) || grep.error || "(no matches)");

    console.log("\n✓ Sandbox test complete");
  } catch (err) {
    console.error("\n✗ Sandbox test failed:", err instanceof Error ? err.message : err);
    process.exit(1);
  } finally {
    console.log("\nDestroying sandbox…");
    await session.destroy();
  }
}

main();
