import fs from "node:fs";
import path from "node:path";
import { OwaspCategory } from "@/lib/types";

interface EvalScorecard {
  model: string;
  timestamp: string;
  recall: Record<OwaspCategory | "clean", number>;
  precision: number;
  falsePositives: number;
  injectionResisted: boolean;
  latencyMs: number;
  costEstimateUsd?: number;
  findingsBySource: { llm: number; semgrep: number; osv: number };
}

function loadLatestScorecard(): EvalScorecard | null {
  const resultsDir = path.join(process.cwd(), "evals", "results");
  if (!fs.existsSync(resultsDir)) return null;

  const files = fs
    .readdirSync(resultsDir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .reverse();

  if (files.length === 0) return null;

  try {
    const raw = fs.readFileSync(path.join(resultsDir, files[0]!), "utf-8");
    return JSON.parse(raw) as EvalScorecard;
  } catch {
    return null;
  }
}

export default function HomePage() {
  const scorecard = loadLatestScorecard();

  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-4xl px-6 py-16">
        <header className="mb-12">
          <p className="mb-2 text-sm font-medium uppercase tracking-widest text-emerald-400">
            SecureReview
          </p>
          <h1 className="mb-4 text-4xl font-bold tracking-tight">
            PR Security Review Agent
          </h1>
          <p className="max-w-2xl text-lg text-zinc-400">
            A GitHub-connected agent that reviews every pull request for OWASP Top 10
            vulnerabilities. Three signal sources: Semgrep SAST in an isolated Vercel
            Sandbox, deterministic CVE lookups via OSV.dev, and an AI SDK agent for
            contextual judgment.
          </p>
        </header>

        <section className="mb-12 grid gap-4 sm:grid-cols-3">
          {[
            {
              title: "Semgrep",
              desc: "Deterministic SAST baseline with p/owasp-top-ten rules inside the Sandbox.",
            },
            {
              title: "OSV.dev",
              desc: "Known CVE alerts on dependency bumps — never LLM-hallucinated CVE IDs.",
            },
            {
              title: "AI Agent",
              desc: "Full-repo context via Sandbox tools for auth logic, IDOR, and design flaws.",
            },
          ].map((item) => (
            <div
              key={item.title}
              className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5"
            >
              <h3 className="mb-2 font-semibold text-emerald-400">{item.title}</h3>
              <p className="text-sm text-zinc-400">{item.desc}</p>
            </div>
          ))}
        </section>

        <section className="mb-12 rounded-xl border border-zinc-800 bg-zinc-900/30 p-6">
          <h2 className="mb-4 text-xl font-semibold">Architecture</h2>
          <pre className="overflow-x-auto rounded-lg bg-black/40 p-4 text-xs leading-relaxed text-zinc-300">
{`GitHub App (PR webhook)
        │
        ▼
Next.js route on Vercel
        │  verify HMAC, dedupe, start run (waitUntil)
        ▼
Vercel Sandbox (ephemeral, per run)
  • clone repo @ PR head
  • semgrep scan + agent tools
        │
        ▼
AI SDK agent (via AI Gateway)
  → dedupe/rank findings → GitHub PR review + Check Run`}
          </pre>
        </section>

        {scorecard ? (
          <section className="rounded-xl border border-zinc-800 bg-zinc-900/30 p-6">
            <h2 className="mb-4 text-xl font-semibold">Latest Eval Scorecard</h2>
            <p className="mb-4 text-sm text-zinc-400">
              Model: {scorecard.model} · {new Date(scorecard.timestamp).toLocaleString()}
            </p>
            <div className="mb-4 grid gap-3 sm:grid-cols-2">
              <Metric label="Precision (clean PRs)" value={`${(scorecard.precision * 100).toFixed(0)}%`} />
              <Metric label="False positives" value={String(scorecard.falsePositives)} />
              <Metric label="Prompt injection resisted" value={scorecard.injectionResisted ? "Yes" : "No"} />
              <Metric label="Latency" value={`${(scorecard.latencyMs / 1000).toFixed(1)}s`} />
            </div>
            <h3 className="mb-2 text-sm font-medium text-zinc-300">Recall by OWASP category</h3>
            <div className="grid grid-cols-5 gap-2 text-center text-xs sm:grid-cols-10">
              {(Object.entries(scorecard.recall) as [string, number][]).map(([cat, val]) => (
                <div
                  key={cat}
                  className={`rounded px-1 py-2 ${val >= 1 ? "bg-emerald-900/40 text-emerald-300" : cat === "clean" ? "bg-zinc-800 text-zinc-400" : "bg-red-900/30 text-red-300"}`}
                >
                  <div className="font-mono">{cat}</div>
                  <div>{cat === "clean" ? (val === 0 ? "✓" : "✗") : val >= 1 ? "✓" : "✗"}</div>
                </div>
              ))}
            </div>
          </section>
        ) : (
          <section className="rounded-xl border border-dashed border-zinc-700 p-6 text-center text-zinc-500">
            Run <code className="text-emerald-400">npm run eval</code> to generate scorecards in{" "}
            <code className="text-emerald-400">evals/results/</code>
          </section>
        )}

        <footer className="mt-16 border-t border-zinc-800 pt-8 text-sm text-zinc-500">
          <p>
            Install the GitHub App and configure{" "}
            <code className="text-zinc-400">POST /api/webhooks/github</code> to start reviewing PRs.
          </p>
        </footer>
      </div>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg bg-black/30 px-4 py-3">
      <div className="text-xs text-zinc-500">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}
