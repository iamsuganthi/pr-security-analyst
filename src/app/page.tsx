const GITHUB_APP_INSTALL_URL =
  "https://github.com/apps/pr-security-analyst/installations/new";

export default function HomePage() {
  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-4xl px-4 py-10 sm:px-6 sm:py-16">
        <header className="mb-8 sm:mb-10">
          <p className="mb-2 text-sm font-medium uppercase tracking-widest text-emerald-400">
            Secure Review
          </p>
          <h1 className="mb-4 text-3xl font-bold tracking-tight sm:text-4xl">
            Security review on every pull request
          </h1>
          <p className="max-w-2xl text-base leading-relaxed text-zinc-300 sm:text-lg">
            Fix security vulnerabilities before a pull request is merged. SecureReview gives
            every PR an automated security pass — so teams move fast without shipping blind.
          </p>
        </header>

        <section className="mb-8 rounded-xl border border-emerald-900/50 bg-emerald-950/20 p-4 sm:mb-10 sm:p-6">
          <h2 className="mb-3 flex items-center gap-2 text-lg font-semibold text-emerald-300">
            <GitHubIcon className="h-5 w-5 shrink-0" />
            Try it on GitHub
          </h2>
          <ol className="mb-5 ml-4 list-decimal space-y-3 text-sm leading-relaxed text-zinc-300">
            <li>
              <a
                href={GITHUB_APP_INSTALL_URL}
                className="font-medium text-emerald-400 underline-offset-2 hover:underline"
              >
                Install the GitHub App
              </a>{" "}
              on one or more repositories
            </li>
            <li>Open a PR — expand below if you need inspiration</li>
            <li>
              Watch for a PR review comment, inline notes on changed lines, and a{" "}
              <strong className="font-medium text-zinc-200">SecureReview</strong> check
            </li>
          </ol>
          <a
            href={GITHUB_APP_INSTALL_URL}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-emerald-500 sm:inline-flex sm:w-auto sm:py-2.5"
          >
            <GitHubIcon className="h-4 w-4 shrink-0" />
            Install on GitHub →
          </a>
          <details className="group mt-5 border-t border-emerald-900/40 pt-4">
            <summary className="cursor-pointer list-none py-1 text-sm text-zinc-400 transition hover:text-zinc-300 [&::-webkit-details-marker]:hidden">
              <span className="inline-flex min-h-11 items-center gap-2">
                <span
                  className="text-emerald-400/70 transition group-open:rotate-90"
                  aria-hidden="true"
                >
                  ›
                </span>
                Need inspiration for a test PR?
              </span>
            </summary>
            <ul className="mt-2 space-y-3 break-words border-l border-zinc-800 pl-4 text-sm leading-relaxed text-zinc-400">
              <li>
                Add <code className="break-all text-emerald-400">lodash@4.17.4</code> to{" "}
                <code className="break-all text-zinc-300">package.json</code> — CVE alerts and
                often an autofix commit
              </li>
              <li>A delete route with no auth check — flags missing authorization</li>
              <li>
                Server-side <code className="break-all text-zinc-300">fetch(userUrl)</code> —
                flags SSRF risk
              </li>
              <li>SQL built from user input — flags injection risk</li>
            </ul>
          </details>
        </section>

        <section className="mb-8 grid gap-4 sm:mb-10 sm:grid-cols-3">
          {[
            {
              title: "Agent for judgment",
              desc: "Finds auth gaps, insecure design, and context-dependent bugs by reading surrounding code — not just pattern matching the diff.",
            },
            {
              title: "OSV for facts",
              desc: "Known CVEs when npm dependencies change in package.json — advisory IDs from OSV.dev, never hallucinated.",
            },
            {
              title: "Graceful degradation",
              desc: "If OSV or the model fails, the review says so explicitly instead of silently passing.",
            },
          ].map((item) => (
            <div
              key={item.title}
              className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 sm:p-5"
            >
              <h3 className="mb-2 font-semibold text-emerald-400">{item.title}</h3>
              <p className="text-sm leading-relaxed text-zinc-400">{item.desc}</p>
            </div>
          ))}
        </section>

        <details className="group mb-8 rounded-xl border border-zinc-800 bg-zinc-900/30 p-4 sm:mb-10 sm:p-6">
          <summary className="cursor-pointer list-none py-1 text-base font-semibold text-zinc-200 transition hover:text-white sm:text-lg [&::-webkit-details-marker]:hidden">
            <span className="inline-flex min-h-11 items-center gap-2">
              <span
                className="text-emerald-400/70 transition group-open:rotate-90"
                aria-hidden="true"
              >
                ›
              </span>
              How it works
            </span>
          </summary>
          <p className="mb-4 mt-2 text-sm leading-relaxed text-zinc-400">
            Each review spins up a fresh sandbox,
            clones at the PR head, and posts results back to GitHub.
          </p>
          <pre className="max-w-full overflow-x-auto rounded-lg bg-black/40 p-3 text-[11px] leading-relaxed text-zinc-300 sm:p-4 sm:text-xs">
{`pull_request webhook
        │
        ▼
Clone repo @ PR head (Vercel Sandbox — ephemeral)
        │
        ▼
Triage → security-relevant changed files
        │
        ▼
OSV.dev → CVEs on package.json changes (npm, today)
        │
        ▼
AI agent → read diff + surrounding code; reason about
           auth, injection, SSRF, trust boundaries;
           dedupe findings, suggest fixes
        │
        ▼
GitHub PR review + SecureReview check run (+ optional autofix commit)`}
          </pre>
        </details>
      </div>
    </main>
  );
}

function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}
