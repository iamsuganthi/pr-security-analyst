# SecureReview

PR Security Review Agent — Vercel SA tech assessment (AI Cloud track).

Reviews every pull request for OWASP Top 10 vulnerabilities using two signal sources:

1. **OSV.dev** — known CVE lookups on dependency changes (never LLM-hallucinated CVE IDs), with optional auto-commit of safe version bumps
2. **AI SDK agent** — contextual judgment via Sandbox-backed tools (`readFile`, `grep`, `lookupCve`, `submitFindings`)

Untrusted PR code never touches the app runtime — all repo operations run in an isolated Sandbox per review.

## Quick start

```bash
npm install
cp .env.example .env.local
# Fill in GitHub App + Vercel + AI Gateway credentials
npm run dev
```

Webhook endpoint: `POST /api/webhooks/github`

## Environment variables

| Variable | Description |
|---|---|
| `GITHUB_APP_ID` | GitHub App ID |
| `GITHUB_APP_PRIVATE_KEY` | PEM private key (use `\n` for newlines in env) |
| `GITHUB_WEBHOOK_SECRET` | Webhook secret for HMAC verification |
| `VERCEL_TEAM_ID` | Vercel team ID for Sandbox |
| `VERCEL_PROJECT_ID` | Vercel project ID |
| `VERCEL_TOKEN` | Vercel access token |
| `AI_GATEWAY_API_KEY` | Vercel AI Gateway API key |
| `AI_TRIAGE_MODEL` | Cheap triage model (default: `openai/gpt-4o-mini`) |
| `AI_REVIEW_MODEL` | Review model (default: `openai/gpt-4o`) |
| `AI_FALLBACK_MODEL` | Fallback model on error |

## GitHub App setup

1. Create a GitHub App with `pull_request` webhook events
2. Permissions: Pull requests (read & write), Contents (read & write for dependency autofix), Checks (read & write)
3. Subscribe to: `pull_request` (opened, synchronize, reopened)
4. Set webhook URL to `https://your-app.vercel.app/api/webhooks/github`

## Evals

```bash
npm run eval    # Run fixture suite, write scorecard to evals/results/
npm test        # Unit tests (OSV parsing, hallucination checks)
```

12 fixture diffs cover one planted vuln per OWASP category plus 3 clean PRs. Scorecards are committed to `evals/results/` for model comparison.

## Architecture

See [PLAN.md](./PLAN.md) for full architecture, fallback handling, and discussion prep.

## Deploy

```bash
vercel deploy
```

Set all environment variables in the Vercel project dashboard.
