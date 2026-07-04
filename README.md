# Secure Review

GitHub App that reviews pull requests for security issues — OSV-backed dependency checks, an AI agent for logic flaws, and optional autofix commits.

**Live app:** https://pr-security-analyst.vercel.app

**Try it:** [Install the GitHub App](https://github.com/apps/pr-security-analyst/installations/new) on a repo you control, then open a pull request.

## What it does

- Clones the PR branch in an ephemeral Vercel Sandbox
- Looks up known CVEs when `package.json` changes (npm only, today)
- Runs an AI agent to flag auth gaps, injection, SSRF, and similar issues
- Posts a PR review, inline comments, and a SecureReview check run
- Commits dependency version bumps when OSV has a fixed version

## Local development

```bash
npm install
cp .env.example .env.local
# Fill in GitHub App, Vercel Sandbox, and AI Gateway credentials
npm run dev
```

## Scripts

```bash
npm test          # Unit tests
npm run eval      # Fixture regression suite (dev only)
```

