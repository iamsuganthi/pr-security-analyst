import { SemgrepFinding, SemgrepFindingSchema } from "./types";

export interface SandboxToolResult {
  content: string;
  error?: string;
}

export interface SandboxSession {
  readFile(path: string): Promise<SandboxToolResult>;
  grep(pattern: string, path?: string, glob?: string): Promise<SandboxToolResult>;
  runShell(script: string): Promise<{ exitCode: number; stdout: string; stderr: string }>;
  runSemgrep(ruleset?: string): Promise<{ findings: SemgrepFinding[]; raw: string }>;
  destroy(): Promise<void>;
}

export interface CreateSandboxOptions {
  cloneUrl: string;
  revision: string;
  username: string;
  password: string;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 8 * 60 * 1000;

type SandboxCommandRunner = {
  runCommand(params: {
    cmd: string;
    args?: string[];
    sudo?: boolean;
    env?: Record<string, string>;
  }): Promise<{ exitCode: number; stdout(): Promise<string>; stderr(): Promise<string> }>;
};

async function runSandboxShell(
  sandbox: SandboxCommandRunner,
  script: string,
  sudo = false,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const result = await sandbox.runCommand({
    cmd: "sh",
    args: ["-c", script],
    sudo,
  });
  return {
    exitCode: result.exitCode,
    stdout: await result.stdout(),
    stderr: await result.stderr(),
  };
}

/** Semgrep exits 1 when findings exist; 0 when clean; >=2 indicates failure. */
export function isSemgrepScanFailure(exitCode: number): boolean {
  return exitCode >= 2;
}

async function executeSemgrepScan(
  sandbox: SandboxCommandRunner,
  semgrepCmd: string[],
  semgrepEnv: Record<string, string>,
  ruleset: string,
): Promise<{ findings: SemgrepFinding[]; raw: string; crashed: boolean }> {
  const [cmd, ...cmdPrefix] = semgrepCmd;
  const args = [
    ...cmdPrefix,
    "--config",
    ruleset,
    "--json",
    "--quiet",
    "--metrics=off",
    "--timeout",
    "180",
    ".",
  ];

  const result = await sandbox.runCommand({
    cmd: cmd!,
    args,
    env: semgrepEnv,
  });
  const raw = await result.stdout();
  const stderr = await result.stderr();
  const parsed = parseSemgrepOutput(raw, stderr);

  if (parsed.crashed) {
    return parsed;
  }

  if (isSemgrepScanFailure(result.exitCode) && parsed.findings.length === 0) {
    throw new Error(
      `Semgrep scan failed (exit ${result.exitCode}): ${(stderr || raw).slice(0, 500)}`,
    );
  }

  return parsed;
}

export function parseSemgrepOutput(raw: string, stderr: string): {
  findings: SemgrepFinding[];
  raw: string;
  crashed: boolean;
} {
  const combined = raw.trim() || stderr.trim();
  if (!combined) {
    return { findings: [], raw: stderr || raw, crashed: false };
  }

  if (combined.includes("Traceback (most recent call last)")) {
    return { findings: [], raw: combined, crashed: true };
  }

  if (/python -m semgrep.*deprecated/i.test(combined)) {
    return { findings: [], raw: combined, crashed: true };
  }

  try {
    const parsed = JSON.parse(combined) as { results?: unknown[]; errors?: unknown[] };
    const findings: SemgrepFinding[] = [];
    for (const item of parsed.results ?? []) {
      const parsedFinding = SemgrepFindingSchema.safeParse(item);
      if (parsedFinding.success) findings.push(parsedFinding.data);
    }
    return { findings, raw: combined, crashed: false };
  } catch {
    return { findings: [], raw: combined, crashed: combined.includes("Error") };
  }
}

const UV_VERSION = "0.11.25";

function mapUvArch(uname: string): string {
  switch (uname.trim()) {
    case "x86_64":
    case "amd64":
      return "x86_64-unknown-linux-gnu";
    case "aarch64":
    case "arm64":
      return "aarch64-unknown-linux-gnu";
    default:
      return "x86_64-unknown-linux-gnu";
  }
}

function extractMarker(output: string, key: string): string | undefined {
  return output
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line.startsWith(`${key}=`))
    ?.slice(key.length + 1);
}

/** Embedded shell helpers for locating and validating the Semgrep CLI in sandbox. */
const SEMGREP_SHELL_HELPERS = `
resolve_semgrep_cli() {
  BINDIR="$1"
  shift
  for base in "$@"; do
    [ -z "$base" ] && continue
    for candidate in "$BINDIR/semgrep" "$base/bin/semgrep" "$base/bin/osemgrep" "$base/bin/pysemgrep"; do
      if [ -x "$candidate" ]; then
        echo "$candidate"
        return 0
      fi
    done
    CORE=$(find "$base" -type f \\( -name osemgrep -o -name semgrep-core \\) -perm /111 2>/dev/null | head -1)
    if [ -n "$CORE" ]; then
      ln -sf "$CORE" "$BINDIR/semgrep"
      echo "$BINDIR/semgrep"
      return 0
    fi
  done
  return 1
}

validate_semgrep_smoke() {
  SEM="$1"
  HOME="$2"
  SCAN="."
  [ -d "src" ] && SCAN="src"
  mkdir -p "$HOME/.tmp"
  TMPDIR="$HOME/.tmp" SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \\
    "$SEM" --config auto --json --quiet --timeout 60 "$SCAN" \\
    >/tmp/sg_out 2>/tmp/sg_err
  EC=$?
  if grep -q "Traceback" /tmp/sg_err /tmp/sg_out 2>/dev/null; then
    cat /tmp/sg_err /tmp/sg_out >&2
    return 1
  fi
  if grep -qi "python -m semgrep.*deprecated" /tmp/sg_err /tmp/sg_out 2>/dev/null; then
    cat /tmp/sg_err /tmp/sg_out >&2
    return 1
  fi
  [ $EC -eq 0 ] || [ $EC -eq 1 ]
}
`;

/**
 * Install Semgrep via pipx (primary), venv pip, or uv fallback.
 */
export async function installSemgrepInSandbox(
  sandbox: SandboxCommandRunner,
  localBin: string,
  home: string,
): Promise<{ command: string[]; pathPrefix: string } | null> {
  const binDir = localBin;
  const venvBin = `${home}/.local/semgrep-venv/bin`;
  const pathPrefix = `${venvBin}:${binDir}:/usr/bin:/bin`;

  console.error("Semgrep install: home=", home);

  const semgrepInstall = await runSandboxShell(
    sandbox,
    `
${SEMGREP_SHELL_HELPERS}
set +e
VENV="${home}/.local/semgrep-venv"
PIPX_HOME="${home}/.local/pipx"
rm -rf "$VENV"
mkdir -p "${home}/.cache/semgrep" "${home}/.tmp" "${binDir}" "$PIPX_HOME"

dnf install -y python3.11 python3.11-pip python3.11-venv 2>/dev/null
dnf install -y python3 python3-pip python3-venv 2>/dev/null

PY=$(command -v python3.11 || command -v python3)
if [ -z "$PY" ]; then
  echo "python3 not available" >&2
  exit 1
fi

SEM=""
SEARCH_BASES=""

echo "[1/3] pipx install semgrep ($PY)"
export PIPX_HOME
export PIPX_BIN_DIR="${binDir}"
"$PY" -m pip install --upgrade pip pipx wheel 2>&1
"$PY" -m pipx install semgrep --force 2>&1
SEM=$(resolve_semgrep_cli "${binDir}" "$PIPX_HOME/venvs/semgrep")
if [ -n "$SEM" ]; then SEARCH_BASES="$PIPX_HOME/venvs/semgrep"; fi

if [ -z "$SEM" ]; then
  echo "[2/3] python venv + pip semgrep ($PY)"
  "$PY" -m venv "$VENV"
  "$VENV/bin/python" -m pip install --upgrade pip wheel 2>&1
  "$VENV/bin/python" -m pip install "semgrep>=1.96.0" 2>&1
  echo "[validate] installed binaries:"
  ls -la "$VENV/bin" 2>&1 | head -20
  find "$VENV" -type f \\( -name semgrep-core -o -name osemgrep \\) 2>/dev/null | head -3
  SEM=$(resolve_semgrep_cli "${binDir}" "$VENV")
  if [ -n "$SEM" ]; then SEARCH_BASES="$VENV"; fi
fi

if [ -z "$SEM" ]; then
  echo "semgrep CLI not found after pipx and venv install" >&2
  exit 1
fi

echo "[validate] using CLI: $SEM"
echo "[validate] smoke scan"
if validate_semgrep_smoke "$SEM" "${home}"; then
  "$SEM" --version 2>&1
  echo "__SEMGREP_CMD__=$SEM"
  echo "__SEMGREP_BASE__=$SEARCH_BASES"
  exit 0
fi

echo "semgrep smoke scan failed" >&2
exit 1
`,
    false,
  );

  const output = `${semgrepInstall.stdout}\n${semgrepInstall.stderr}`;

  if (semgrepInstall.exitCode !== 0) {
    console.error("Semgrep install: venv path failed:", output.slice(-4000));
    const archResult = await runSandboxShell(sandbox, "uname -m", false);
    const uvArch = mapUvArch(archResult.stdout);
    const uvFallback = await installSemgrepViaUv(sandbox, binDir, home, uvArch);
    if (uvFallback) return uvFallback;
    return null;
  }

  const marker = extractMarker(output, "__SEMGREP_CMD__");
  if (!marker) {
    console.error("Semgrep install: missing marker:", output.slice(-2000));
    return null;
  }

  console.error("Semgrep install: using", marker);
  return { command: parseSemgrepCommandMarker(`__SEMGREP_CMD__=${marker}`), pathPrefix };
}

async function installSemgrepViaUv(
  sandbox: SandboxCommandRunner,
  binDir: string,
  home: string,
  uvArch: string,
): Promise<{ command: string[]; pathPrefix: string } | null> {
  const uvUrl = `https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${uvArch}.tar.gz`;
  const pathPrefix = `${binDir}:/usr/bin:/bin`;

  const uvInstall = await runSandboxShell(
    sandbox,
    `
set -e
mkdir -p "${binDir}" "${home}/.local/share/uv"
TMP=$(mktemp -d)
curl -fL "${uvUrl}" -o "$TMP/uv.tgz"
tar xzf "$TMP/uv.tgz" -C "$TMP"
UV_BIN=$(find "$TMP" -type f -name uv | head -1)
cp "$UV_BIN" "${binDir}/uv"
chmod +x "${binDir}/uv"
"${binDir}/uv" --version
`,
    false,
  );

  if (uvInstall.exitCode !== 0) return null;

  const semgrepInstall = await runSandboxShell(
    sandbox,
    `
${SEMGREP_SHELL_HELPERS}
set +e
export PATH="${binDir}:$PATH"
export UV_CACHE_DIR="${home}/.cache/uv"
export UV_TOOL_DIR="${home}/.local/share/uv/tools"
UV_TOOL_ROOT="${home}/.local/share/uv/tools"
export UV_TOOL_BIN_DIR="${binDir}"
"${binDir}/uv" tool install semgrep --force 2>&1
SEM=$(resolve_semgrep_cli "${binDir}" "$UV_TOOL_ROOT/semgrep" "$UV_TOOL_ROOT")
if [ -z "$SEM" ]; then
  echo "uv semgrep CLI not found" >&2
  exit 1
fi
if validate_semgrep_smoke "$SEM" "${home}"; then
  "$SEM" --version 2>&1
  echo "__SEMGREP_CMD__=$SEM"
  exit 0
fi
exit 1
`,
    false,
  );

  const output = `${semgrepInstall.stdout}\n${semgrepInstall.stderr}`;
  const marker = extractMarker(output, "__SEMGREP_CMD__");
  if (!marker || semgrepInstall.exitCode !== 0) return null;
  return { command: parseSemgrepCommandMarker(`__SEMGREP_CMD__=${marker}`), pathPrefix };
}

export function parseSemgrepCommandMarker(marker: string): string[] {
  const value = marker.replace("__SEMGREP_CMD__=", "").trim();
  if (value.includes(" ")) return value.split(/\s+/);
  if (value.includes("/")) return [value];
  if (value === "python3 -m semgrep") return ["python3", "-m", "semgrep"];
  return ["semgrep"];
}

async function installRipgrep(sandbox: SandboxCommandRunner, localBin: string): Promise<void> {
  await runSandboxShell(
    sandbox,
    `
set +e
mkdir -p "${localBin}"
TMP=$(mktemp -d)
curl -sL https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz | tar xz -C "$TMP"
RG=$(find "$TMP" -type f -name rg | head -1)
if [ -n "$RG" ]; then
  cp "$RG" "${localBin}/rg"
  chmod +x "${localBin}/rg"
fi
`,
    false,
  );
}

export async function createSandboxSession(
  options: CreateSandboxOptions,
): Promise<SandboxSession> {
  const { Sandbox } = await import("@vercel/sandbox");

  const teamId = process.env.VERCEL_TEAM_ID;
  const projectId = process.env.VERCEL_PROJECT_ID;
  const token = process.env.VERCEL_TOKEN;

  if (!teamId || !projectId || !token) {
    throw new Error("VERCEL_TEAM_ID, VERCEL_PROJECT_ID, and VERCEL_TOKEN are required for Sandbox");
  }

  const sandbox = await Sandbox.create({
    teamId,
    projectId,
    token,
    source: {
      type: "git",
      url: options.cloneUrl,
      username: options.username,
      password: options.password,
      revision: options.revision,
      depth: 1,
    },
    runtime: "node24",
    resources: { vcpus: 2 },
    timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  });

  const homeResult = await runSandboxShell(sandbox, 'printf "%s" "$HOME"', false);
  const home = homeResult.stdout.trim() || "/tmp";
  const localBin = `${home}/.local/bin`;

  await installRipgrep(sandbox, localBin);
  const semgrepInstall = await installSemgrepInSandbox(sandbox, localBin, home);

  const workspace = await runSandboxShell(
    sandbox,
    "pwd && ls -la 2>/dev/null | head -25",
    false,
  );
  console.error(
    "Sandbox workspace:",
    workspace.stdout.trim() || workspace.stderr.trim() || "(empty)",
  );

  const semgrepCmd = semgrepInstall?.command ?? null;
  const toolPath = semgrepInstall?.pathPrefix ?? `${localBin}:/usr/bin:/bin`;

  const semgrepEnv = {
    SEMGREP_SEND_METRICS: "off",
    SEMGREP_ENABLE_VERSION_CHECK: "0",
    SEMGREP_TIMEOUT: "180",
    TMPDIR: `${home}/.tmp`,
    PATH: toolPath,
  };

  const session: SandboxSession = {
    async readFile(path: string): Promise<SandboxToolResult> {
      try {
        const result = await sandbox.runCommand({
          cmd: "cat",
          args: [path],
        });
        const content = await result.stdout();
        if (result.exitCode !== 0) {
          return { content: "", error: (await result.stderr()) || "File not found" };
        }
        return { content };
      } catch (err) {
        return { content: "", error: err instanceof Error ? err.message : "readFile failed" };
      }
    },

    async grep(pattern: string, path = ".", glob?: string): Promise<SandboxToolResult> {
      try {
        const args = ["--no-heading", "--line-number", "-C", "2", pattern, path];
        if (glob) args.splice(4, 0, "--glob", glob);
        const result = await sandbox.runCommand({ cmd: "rg", args, env: semgrepEnv });
        const content = await result.stdout();
        return { content: content || "(no matches)" };
      } catch (err) {
        return { content: "", error: err instanceof Error ? err.message : "grep failed" };
      }
    },

    async runShell(script: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
      return runSandboxShell(sandbox, script, false);
    },

    async runSemgrep(ruleset = "p/owasp-top-ten"): Promise<{ findings: SemgrepFinding[]; raw: string }> {
      if (!semgrepCmd) {
        throw new Error("Semgrep not installed in sandbox");
      }

      const rulesets = ruleset === "auto" ? ["auto"] : [ruleset, "auto"];

      for (const config of rulesets) {
        const parsed = await executeSemgrepScan(sandbox, semgrepCmd, semgrepEnv, config);
        if (parsed.crashed) {
          throw new Error(`Semgrep crashed: ${parsed.raw.slice(0, 500)}`);
        }
        if (parsed.findings.length > 0 || config === rulesets[rulesets.length - 1]) {
          return parsed;
        }
      }

      return { findings: [], raw: "" };
    },

    async destroy(): Promise<void> {
      try {
        await sandbox.stop();
      } catch {
        // Sandbox may already be stopped
      }
    },
  };

  return session;
}

export async function withSandbox<T>(
  options: CreateSandboxOptions,
  fn: (session: SandboxSession) => Promise<T>,
): Promise<{ result: T; degraded: boolean }> {
  let session: SandboxSession | null = null;
  try {
    session = await createSandboxSession(options);
    const result = await fn(session);
    return { result, degraded: false };
  } catch {
    return {
      result: await fn(createLocalFallbackSession()),
      degraded: true,
    };
  } finally {
    if (session) await session.destroy();
  }
}

function createLocalFallbackSession(): SandboxSession {
  return {
    async readFile() {
      return { content: "", error: "Sandbox unavailable — diff-only mode" };
    },
    async grep() {
      return { content: "", error: "Sandbox unavailable — diff-only mode" };
    },
    async runShell() {
      return { exitCode: 1, stdout: "", stderr: "Sandbox unavailable" };
    },
    async runSemgrep() {
      return { findings: [], raw: "Sandbox unavailable" };
    },
    async destroy() {},
  };
}

export function semgrepToOwasp(checkId: string, metadata?: { owasp?: string | string[] }): string {
  if (metadata?.owasp) {
    const owasp = Array.isArray(metadata.owasp) ? metadata.owasp[0] : metadata.owasp;
    const match = owasp.match(/A\d{2}/);
    if (match) return match[0];
  }
  const id = checkId.toLowerCase();
  if (id.includes("sql") || id.includes("xss") || id.includes("injection")) return "A03";
  if (id.includes("ssrf")) return "A10";
  if (id.includes("cors") || id.includes("cookie") || id.includes("header")) return "A05";
  if (id.includes("secret") || id.includes("crypto") || id.includes("md5")) return "A02";
  if (id.includes("jwt") || id.includes("auth")) return "A07";
  if (id.includes("deserial")) return "A08";
  return "A03";
}

export function mapSemgrepSeverity(severity?: string): "critical" | "high" | "medium" | "low" | "info" {
  const s = (severity ?? "WARNING").toUpperCase();
  if (s === "ERROR") return "high";
  if (s === "WARNING") return "medium";
  if (s === "INFO") return "low";
  return "medium";
}
