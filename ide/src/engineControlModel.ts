// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Pure (vscode-free, I/O-free) logic for the engine LIFECYCLE the status bar drives — the decisions the
// shell (statusBar.ts) needs but that must be unit-testable node-side, like engineStatusModel.ts. No
// vscode, no child_process, no fs: the shell does the exec/fs and hands the RESULTS to these functions.
//
// The boundary this preserves (ADR 0110 §5, superseded by ADR 0112): the IDE may now RUN `serve`, but only in a
// way that cannot fork the user's engine with a rogue empty database. That safety lives in two places —
// the gating in engineStatusModel's EngineControlContext (WHETHER to offer Start), and the invocation
// built here (WHAT Start runs): the exact command ADR 0110 blessed for the clipboard — `serve --config
// <dir>` with NO --db/--env overrides, so the service TOML stays the sole authority on store + environment.

/** The interpreter import used to preflight before launching `serve`. It is `serve`'s own early import
 *  chain (config.models imports pydantic), so it fails for BOTH "wrong interpreter, no messagefoundry"
 *  AND "messagefoundry source on the path but its dependencies are not installed" — which is exactly the
 *  `ModuleNotFoundError: No module named 'pydantic'` a hand-run `python -m messagefoundry serve` produces. */
export const PREFLIGHT_IMPORT = "messagefoundry.config.models";

/** The argv for the preflight import check (`python <these>`). */
export function preflightArgs(): string[] {
  return ["-c", `import ${PREFLIGHT_IMPORT}`];
}

/**
 * The command the pill's Start action runs. Deliberately identical to the command ADR 0110 shipped for the
 * clipboard — `python -m messagefoundry serve --config <configDir>` — with NO `--db`/`--env`/`--port`
 * overrides: the service TOML is the authority on which store, which environment and which port this engine
 * is (ADR 0110 rejected a `messagefoundry.engineEnv` setting for exactly this reason). The only change from
 * "copy" to "run" is that `python` is the resolved workspace interpreter, not whatever the user's terminal
 * happens to resolve — which is the entire fix for the reported `ModuleNotFoundError`.
 *
 * `configDir` is passed as a single argv element, so a path with spaces needs no quoting (the shell never
 * re-parses it — it is `shellArgs` to a `createTerminal`, i.e. argv, not a command line).
 */
export function buildServeInvocation(opts: {
  python: string;
  configDir: string;
}): { command: string; args: string[] } {
  return {
    command: opts.python,
    args: ["-m", "messagefoundry", "serve", "--config", opts.configDir],
  };
}

/** The outcome of the interpreter preflight, each with a DIFFERENT remedy. */
export type PreflightVerdict = "ok" | "missingDeps" | "missingInterpreter" | "error";

/**
 * Classify the preflight import (`python -c "import messagefoundry.config.models"`). Pure over the exec
 * result the shell captures:
 *   - `spawnError` set (ENOENT / "not recognized") ⇒ the interpreter itself is not runnable → missingInterpreter
 *   - exit 0 ⇒ ok
 *   - a `No module named` on stderr ⇒ the interpreter runs but the package/deps are absent → missingDeps
 *     (the reported failure: a `python` without pydantic / without messagefoundry installed)
 *   - anything else ⇒ error (surface stderr; let the user decide whether to launch anyway)
 */
export function classifyPreflight(result: {
  code: number;
  stderr: string;
  spawnError?: string;
}): PreflightVerdict {
  if (result.spawnError) {
    return "missingInterpreter";
  }
  if (result.code === 0) {
    return "ok";
  }
  if (/no module named/i.test(result.stderr)) {
    return "missingDeps";
  }
  return "error";
}

/**
 * Whether a REAL engine store already lives where `serve` would run. Pure over what the shell reads from
 * the run directory. When false, Start must not silently create a store — it confirms it will make a NEW
 * database (the ADR 0110 §5 fork hazard, now an explicit, labelled choice). It does NOT say whether the
 * store holds an Administrator; {@link runStartPlan} asks the engine that, whatever this returns.
 *
 * The heuristic is deliberately permissive-of-presence: the service TOML OR any `*.db` file is enough to
 * say "an engine already lives here", because either one means a `serve` run here adopts an existing engine
 * rather than forking a fresh one.
 */
export function runDirHasEngine(opts: { serviceTomlExists: boolean; dbFiles: string[] }): boolean {
  return opts.serviceTomlExists || opts.dbFiles.length > 0;
}

/**
 * The shell commands the "Set up Python environment" bootstrap types into a terminal, for the case where
 * the resolved interpreter cannot import messagefoundry (a fresh clone with no venv / uninstalled deps).
 * Pure over `{ hasPyproject, platform }`:
 *   - a workspace WITH a `pyproject.toml` is the source checkout ⇒ an editable install (`-e .`);
 *   - a workspace without one is a config repo ⇒ install the published package.
 * The venv is created with a base `python` (venv is stdlib, so any Python 3 can), then the venv's own
 * interpreter does the install. Returned as strings (not argv) because the shell TYPES them into a real
 * terminal the user watches — the venv interpreter path is platform-specific and shell-runnable as-is.
 */
export function buildBootstrapPlan(opts: {
  hasPyproject: boolean;
  platform: NodeJS.Platform;
}): { steps: string[]; venvPython: string } {
  const venvPython =
    opts.platform === "win32" ? ".\\.venv\\Scripts\\python.exe" : "./.venv/bin/python";
  const target = opts.hasPyproject ? "-e ." : "messagefoundry";
  return {
    steps: [`python -m venv .venv`, `${venvPython} -m pip install ${target}`],
    venvPython,
  };
}


// ── Provision before serve (ADR 0183 Amendment A, Wave 5 — BACKLOG #1136, ASVS 6.3.2) ─────────────────
// The engine creates no account on its own. A `serve` on a store with no enabled Administrator either
// refuses (the shipped posture) or starts with nobody able to sign in. So Start runs `provision-admin`
// first, and only then `serve`.
//
// `serve` is its terminal's own process (`createTerminal` with `shellPath`), so there is no shell to chain
// a command in front of it. Provisioning therefore gets its OWN terminal, and the plan waits for it to
// exit before `serve` starts. The password is typed into that terminal: `provision-admin` reads it from
// the terminal and has no `--password` on purpose, and nothing here may add a way round that.
//
// Store presence alone cannot decide this, because a store can exist with no Administrator in it. So the
// plan ASKS the engine, with a probe: `provision-admin` run with no terminal. It answers "an enabled
// Administrator already exists" BEFORE it checks for a terminal, and otherwise refuses for want of one.
// It creates no store and no account either way. The first answer is go-ahead; the second means provision
// first.
//
// The probe and the provisioning terminal run in the workspace, as `serve` does, with no `--db` or
// `--service-config`. In the default layout that is the store `serve` opens. It is NOT when the service
// TOML sets `[environments].base_dir`: `serve` anchors a relative `[store].path` under it, and
// `provision-admin` does not (yet). The probe is advice, never the control: `serve` applies its own gates.

/** The username the probe passes. `provision-admin` requires one, and the probe never reaches the step
 *  that would use it: with no terminal, the command refuses before it asks for a password. */
export const PROBE_USERNAME = "probe";

/** The fragment of `provision-admin`'s refusal that means "an enabled Administrator already exists". */
export const ADMIN_EXISTS_REFUSAL = "already has an enabled Administrator";

/** The fragment of `provision-admin`'s refusal when no terminal is attached: the store needs one. */
export const NO_TERMINAL_REFUSAL = "refusing to provision without a terminal";

/** Who to provision. The address is not a secret; the password is never here, and never in argv. */
export interface AdminDetails {
  username: string;
  /** The notification address. The shipped posture refuses to start without one on some Administrator. */
  email?: string;
}

/**
 * The `provision-admin` argv. Each value is bound with `=`, so a name that starts with a dash stays a value
 * and never becomes a flag. A blank address is left out, which `provision-admin` treats as no address.
 */
export function buildProvisionInvocation(opts: { python: string } & AdminDetails): {
  command: string;
  args: string[];
} {
  const args = ["-m", "messagefoundry", "provision-admin", `--username=${opts.username}`];
  if (opts.email !== undefined && opts.email.trim() !== "") {
    args.push(`--email=${opts.email.trim()}`);
  }
  return { command: opts.python, args };
}

/** The probe's argv: {@link buildProvisionInvocation} for {@link PROBE_USERNAME}, answering in JSON. */
export function buildAdminProbeInvocation(opts: { python: string }): {
  command: string;
  args: string[];
} {
  const inv = buildProvisionInvocation({ python: opts.python, username: PROBE_USERNAME });
  return { command: inv.command, args: [...inv.args, "--json"] };
}

/**
 * A terminal whose process is the command closes the moment the command exits, taking its output with it:
 * a refused password, the "OK: created" line, the missing-address warning. So the provisioning terminal runs
 * this small Python wrapper instead. It runs the same interpreter with the same argv, inherits the terminal
 * (so `provision-admin` still sees a real terminal and reads the password there), then waits for Enter and
 * exits with the command's own code. One line, no backslashes, so it survives Windows argv quoting.
 */
export const HOLD_OPEN_SCRIPT =
  "import subprocess, sys; rc = subprocess.call([sys.executable, *sys.argv[1:]]); print(); " +
  "print('The authenticator key and the recovery codes above are secrets. Save the codes now: " +
  "pressing Enter clears this terminal and closes it.') if rc == 0 else None; " +
  "input('provision-admin finished (exit code %d). Press Enter to close this terminal. ' % rc); " +
  "print(chr(27) + '[3J' + chr(27) + '[2J', end='', flush=True) if rc == 0 else None; " +
  "sys.exit(rc)";

/** Wrap an invocation so its terminal stays open until the user has read it (see {@link HOLD_OPEN_SCRIPT}). */
export function buildHeldInvocation(inv: { command: string; args: string[] }): {
  command: string;
  args: string[];
} {
  return { command: inv.command, args: ["-c", HOLD_OPEN_SCRIPT, ...inv.args] };
}

/** What the shell captured from running the probe with no terminal. */
export interface AdminProbeResult {
  code: number;
  stdout: string;
  stderr: string;
  spawnError?: string;
}

export type AdminProbeVerdict = "adminExists" | "needsAdmin" | "refused";

/** The `--json` error object's message on stdout, if the probe printed one. */
function probeJsonError(stdout: string): string | undefined {
  for (const line of stdout.split(/\r?\n/)) {
    try {
      const parsed = JSON.parse(line) as unknown;
      if (parsed !== null && typeof parsed === "object" && "error" in parsed) {
        const err = (parsed as { error: unknown }).error;
        if (typeof err === "string") {
          return err;
        }
      }
    } catch {
      // Not the JSON line; keep looking.
    }
  }
  return undefined;
}

/**
 * Classify the probe. Only a REFUSAL can carry either answer, and only in the `--json` error object the probe
 * asks for: free text on stderr (a log line, a traceback) is kept as the reason for a refusal and never read
 * as an answer. An exit code of 0 is never go-ahead: the probe cannot succeed without a terminal, so a
 * success means the command is not the one this expects.
 */
export function classifyAdminProbe(r: AdminProbeResult): {
  verdict: AdminProbeVerdict;
  detail: string;
} {
  if (r.spawnError) {
    return { verdict: "refused", detail: `could not run Python (${r.spawnError})` };
  }
  if (r.code === 0) {
    return {
      verdict: "refused",
      detail: "provision-admin answered without refusing, which the check does not expect",
    };
  }
  const answer = probeJsonError(r.stdout);
  if (answer !== undefined && answer.includes(ADMIN_EXISTS_REFUSAL)) {
    return { verdict: "adminExists", detail: answer };
  }
  if (answer !== undefined && answer.includes(NO_TERMINAL_REFUSAL)) {
    return { verdict: "needsAdmin", detail: answer };
  }
  const detail = answer ?? r.stderr.trim().replace(/^error:\s*/, "");
  return { verdict: "refused", detail: detail || `provision-admin exited with code ${r.code}` };
}

/** The store-less fork guard's confirm text (ADR 0110 §5): a NEW database, and its first Administrator. */
export function storeLessStartPrompt(ws: string): string {
  return (
    `No engine store found in ${ws}. Starting here creates a NEW database. ` +
    "You will be asked to provision its first administrator before the engine starts. Continue?"
  );
}

/** The username prompt's check: blank is refused here, and everything else is the engine's to judge. */
export function validateProvisionUsername(value: string): string | undefined {
  return value.trim() === "" ? "Enter a username for the first administrator." : undefined;
}

export type StartOutcome =
  | "served"
  | "servedWithoutAdmin"
  | "servedDespiteRefusal"
  | "cancelled"
  | "refused"
  | "notProvisioned";

/** The I/O the Start plan needs. The shell (statusBar.ts) supplies each one; the tests supply fakes. */
export interface StartPlanEffects {
  /** Run the probe with no terminal and capture what it printed. */
  probeAdmin(): Promise<AdminProbeResult>;
  /** The store has no enabled Administrator: provision one (the default), start without one, or stop. */
  chooseToProvision(): Promise<"provision" | "skip" | undefined>;
  /** The probe could not answer: show why, then provision anyway, start anyway, or stop. */
  chooseAfterRefusal(detail: string): Promise<"provision" | "startAnyway" | undefined>;
  /** Ask for the first administrator's username and address; undefined when the user cancels. */
  askAdmin(): Promise<AdminDetails | undefined>;
  /** Run `provision-admin` in its own terminal and resolve with its exit code once it has exited. */
  provisionInTerminal(admin: AdminDetails): Promise<number | undefined>;
  /** Start `serve`. Called at most once. */
  serve(): void;
  /** Tell the user why the engine was not started. */
  report(message: string): void;
}

/**
 * The Start plan: provision an Administrator if the store needs one, then serve.
 *
 *   1. Probe. "An enabled Administrator already exists" → serve.
 *   2. The probe could not answer (a keyless shell, a bad config, an environment the terminal has and the
 *      IDE does not) → show the reason, and let the user provision anyway or start anyway. `serve`
 *      applies every gate itself, so this weakens nothing; refusing outright would make Start a dead end
 *      the probe itself caused.
 *   3. No Administrator → provision one (the default), or start without one: a posture with sign-in off
 *      needs none, and at the shipped posture `serve` refuses and names `provision-admin` itself.
 *   4. Provision: ask a username and address, run `provision-admin` in its own terminal, wait for it to
 *      exit, and ALWAYS probe again. An exit code alone is not trusted: on macOS and Linux a Ctrl+C can
 *      surface as exit 0. "Already exists" → serve. Exit 0 and a probe that still cannot answer → serve,
 *      so an environment only the terminal has cannot strand a real success. Otherwise nothing starts.
 */
export async function runStartPlan(fx: StartPlanEffects): Promise<StartOutcome> {
  const first = classifyAdminProbe(await fx.probeAdmin());
  if (first.verdict === "adminExists") {
    fx.serve();
    return "served";
  }
  if (first.verdict === "refused") {
    const pick = await fx.chooseAfterRefusal(first.detail);
    if (pick === undefined) {
      return "refused";
    }
    if (pick === "startAnyway") {
      fx.serve();
      return "servedDespiteRefusal";
    }
  } else {
    const choice = await fx.chooseToProvision();
    if (choice === undefined) {
      return "cancelled";
    }
    if (choice === "skip") {
      fx.serve();
      return "servedWithoutAdmin";
    }
  }
  const admin = await fx.askAdmin();
  if (admin === undefined) {
    return "cancelled";
  }
  const code = await fx.provisionInTerminal(admin);
  const again = classifyAdminProbe(await fx.probeAdmin());
  if (again.verdict === "adminExists" || (code === 0 && again.verdict === "refused")) {
    fx.serve();
    return "served";
  }
  fx.report(
    "no administrator was provisioned, so the engine was not started. The provisioning terminal " +
      "showed why; fix that and choose Start again.",
  );
  return "notProvisioned";
}
