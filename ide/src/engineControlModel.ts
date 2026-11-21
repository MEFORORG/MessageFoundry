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
import { isFullyQualifiedPath } from "./engineTrustModel";

/** The interpreter import used to preflight before launching `serve`. It is `serve`'s own early import
 *  chain (config.models imports pydantic), so it fails for BOTH "wrong interpreter, no messagefoundry"
 *  AND "messagefoundry source on the path but its dependencies are not installed" — which is exactly the
 *  `ModuleNotFoundError: No module named 'pydantic'` a hand-run `python -m messagefoundry serve` produces. */
export const PREFLIGHT_IMPORT = "messagefoundry.config.models";

/** The interpreter options the pill's engine lifecycle takes: the preflight, provision-admin (and
 *  its held wrapper) and serve. `-P` keeps the working directory off the import path, so all of
 *  them import the same engine; `-X disable-remote-debug` is what serve's enforce refusal names
 *  (vault BACKLOG #2700). The CLI bridge in cli.ts (validate, graph and the rest) takes them too,
 *  through {@link cliArgv} (BACKLOG #5409). */
export const INTERPRETER_OPTIONS: readonly string[] = ["-P", "-X", "disable-remote-debug"];

/**
 * The argv after the interpreter for `python -m <module> <args>`, as cli.ts's `run` and
 * `runWithStdin` launch it (BACKLOG #5409). The interpreter options come first: `-P` keeps the
 * working directory, which is the workspace, off the import path, so at least a `messagefoundry.py`
 * or a stdlib-named module in the workspace root no longer shadows the installed one through the
 * cwd entry. It does not remove an empty or `.` entry an inherited PYTHONPATH supplies.
 */
export function cliArgv(module: string, args: readonly string[]): string[] {
  return [...INTERPRETER_OPTIONS, "-m", module, ...args];
}

/**
 * The program the Test Bench's Debug launch hands debugpy in place of `module: "messagefoundry"`
 * (BACKLOG #5409 item 2): its folder below the extension's global storage, its file name, and its
 * source. `-P` alone does not hold for a module: a debugpy older than 1.8.22, which includes the
 * 1.8.21 the Python Debugger extension bundles at the time of writing, inserts the working
 * directory, the workspace, into `sys.path` when it runs a module, whatever `-P` says. For a
 * program it adds at most the program's own folder, which the extension writes and which holds
 * only this file, and the file runs the installed package through `runpy`. So `-P` keeps the
 * workspace off the import path on every debugpy build. The source is written at launch rather
 * than shipped, because the extension package holds no Python (the crypto inventory's ide/ arm
 * reads only TypeScript).
 */
export const TEST_BENCH_DEBUG_PROGRAM = {
  folder: "testbench-debug",
  file: "mefor_testbench_debug.py",
  source: [
    "# Written by the MessageFoundry extension for the Test Bench Debug launch (BACKLOG #5409 item 2).",
    "import runpy",
    "",
    'runpy.run_module("messagefoundry", run_name="__main__", alter_sys=True)',
    "",
  ].join("\n"),
} as const;

/** The argv for the preflight import check (`python <these>`). */
export function preflightArgs(): string[] {
  return [...INTERPRETER_OPTIONS, "-c", `import ${PREFLIGHT_IMPORT}`];
}

/** The service TOML serve reads from its working directory when it is given no `--service-config`. */
export const SERVE_DEFAULT_SERVICE_CONFIG = "messagefoundry.toml";

/**
 * The `--service-config` Start hands serve, the admin probe and provision-admin (BACKLOG #5566). It
 * IS connectionServiceConfig, which states the rule, so Start and connection edits cannot resolve one
 * setting to two files. With the flag off, serve reads {@link SERVE_DEFAULT_SERVICE_CONFIG}, and the
 * fork guard judges that file.
 */
export { connectionServiceConfig as startServiceConfigValue } from "./connectionWizardModel";
import { connectionServiceConfig } from "./connectionWizardModel";

/** The `--service-config` element serve, the probe and provision-admin share, or none when undefined.
 *  Bound with `=`, so a path that starts with a dash stays a value and never becomes a flag. */
function serviceConfigFlag(serviceConfig: string | undefined): string[] {
  return serviceConfig === undefined ? [] : [`--service-config=${serviceConfig}`];
}

/**
 * The `messagefoundry ai-policy` argv (sans the `--json` runJson appends) for the IDE's offline
 * fallback (BACKLOG #5405). `setting` is `messagefoundry.serviceConfig` and `isSet` whether the
 * operator set it. It always names a file: with no flag the CLI reads `./messagefoundry.toml` only
 * if it exists and otherwise answers the built-in default, which can enable assistance. Named, a
 * missing or unreadable file is refused, and pickOfflinePolicy then fails closed to the unverified
 * policy.
 *
 * The file is the one Start hands serve ({@link startServiceConfigValue}), except that an unset or
 * blank setting, where serve gets no flag and reads {@link SERVE_DEFAULT_SERVICE_CONFIG}, names
 * that file explicitly. Bound by {@link serviceConfigFlag}, as serve's own flag is.
 */
export function aiPolicyCliArgs(setting: unknown, isSet: boolean): string[] {
  return ["ai-policy", ...serviceConfigFlag(aiPolicyServiceFile(setting, isSet))];
}

/** The service-settings file ai-policy is told to read: one rule for the argv and the plan's gate. */
function aiPolicyServiceFile(setting: unknown, isSet: boolean): string {
  return connectionServiceConfig(setting, isSet) ?? SERVE_DEFAULT_SERVICE_CONFIG;
}

/**
 * The {@link aiPolicyCliArgs} argv and the directory it runs in, or undefined when it must not run
 * (BACKLOG #5405). With no workspace folder the CLI would run in the extension host's own working
 * directory, and a relative service-settings path would be read from there, where a stray file could
 * enable assistance. So with no folder only a fully qualified path runs, the way engine trust's
 * `cert inventory` asks the CLI only with a folder. Refused, the caller has no CLI answer and
 * pickOfflinePolicy fails closed to the unverified policy.
 */
export function aiPolicyCliPlan(
  setting: unknown,
  isSet: boolean,
  workspace: string | undefined,
): { readonly args: string[]; readonly cwd: string | undefined } | undefined {
  const file = aiPolicyServiceFile(setting, isSet);
  // `!workspace`, not `=== undefined`: an empty string is no folder either. Fully qualified, not
  // just absolute: on Windows a root-relative `\svc\x.toml` is absolute but still takes the
  // current drive. The test is engine trust's own, so the two folderless rules cannot drift.
  if (!workspace && !isFullyQualifiedPath(file)) {
    return undefined;
  }
  return { args: aiPolicyCliArgs(setting, isSet), cwd: workspace || undefined };
}

/**
 * The command the pill's Start action runs. Deliberately identical to the command ADR 0110 shipped for the
 * clipboard — `python -P -X disable-remote-debug -m messagefoundry serve --config <configDir>`, the options
 * added for vault BACKLOG #2700 and named by serve's own refusal — with NO `--db`/`--env`/`--port`
 * overrides: the service TOML is the authority on which store, which environment and which port this engine
 * is (ADR 0110 rejected a `messagefoundry.engineEnv` setting for exactly this reason). The only change from
 * "copy" to "run" is that `python` is the resolved workspace interpreter, not whatever the user's terminal
 * happens to resolve — which is the entire fix for the reported `ModuleNotFoundError`.
 *
 * `configDir` is passed as a single argv element, so a path with spaces needs no quoting (the shell never
 * re-parses it — it is `shellArgs` to a `createTerminal`, i.e. argv, not a command line).
 *
 * `serviceConfig` names the service TOML: the value `connectionServiceConfig` gives for the
 * `messagefoundry.serviceConfig` setting, undefined when the setting is left at its default (BACKLOG
 * #5566). It is the file the Start fork guard looked at, so `serve` must open the same one. Left off,
 * `serve` reads `./messagefoundry.toml`, so with a non-default setting the guard judged one file and
 * `serve` opened none and created a new default store. Undefined leaves the flag off, where `serve`
 * falls back to the same default file the setting names.
 */
export function buildServeInvocation(opts: {
  python: string;
  configDir: string;
  serviceConfig?: string;
}): { command: string; args: string[] } {
  return {
    command: opts.python,
    // Vault BACKLOG #2700: under the default enforce, serve refuses to start with the
    // interpreter's remote debugging on. The argv is the launch that refusal names.
    args: cliArgv("messagefoundry", [
      "serve",
      "--config",
      opts.configDir,
      ...serviceConfigFlag(opts.serviceConfig),
    ]),
  };
}

/** The pill's Start command as one line, for the clipboard and for hints: the argv of
 *  {@link buildServeInvocation}, with `python` for the interpreter, and an element holding
 *  whitespace double-quoted so a pasted path with a space stays one argument. */
export function serveCommandLine(configDir: string, serviceConfig?: string): string {
  const args = buildServeInvocation({ python: "python", configDir, serviceConfig }).args;
  return ["python", ...args.map((a) => (/\s/.test(a) ? `"${a}"` : a))].join(" ");
}

/** The Start command as a hint, for text that cannot read the settings (an error message): the
 *  command Start runs, with the `--service-config` it adds when `messagefoundry.serviceConfig` is
 *  set named too, so the hint never omits a flag Start passes (BACKLOG #5566). */
export function serveCommandHint(): string {
  return (
    `\`${serveCommandLine("<configDir>")}\`, adding \`--service-config=<file>\` when ` +
    "messagefoundry.serviceConfig is set and not blank"
  );
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
 *   - a workspace without one is a config repo ⇒ install the published engine AND toolkit, since the
 *     extension's Steps view and Generate Samples run the toolkit (ADR 0201 slice 4). A scaffolded
 *     repo's `requirements.txt` and `requirements-dev.txt` pin both, so they are installed as written;
 *     the repo's own install step would otherwise move the engine off a toolkit installed beside it,
 *     and the toolkit refuses to run beside another engine version. Without both files, the two are
 *     installed unpinned, and the toolkit's exact engine pin makes pip resolve them to one version.
 * The venv is created with a base `python` (venv is stdlib, so any Python 3 can), then the venv's own
 * interpreter does the install. Returned as strings (not argv) because the shell TYPES them into a real
 * terminal the user watches — the venv interpreter path is platform-specific and shell-runnable as-is.
 */
export function buildBootstrapPlan(opts: {
  hasPyproject: boolean;
  hasPinFiles?: boolean;
  platform: NodeJS.Platform;
}): { steps: string[]; venvPython: string } {
  const venvPython =
    opts.platform === "win32" ? ".\\.venv\\Scripts\\python.exe" : "./.venv/bin/python";
  const target = opts.hasPyproject
    ? "-e ."
    : opts.hasPinFiles
      ? "-r requirements.txt -r requirements-dev.txt"
      : "messagefoundry messagefoundry-toolkit";
  return {
    steps: [`python -m venv .venv`, `${venvPython} -m pip install ${target}`],
    venvPython,
  };
}


// ── Provision before serve (ADR 0183 Amendment A, Wave 5 — BACKLOG #1136, ASVS 6.3.2) ─────────────────
// The engine creates no account on its own. A `serve` on a store with no enabled Administrator either
// refuses (the shipped posture) or starts with nobody able to manage users and roles. So Start runs
// `provision-admin` first, and only then `serve`.
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
// first. Since vault BACKLOG #2711 step 1 the first answer means an enabled LOCAL Administrator with a
// usable password, so a store whose Administrators all sign in through the directory gets the second
// answer. The modal in `statusBar.ts` words both cases: no Administrator at all, or only ones that need
// an outside service (vault BACKLOG #3849 B3).
//
// The probe and the provisioning terminal run in the workspace, as `serve` does, with no `--db`, and
// with the same `--service-config` `serve` gets (BACKLOG #5566), so all three read one service TOML.
// In the default layout that is the store `serve` opens. It is NOT when the service TOML sets
// `[environments].base_dir`: `serve` anchors a relative `[store].path` under it, and
// `provision-admin` does not (yet). The probe is advice, never the control: `serve` applies its own gates.

/** The username the probe passes. `provision-admin` requires one, and the probe never reaches the step
 *  that would use it: with no terminal, the command refuses before it asks for a password. */
export const PROBE_USERNAME = "probe";

/** The address the probe passes. `provision-admin` requires `--email` (BACKLOG #1138) and checks its shape
 *  first, so the probe needs one that passes. Nothing stores it: with no terminal, the command refuses
 *  before it asks for a password. `.invalid` is a reserved name, so it can be no real mailbox. */
export const PROBE_EMAIL = "probe@example.invalid";

/** The fragment of `provision-admin`'s refusal that means "an enabled Administrator already exists". */
export const ADMIN_EXISTS_REFUSAL = "already has an enabled Administrator";

/** The fragment of `provision-admin`'s refusal when no terminal is attached: the store needs one. */
export const NO_TERMINAL_REFUSAL = "refusing to provision without a terminal";

/** Who to provision. The address is not a secret; the password is never here, and never in argv. */
export interface AdminDetails {
  username: string;
  /** The notification address. `provision-admin` requires one (BACKLOG #1138). */
  email: string;
}

/**
 * The `provision-admin` argv. Each value is bound with `=`, so a value that starts with a dash stays a value
 * and never becomes a flag. The address always rides, trimmed: `provision-admin` refuses a blank one.
 * `serviceConfig` is {@link buildServeInvocation}'s, so the Administrator lands in the store `serve`
 * opens; undefined leaves the flag off.
 */
export function buildProvisionInvocation(opts: { python: string; serviceConfig?: string } & AdminDetails): {
  command: string;
  args: string[];
} {
  const args = cliArgv("messagefoundry", [
    "provision-admin",
    `--username=${opts.username}`,
    `--email=${opts.email.trim()}`,
    ...serviceConfigFlag(opts.serviceConfig),
  ]);
  return { command: opts.python, args };
}

/** The probe's argv: {@link buildProvisionInvocation} for {@link PROBE_USERNAME} and {@link PROBE_EMAIL},
 *  answering in JSON, against the same service TOML. */
export function buildAdminProbeInvocation(opts: { python: string; serviceConfig?: string }): {
  command: string;
  args: string[];
} {
  const inv = buildProvisionInvocation({
    python: opts.python,
    serviceConfig: opts.serviceConfig,
    username: PROBE_USERNAME,
    email: PROBE_EMAIL,
  });
  return { command: inv.command, args: [...inv.args, "--json"] };
}

/**
 * A terminal whose process is the command closes the moment the command exits, taking its output with it:
 * a refused password, a refused address, the "OK: created" line. So the provisioning terminal runs
 * this small Python wrapper instead. It runs the same interpreter with the same argv, inherits the terminal
 * (so `provision-admin` still sees a real terminal and reads the password there), then waits for Enter and
 * exits with the command's own code. One line, no backslashes, so it survives Windows argv quoting.
 */
export const HOLD_OPEN_SCRIPT =
  "import subprocess, sys; rc = subprocess.call([sys.executable, *sys.argv[1:]]); print(); " +
  "print('Any authenticator key or recovery codes above are secrets. Save the codes now: " +
  "pressing Enter clears this terminal and closes it.'); " +
  "input('provision-admin finished (exit code %d). Press Enter to close this terminal. ' % rc); " +
  "print(chr(27) + '[3J' + chr(27) + '[2J', end='', flush=True); " +
  "sys.exit(rc)";

/** Wrap an invocation so its terminal stays open until the user has read it (see {@link HOLD_OPEN_SCRIPT}). */
export function buildHeldInvocation(inv: { command: string; args: string[] }): {
  command: string;
  args: string[];
} {
  // The wrapper takes the options too: it runs in the workspace, where -P keeps a stray module
  // there from replacing the subprocess module the wrapper imports.
  return { command: inv.command, args: [...INTERPRETER_OPTIONS, "-c", HOLD_OPEN_SCRIPT, ...inv.args] };
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

/** The address prompt's check: blank is refused here, and everything else is the engine's to judge. */
export function validateProvisionEmail(value: string): string | undefined {
  return value.trim() === "" ? "Enter a notification address for the first administrator." : undefined;
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
  /** The store has no enabled local Administrator with a usable password: provision one (the default),
   *  start without one, or stop. */
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
 *   3. No Administrator → provision one (the default), or start without one: at the shipped posture
 *      `serve` refuses, and its Administrator check names `provision-admin` itself. Under `warn`, or
 *      with the security-notice requirement waived, it can start and route HL7, and nobody can manage
 *      users and roles. `serve` cannot run with sign-in off.
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
