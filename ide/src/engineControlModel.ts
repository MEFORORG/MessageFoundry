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
 * empty database with no accounts (the ADR 0110 §5 fork hazard, now an explicit, labelled choice).
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
