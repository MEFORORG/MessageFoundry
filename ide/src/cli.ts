// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Thin bridge to the `messagefoundry` Python CLI: shell out to a subcommand and parse its JSON. The
// authoring commands (`lens`, `generate`) run under the toolkit's module instead (ADR 0201 slice 4).
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";

import {
  ENGINE_MODULE,
  TOOLKIT_MODULE,
  UNTRUSTED_WORKSPACE_STDERR,
  explainMissingToolkit,
  parseJsonResult,
  type CliModule,
  type CliResult,
} from "./cliJson";
import { connectionServiceConfig, settingIsSet } from "./connectionWizardModel";
import { contextCharLimitOf } from "./aiPolicyModel";
import { cliArgv } from "./engineControlModel";
import { LENS_CONTRACT, isUnknownArgumentError, looksLikeUnknownArgument } from "./stepsModel";
import type { LensParseResult, OpSchema } from "./stepsModel";
import {
  containedPathSetting,
  droppedNotice,
  escapesByLink,
  linkEscapeRefusal,
  writerRefusal,
  type ContainedPathSetting,
  type PathSettingKey,
} from "./workspaceContainment";

// Parsing lives in cliJson.ts (no vscode, so the unit suite runs it). Every importer of CliResult
// keeps importing it from here.
export type { CliResult } from "./cliJson";

function config() {
  return vscode.workspace.getConfiguration("messagefoundry");
}

/**
 * Pure interpreter selection (testable without the Extension Host). An explicitly-configured
 * interpreter is always honored verbatim. The default ("python") auto-detects a workspace-local
 * `.venv`, but ONLY in a trusted workspace: a checked-in/cloned repo can ship a trojaned
 * `.venv/Scripts/python.exe` (Windows) or `.venv/bin/python` (POSIX), and silently preferring that
 * repo-supplied binary over PATH would let an untrusted workspace run arbitrary code on the first
 * CLI launch (SEC-004, CWE-426). When untrusted, we skip the .venv probe and fall through to PATH.
 */
export function resolvePythonPath(opts: {
  configured: string;
  workspace: string | undefined;
  isTrusted: boolean;
  venvExists: (candidate: string) => boolean;
  platform: NodeJS.Platform;
}): string {
  if (opts.configured && opts.configured !== "python") {
    return opts.configured; // user set it explicitly — respect it
  }
  // Default: auto-detect a workspace .venv so the CLI resolves with no config — but never trust a
  // workspace-supplied interpreter in an untrusted workspace.
  if (opts.workspace && opts.isTrusted) {
    const candidate =
      opts.platform === "win32"
        ? path.join(opts.workspace, ".venv", "Scripts", "python.exe")
        : path.join(opts.workspace, ".venv", "bin", "python");
    if (opts.venvExists(candidate)) {
      return candidate;
    }
  }
  return "python";
}

export function pythonPath(): string {
  return resolvePythonPath({
    configured: config().get<string>("pythonPath", "python"),
    workspace: workspaceDir(),
    isTrusted: vscode.workspace.isTrusted,
    venvExists: (candidate) => fs.existsSync(candidate),
    platform: process.platform,
  });
}

/**
 * True when the window is NOT trusted: in that state the CLI must not exec a (possibly repo-supplied)
 * interpreter. run()/runJson() short-circuit on this rather than launching anything, so neither
 * activation nor save-triggered refreshes can run a workspace binary (SEC-004).
 *
 * Trust alone decides it, with or without a workspace folder (BACKLOG #5408). A Restricted Mode
 * window with no folder open (an empty window under `security.workspace.trust.emptyWindow: false`)
 * is untrusted too, and gating only when a folder existed let the extension spawn Python there.
 */
export function isExecGated(): boolean {
  return !vscode.workspace.isTrusted;
}

/** The dropped values already named to the user, keyed by setting, scope and value, so each is
 *  named once a session rather than on every CLI call, and a new dropped value is named again. */
const droppedPathSettings = new Set<string>();

/** The workspace-relative path settings {@link containedPathSetting} contains. */
export type { PathSettingKey };

/**
 * A workspace-relative path setting, contained to the workspace folder by
 * {@link containedPathSetting} (BACKLOG #5404): a workspace value that leaves the folder, or a user
 * value that is not text, is dropped for the next scope down, and the user is told once per value.
 */
function pathSetting(key: PathSettingKey, fallback: string, warn = true): ContainedPathSetting {
  const seen = config().inspect(key);
  const contained = containedPathSetting(seen, workspaceDir(), fallback);
  if (contained.dropped === false || !warn) {
    return contained;
  }
  const raw = contained.dropped === "workspace" ? seen?.workspaceValue : seen?.globalValue;
  const seenKey = `${key}\u0000${contained.dropped}\u0000${JSON.stringify(raw) ?? ""}`;
  if (!droppedPathSettings.has(seenKey)) {
    droppedPathSettings.add(seenKey);
    // The value is not quoted back (docs/REVIEW-STANDARDS.md R12); the operator can read the setting.
    void vscode.window.showWarningMessage(droppedNotice(key, contained.dropped));
  }
  return contained;
}

/** Each path setting's fallback when the manifest gives no default. */
const PATH_FALLBACK: Readonly<Record<PathSettingKey, string>> = {
  configDir: "samples/config",
  serviceConfig: "messagefoundry.toml",
  messageSetsDir: "samples/messages",
};

/** A path setting read for a writer's own check, without the reader's once-per-value warning, so
 *  the writer's refusal is the notice its command shows. A reader elsewhere may still have warned
 *  about the same value earlier in the session; that warning names the same cause. */
export function writerCheckSetting(key: PathSettingKey): ContainedPathSetting {
  return pathSetting(key, PATH_FALLBACK[key], false);
}

/**
 * {@link writerPathSetting}'s reading with its scope, or undefined after the refusal is shown. The
 * link check ({@link escapesByLink}, BACKLOG #5404 item 1) runs only in a trusted window, so an
 * untrusted one touches no file before its own trust refusal: there the writer's CLI call is refused
 * by the exec gate ({@link isExecGated}), and the writers that write without the CLI refuse an
 * untrusted window themselves.
 */
function writerSetting(key: PathSettingKey): ContainedPathSetting | undefined {
  const s = writerCheckSetting(key);
  if (s.dropped !== false) {
    void vscode.window.showErrorMessage(writerRefusal(key, s.dropped));
    return undefined;
  }
  if (!isExecGated() && escapesByLink(workspaceDir(), s.value)) {
    void vscode.window.showErrorMessage(linkEscapeRefusal(key));
    return undefined;
  }
  return s;
}

/**
 * The value of a path setting for a command that WRITES or LAUNCHES under it (BACKLOG #5404), or
 * undefined after an error naming the setting when a value the operator wrote was dropped. A reader
 * uses {@link configDir}, {@link serviceConfig} or {@link messageSetsDir}, which go on with the
 * value used in the dropped one's place; a writer must not act on that substitute. See
 * {@link writerRefusal}.
 */
export function writerPathSetting(key: PathSettingKey): string | undefined {
  return writerSetting(key)?.value;
}

/**
 * The `--config` directory and the `--service-config` value (see `connectionServiceConfig`) that
 * every connections.toml writer passes and Start and Restart launch serve with, both read through
 * {@link writerPathSetting}, or undefined after its refusal is shown.
 */
export function writerConfigTarget(): { configDir: string; serviceConfig: string | undefined } | undefined {
  const dir = writerPathSetting("configDir");
  if (dir === undefined) {
    return undefined;
  }
  const file = writerSetting("serviceConfig");
  if (file === undefined) {
    return undefined;
  }
  // Nothing was dropped, so the setting is set exactly when it did not come from the default.
  const flag = connectionServiceConfig(file.value, file.source !== "default");
  // A set but blank value drops the flag, so the CLI falls back to `./messagefoundry.toml` in the
  // workspace folder, at least serve does, a file the check of the blank value (the folder itself)
  // did not read (BACKLOG #5404 item 1). The default value was checked as that file already.
  if (
    flag === undefined &&
    file.source !== "default" &&
    !isExecGated() &&
    escapesByLink(workspaceDir(), PATH_FALLBACK.serviceConfig)
  ) {
    void vscode.window.showErrorMessage(linkEscapeRefusal("serviceConfig"));
    return undefined;
  }
  return { configDir: dir, serviceConfig: flag };
}

export function configDir(): string {
  return configDirSetting().value;
}

/** {@link configDir} with its scope and which value, if any, was dropped. */
export function configDirSetting(): ContainedPathSetting {
  return pathSetting("configDir", PATH_FALLBACK.configDir);
}

/** Service-settings TOML the engine loads (`[alerts].rules` live here — ADR 0014). Workspace-relative,
 *  and a workspace value is contained to the folder (BACKLOG #5404); the `alert` CLI creates it on
 *  first `add` if absent. */
export function serviceConfig(): string {
  return serviceConfigSetting().value;
}

/** {@link serviceConfig} with the scope it came from, for a caller whose checks depend on whether
 *  the workspace set the value it is handed (securityEditor.ts). */
export function serviceConfigSetting(): ContainedPathSetting {
  return pathSetting("serviceConfig", PATH_FALLBACK.serviceConfig);
}

/** Whether `messagefoundry.serviceConfig` is set rather than left at the manifest default; see
 *  `connectionServiceConfig` in connectionWizardModel.ts (BACKLOG #2908). For the readers only, at
 *  least the status bar's control context: writers and the offline ai-policy refuse a dropped value
 *  (writerConfigTarget, aiPolicy.ts). A value the containment dropped still counts (BACKLOG #5404),
 *  so the file a reader judges in its place is the one named explicitly. */
export function serviceConfigIsSet(): boolean {
  const s = serviceConfigSetting();
  return s.source !== "default" || s.dropped !== false;
}

/**
 * The engine API URL. **https by default** since ADR 0172 made the engine always serve TLS, minting
 * a self-signed pair when no operator chain is configured (BACKLOG #1695) — the previous `http://`
 * default reached a TLS socket in cleartext and failed with `ECONNRESET`.
 *
 * THE FALLBACK HERE AND `messagefoundry.engineUrl`'s `default` IN package.json MUST AGREE. Nothing
 * in VS Code reconciles them: the manifest default is what `get` returns to a user who never touched
 * the setting, and this literal is what it returns if the key is ever absent from the manifest. They
 * are pinned equal by `settings-scope.test.ts` because changing one and not the other is silent.
 */
export function engineUrl(): string {
  return config().get<string>("engineUrl", "https://127.0.0.1:8765");
}

/** Whether the operator configured the engine target: `messagefoundry.engineUrl` set rather than
 *  left at its default, or any named `environments` (BACKLOG #5564; see pickOfflinePolicy). */
export function engineTargetIsSet(): boolean {
  return settingIsSet(config().inspect("engineUrl")) || environments().length > 0;
}

/** One addressable engine instance within an environment (e.g. a horizontal shard / replica). */
export interface Shard {
  name: string;
  url: string;
  /** Optional full path to a PEM to trust for this instance; falls back to its environment's. See
   *  `trustPinsFor` in engineTrustModel.ts, which validates it (BACKLOG #1695). */
  caFile?: unknown;
}

export interface EnvironmentTarget {
  name: string;
  url: string;
  /**
   * Optional engine instances (shards/replicas) within this environment. When an environment defines
   * ≥2, promote asks WHICH shard to deploy to and uses that shard's url; 0 or 1 behaves exactly as a
   * shard-less environment (the single shard, or `url`, is used with no extra prompt). Additive and
   * backward-compatible: an environment that omits `shards` is unchanged.
   */
  shards?: Shard[];
  /**
   * Optional full path to a PEM (the issuing CA, or the engine's own self-signed certificate) to
   * trust for this environment's engine(s). Machine-scoped with the rest of the setting, so a
   * workspace cannot set it. `unknown` because nothing has type-checked it yet: `trustPinsFor` in
   * engineTrustModel.ts validates it and logs a refusal (BACKLOG #1695).
   */
  caFile?: unknown;
}

/** Drop malformed {name,url} entries from a raw config array (shared by environments()/shards()). */
function validTargets<T extends { name: string; url: string }>(raw: unknown): T[] {
  return Array.isArray(raw)
    ? (raw.filter((e) => e && typeof e.name === "string" && typeof e.url === "string") as T[])
    : [];
}

/**
 * Configured promote targets (DEV/PROD/…), each a {name, url[, shards]}. Empty (the default) means "no
 * named environments" — promote then falls back to the single `engineUrl`. Malformed entries are
 * dropped; each kept entry carries its validated `shards` (see shardsOf), if any.
 */
export function environments(): EnvironmentTarget[] {
  const envs = validTargets<EnvironmentTarget>(config().get("environments", []));
  return envs.map((e) => {
    const shards = shardsOf(e);
    const base: EnvironmentTarget = { name: e.name, url: e.url };
    if (e.caFile !== undefined) {
      base.caFile = e.caFile;
    }
    return shards.length > 0 ? { ...base, shards } : base;
  });
}

/**
 * The validated shards of one environment entry (malformed shard entries dropped). Pure — operates on
 * the entry, not on vscode config — so the promote resolver and its tests can use it directly.
 */
export function shardsOf(env: EnvironmentTarget): Shard[] {
  return validTargets<Shard>(env.shards);
}

export function messageSetsDir(): string {
  return messageSetsDirSetting().value;
}

/** {@link messageSetsDir} with its scope and which value, if any, was dropped. */
export function messageSetsDirSetting(): ContainedPathSetting {
  return pathSetting("messageSetsDir", PATH_FALLBACK.messageSetsDir);
}

/**
 * Max characters of active-editor code attached to a `@messagefoundry` AI chat request
 * (`messagefoundry.ai.contextCharLimit`, default 8000). Bounds how much of the user's own code
 * egresses to their chosen model provider; `0` means "graph names only, no editor code". A
 * workspace value may only LOWER the bound that the user's own value or the default sets, never
 * raise it (BACKLOG #5404 item 2); see {@link contextCharLimitOf}.
 */
export function aiContextCharLimit(): number {
  return contextCharLimitOf(config().inspect("ai.contextCharLimit"));
}

export function workspaceDir(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

/** Per-call options for {@link run} and {@link runJson}. */
export interface RunOptions {
  /**
   * Kill the child after this many milliseconds; it then resolves as a non-zero exit. Omitted, there
   * is no limit, which is every caller's behaviour before this option existed: an editor command the
   * user started and is watching can take as long as it takes. A BACKGROUND caller that nobody watches
   * and that others queue behind (engine trust's `cert inventory`) passes one, so a hung interpreter
   * cannot stall it for the life of the window.
   */
  readonly timeoutMs?: number;
  /**
   * The module to run, `messagefoundry` when omitted. The toolkit's commands pass
   * {@link TOOLKIT_MODULE}; a toolkit missing from the interpreter then resolves as a clear refusal
   * naming the distribution (`explainMissingToolkit`), not as Python's bare module error.
   */
  readonly module?: CliModule;
}

/** Run `python -m <module> <args>` and resolve with stdout/stderr/exit code (never rejects). */
export function run(args: string[], cwd?: string, opts: RunOptions = {}): Promise<CliResult> {
  if (isExecGated()) {
    // Untrusted workspace: refuse to exec any (possibly repo-supplied) interpreter (SEC-004). Return
    // a synthetic non-zero result; callers already treat a non-zero exit as the error path.
    return Promise.resolve({ stdout: "", stderr: UNTRUSTED_WORKSPACE_STDERR, code: 1 });
  }
  const module = opts.module ?? ENGINE_MODULE;
  return new Promise((resolve) => {
    execFile(
      pythonPath(),
      cliArgv(module, args),
      { cwd, maxBuffer: 64 * 1024 * 1024, timeout: opts.timeoutMs ?? 0 },
      (err, stdout, stderr) => {
        const code =
          err && typeof (err as { code?: unknown }).code === "number"
            ? ((err as { code: number }).code)
            : err
              ? 1
              : 0;
        resolve(settle(module, { stdout: stdout ?? "", stderr: stderr ?? "", code }));
      },
    );
  });
}

/** The options that run a command on the toolkit's module (ADR 0201 slice 4). */
export const TOOLKIT_RUN: RunOptions = { module: TOOLKIT_MODULE };

/** A toolkit result passes through `explainMissingToolkit`; an engine result is returned as it came. */
function settle(module: CliModule, res: CliResult): CliResult {
  return module === TOOLKIT_MODULE ? explainMissingToolkit(res) : res;
}

/**
 * Run `python -m <module> <args>` feeding `stdin` to the child, resolving with stdout/stderr/exit
 * code (never rejects). Used by the Steps view's `lens rewrite - --edit …`, which reads the live
 * editor buffer from stdin (never the on-disk file) so a rewrite operates on the current, possibly-dirty
 * document. Same exec gate as {@link run}. stdin/stdout are UTF-8, so module source round-trips exactly.
 */
export function runWithStdin(
  args: string[],
  stdin: string,
  cwd?: string,
  opts: RunOptions = {},
): Promise<CliResult> {
  if (isExecGated()) {
    return Promise.resolve({ stdout: "", stderr: UNTRUSTED_WORKSPACE_STDERR, code: 1 });
  }
  const module = opts.module ?? ENGINE_MODULE;
  return new Promise((resolve) => {
    const child = execFile(
      pythonPath(),
      cliArgv(module, args),
      { cwd, maxBuffer: 64 * 1024 * 1024, encoding: "utf8", timeout: opts.timeoutMs ?? 0 },
      (err, stdout, stderr) => {
        const code =
          err && typeof (err as { code?: unknown }).code === "number"
            ? (err as { code: number }).code
            : err
              ? 1
              : 0;
        resolve(settle(module, { stdout: stdout ?? "", stderr: stderr ?? "", code }));
      },
    );
    // Swallow a stdin write error (e.g. EPIPE if the child exited before consuming input) — the exit
    // code + stderr from the callback are the real signal; an unhandled stream 'error' would crash.
    child.stdin?.on("error", () => {});
    child.stdin?.end(stdin, "utf8");
  });
}

/**
 * Run a `--json` subcommand and parse stdout. The CLI prints valid JSON even on a non-zero exit
 * (e.g. `validate` returns 1 when there are diagnostics), so we parse stdout regardless of code.
 * A failure's message never quotes the CLI's output; see cliJson.ts for why.
 */
export async function runJson<T>(args: string[], cwd?: string, opts: RunOptions = {}): Promise<T> {
  // The module is resolved once, here, so the command that runs and the command a failure names
  // are the same one.
  const module = opts.module ?? ENGINE_MODULE;
  return parseJsonResult<T>(await run([...args, "--json"], cwd, { ...opts, module }), args, module);
}

/**
 * Run a `--json` subcommand feeding `stdin` to the child, and parse stdout (see {@link runJson}). Used by
 * the Steps view to re-project the LIVE buffer (`lens parse - --json`, source over stdin) after a
 * structural edit shifts every row coordinate — reading the dirty buffer, never the on-disk file.
 */
export async function runJsonWithStdin<T>(
  args: string[],
  stdin: string,
  cwd?: string,
  opts: RunOptions = {},
): Promise<T> {
  const module = opts.module ?? ENGINE_MODULE; // resolved once, as in runJson
  return parseJsonResult<T>(
    await runWithStdin([...args, "--json"], stdin, cwd, { ...opts, module }),
    args,
    module,
  );
}

// ---- Code-set (translation table) CLI bridge --------------------------------------------------
// Thin typed wrappers over `messagefoundry codeset <action>` (see docs/CODESETS.md / the contract).
// Each reuses runJson, so a `{"error": ...}` body throws and the {compact} JSON shapes parse as-is.
// A code set is read-only reference data in codesets/<name>.csv|.toml relative to the --config dir.

// SUMMARY (one per code set, from `codeset list`).
export interface CodeSetSummary {
  name: string;
  format: "csv" | "toml";
  key: string;
  columns: string[];
  value_columns: string[];
  shape: "scalar" | "dict";
  entries: number;
}

// DETAIL/GRID (from `codeset show`; consumed by `codeset upsert`). Rows are an array-of-arrays of
// strings, each inner row aligned to `columns` by position; row[0] is the lookup key.
export interface CodeSetDetail {
  name: string;
  format: "csv" | "toml";
  columns: string[];
  rows: string[][];
}

/** `codeset list` — every code set under codesets/ as a SUMMARY, sorted by name. */
export function codesetList(cwd?: string): Promise<CodeSetSummary[]> {
  return runJson<CodeSetSummary[]>(["codeset", "list", "--config", configDir()], cwd);
}

// ---- lens contract negotiation (ADR 0076 §A.7 / §D.7) -----------------------------------------
//
// `lens parse` emits no schema version of its own and the extension shells whatever toolkit is in the
// selected interpreter (`python -m messagefoundry_toolkit`, ADR 0201 slice 4), so the two skew directions are handled EXPLICITLY here rather than discovered at render time:
//
//  * an OLDER extension meeting a NEWER engine passes no `--contract`, so the engine defaults to the
//    shipped contract and never sends a kind that extension cannot title (it would render blank); and
//  * a NEWER extension meeting an OLDER engine passes `--contract`, which that engine rejects as an
//    unknown argument — so {@link lensParseStdin} RETRIES without it and degrades to the v1 projection
//    (no note rows, no router Steps) instead of surfacing an argument-parsing error to the user.

/**
 * `lens parse -` over the LIVE buffer at {@link LENS_CONTRACT}, falling back to the engine's default
 * contract when the installed engine predates the flag.
 *
 * The fallback is deliberately narrow: it retries ONCE, and only when the first attempt failed in a way
 * an older CLI's argument parser produces. A genuine parse refusal (a syntax error in the module) fails
 * on the retry too and propagates, so this can never mask a real error as a silent downgrade.
 */
export async function lensParseStdin(
  source: string,
  cwd?: string,
  contract: number = LENS_CONTRACT,
): Promise<LensParseResult> {
  try {
    return await runJsonWithStdin<LensParseResult>(
      ["lens", "parse", "-", "--contract", String(contract)],
      source,
      cwd,
      TOOLKIT_RUN,
    );
  } catch (err) {
    if (!isUnknownArgumentError(err)) {
      throw err;
    }
    return runJsonWithStdin<LensParseResult>(["lens", "parse", "-"], source, cwd, TOOLKIT_RUN);
  }
}

/**
 * `lens rewrite -` at {@link LENS_CONTRACT}, with the same one-shot fallback as {@link lensParseStdin}.
 *
 * The contract must match the one the rows were PROJECTED with: the engine re-locates the row through
 * the same grammar, so sending v2 coordinates to a v1 partition would miss the row (or, worse, hit a
 * different one). Returns the raw {@link CliResult} because a rewrite's success payload is module SOURCE
 * on stdout, not JSON — the caller parses it (`parseRewriteResult`).
 */
export async function lensRewriteStdin(
  spec: unknown,
  source: string,
  cwd?: string,
  contract: number = LENS_CONTRACT,
): Promise<CliResult> {
  const args = ["lens", "rewrite", "-", "--edit", JSON.stringify(spec)];
  const withContract = [...args, "--contract", String(contract)];
  const first = await runWithStdin(withContract, source, cwd, TOOLKIT_RUN);
  if (first.code !== 0 && looksLikeUnknownArgument(first.stderr + first.stdout)) {
    return runWithStdin(args, source, cwd, TOOLKIT_RUN);
  }
  return first;
}

/**
 * `lens schema` — the transform-vocabulary parameter schema (BACKLOG #1760; op -> editable params with
 * their widget kind/choices), derived by the engine from its own action + diagnostic signatures. The
 * Steps editor drives its per-param input widgets from it. Config-independent (a pure signature
 * introspection), so it takes no `--config`; the toolkit command is lazy-imported and starts no server.
 */
export function lensSchema(cwd?: string): Promise<OpSchema> {
  return runJson<OpSchema>(["lens", "schema"], cwd, TOOLKIT_RUN);
}

/** `codeset show NAME` — the DETAIL/grid for one code set (a .toml one comes back read-only). */
export function codesetShow(name: string, cwd?: string): Promise<CodeSetDetail> {
  return runJson<CodeSetDetail>(["codeset", "show", "--config", configDir(), "--name", name], cwd);
}

// The code-set writers take the config directory from their caller, which reads it with
// writerPathSetting and stops before any prompt when that refuses (BACKLOG #5404). The editors
// build their own `codeset upsert`, which takes an optional `--name`.

/** `codeset rename NAME --to NEWNAME` — rename the file (keeps its extension). */
export function codesetRename(dir: string, name: string, to: string, cwd?: string): Promise<unknown> {
  return runJson(["codeset", "rename", "--config", dir, "--name", name, "--to", to], cwd);
}

/** `codeset remove NAME` — delete codesets/NAME.csv|.toml. */
export function codesetRemove(dir: string, name: string, cwd?: string): Promise<unknown> {
  return runJson(["codeset", "remove", "--config", dir, "--name", name], cwd);
}
