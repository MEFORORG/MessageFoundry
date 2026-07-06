// Thin bridge to the `messagefoundry` Python CLI: shell out to a subcommand and parse its JSON.
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";

export interface CliResult {
  stdout: string;
  stderr: string;
  code: number;
}

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
 * True when there IS a workspace and it is NOT trusted: in that state the CLI must not exec a
 * (possibly repo-supplied) interpreter. run()/runJson() short-circuit on this rather than launching
 * anything, so neither activation nor save-triggered refreshes can run a workspace binary (SEC-004).
 */
export function isExecGated(): boolean {
  return Boolean(workspaceDir()) && !vscode.workspace.isTrusted;
}

export function configDir(): string {
  return config().get<string>("configDir", "samples/config");
}

/** Service-settings TOML the engine loads (`[alerts].rules` live here — ADR 0014). Workspace-relative;
 *  the `alert` CLI creates it on first `add` if absent. */
export function serviceConfig(): string {
  return config().get<string>("serviceConfig", "messagefoundry.toml");
}

export function engineUrl(): string {
  return config().get<string>("engineUrl", "http://127.0.0.1:8765");
}

/** One addressable engine instance within an environment (e.g. a horizontal shard / replica). */
export interface Shard {
  name: string;
  url: string;
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
    return shards.length > 0 ? { ...e, shards } : { name: e.name, url: e.url };
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
  return config().get<string>("messageSetsDir", "samples/messages");
}

/**
 * Max characters of active-editor code attached to a `@messagefoundry` AI chat request
 * (`messagefoundry.ai.contextCharLimit`, default 8000). Bounds how much of the user's own code
 * egresses to their chosen model provider. A non-numeric/negative value (which the settings schema
 * already discourages) falls back to the default; `0` means "graph names only, no editor code".
 */
export function aiContextCharLimit(): number {
  const v = config().get<number>("ai.contextCharLimit", 8000);
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 8000;
}

export function workspaceDir(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

/** Run `python -m messagefoundry <args>` and resolve with stdout/stderr/exit code (never rejects). */
export function run(args: string[], cwd?: string): Promise<CliResult> {
  if (isExecGated()) {
    // Untrusted workspace: refuse to exec any (possibly repo-supplied) interpreter (SEC-004). Return
    // a synthetic non-zero result; callers already treat a non-zero exit as the error path.
    return Promise.resolve({
      stdout: "",
      stderr: "workspace not trusted — MessageFoundry CLI disabled until you trust this workspace",
      code: 1,
    });
  }
  return new Promise((resolve) => {
    execFile(
      pythonPath(),
      ["-m", "messagefoundry", ...args],
      { cwd, maxBuffer: 64 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const code =
          err && typeof (err as { code?: unknown }).code === "number"
            ? ((err as { code: number }).code)
            : err
              ? 1
              : 0;
        resolve({ stdout: stdout ?? "", stderr: stderr ?? "", code });
      },
    );
  });
}

/**
 * Run a `--json` subcommand and parse stdout. The CLI prints valid JSON even on a non-zero exit
 * (e.g. `validate` returns 1 when there are diagnostics), so we parse stdout regardless of code.
 */
export async function runJson<T>(args: string[], cwd?: string): Promise<T> {
  const res = await run([...args, "--json"], cwd);
  const text = res.stdout.trim();
  if (!text) {
    throw new Error(res.stderr.trim() || `messagefoundry ${args.join(" ")} produced no output`);
  }
  const parsed: unknown = JSON.parse(text);
  // The CLI prints {"error": "..."} (e.g. on a WiringError) instead of the expected array/object;
  // surface it as a thrown Error so every caller's try/catch shows the real message.
  if (
    parsed !== null &&
    typeof parsed === "object" &&
    !Array.isArray(parsed) &&
    typeof (parsed as { error?: unknown }).error === "string"
  ) {
    throw new Error((parsed as { error: string }).error);
  }
  return parsed as T;
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

/** `codeset show NAME` — the DETAIL/grid for one code set (a .toml one comes back read-only). */
export function codesetShow(name: string, cwd?: string): Promise<CodeSetDetail> {
  return runJson<CodeSetDetail>(["codeset", "show", "--config", configDir(), "--name", name], cwd);
}

/** `codeset upsert` — write codesets/NAME.csv from a DETAIL (the CLI validates + re-loads it). */
export function codesetUpsert(detail: CodeSetDetail, cwd?: string): Promise<unknown> {
  return runJson(["codeset", "upsert", "--config", configDir(), "--data", JSON.stringify(detail)], cwd);
}

/** `codeset rename NAME --to NEWNAME` — rename the file (keeps its extension). */
export function codesetRename(name: string, to: string, cwd?: string): Promise<unknown> {
  return runJson(["codeset", "rename", "--config", configDir(), "--name", name, "--to", to], cwd);
}

/** `codeset remove NAME` — delete codesets/NAME.csv|.toml. */
export function codesetRemove(name: string, cwd?: string): Promise<unknown> {
  return runJson(["codeset", "remove", "--config", configDir(), "--name", name], cwd);
}
