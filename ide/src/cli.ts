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

export function pythonPath(): string {
  const configured = config().get<string>("pythonPath", "python");
  if (configured && configured !== "python") {
    return configured; // user set it explicitly — respect it
  }
  // Default: auto-detect a workspace .venv so the CLI resolves with no config.
  const ws = workspaceDir();
  if (ws) {
    const candidate =
      process.platform === "win32"
        ? path.join(ws, ".venv", "Scripts", "python.exe")
        : path.join(ws, ".venv", "bin", "python");
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return "python";
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

export interface EnvironmentTarget {
  name: string;
  url: string;
}

/**
 * Configured promote targets (DEV/PROD/…), each a {name, url}. Empty (the default) means "no named
 * environments" — promote then falls back to the single `engineUrl`. Malformed entries are dropped.
 */
export function environments(): EnvironmentTarget[] {
  const raw = config().get<EnvironmentTarget[]>("environments", []);
  return Array.isArray(raw)
    ? raw.filter((e) => e && typeof e.name === "string" && typeof e.url === "string")
    : [];
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
