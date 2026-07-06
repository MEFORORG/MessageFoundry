// Thin bridge to the user's git binary — the git analog of cli.ts. Discovers the executable via the
// built-in Git extension (which honors the user's `git.path` and the bundled Git for Windows), and
// runs commands with a runner that never rejects (resolves with stdout/stderr/exit code).
import { execFile } from "node:child_process";
import * as vscode from "vscode";

export interface GitResult {
  stdout: string;
  stderr: string;
  code: number;
}

// Minimal shape of the built-in Git extension's API we rely on (just the resolved binary path).
interface BuiltinGitApi {
  git: { path: string };
}
interface BuiltinGitExports {
  getAPI(version: 1): BuiltinGitApi;
}

function exec(bin: string, args: string[], cwd?: string): Promise<GitResult> {
  return new Promise((resolve) => {
    execFile(bin, args, { cwd, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      const code =
        err && typeof (err as { code?: unknown }).code === "number"
          ? (err as { code: number }).code
          : err
            ? 1
            : 0;
      resolve({ stdout: stdout ?? "", stderr: stderr ?? "", code });
    });
  });
}

/**
 * Resolve the git executable: prefer the built-in Git extension's path (honors `git.path` and the
 * bundled Git for Windows), else fall back to `git` on PATH. Returns null if nothing runs.
 */
export async function findGit(): Promise<string | null> {
  try {
    const ext = vscode.extensions.getExtension<BuiltinGitExports>("vscode.git");
    if (ext) {
      const exports = ext.isActive ? ext.exports : await ext.activate();
      const apiPath = exports.getAPI(1).git.path;
      if (apiPath && (await exec(apiPath, ["--version"])).code === 0) {
        return apiPath;
      }
    }
  } catch {
    // fall through to PATH
  }
  return (await exec("git", ["--version"])).code === 0 ? "git" : null;
}

/** Run `git <args>` in `cwd` with the resolved binary; never rejects. */
export function git(bin: string, args: string[], cwd: string): Promise<GitResult> {
  return exec(bin, args, cwd);
}

/** Whether `cwd` is inside a git work tree. */
export async function isRepo(bin: string, cwd: string): Promise<boolean> {
  const res = await git(bin, ["rev-parse", "--is-inside-work-tree"], cwd);
  return res.code === 0 && res.stdout.trim() === "true";
}

/** The configured `core.hooksPath` (empty string if unset). */
export async function getHooksPath(bin: string, cwd: string): Promise<string> {
  const res = await git(bin, ["config", "--get", "core.hooksPath"], cwd);
  return res.code === 0 ? res.stdout.trim() : "";
}

/** The URL of a named remote (empty string if that remote doesn't exist). No network — reads config. */
export async function getRemoteUrl(bin: string, cwd: string, remote = "origin"): Promise<string> {
  const res = await git(bin, ["remote", "get-url", remote], cwd);
  return res.code === 0 ? res.stdout.trim() : "";
}
