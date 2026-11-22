// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Pure (vscode-free) helpers behind the customEditor providers (#221b): deriving a code-set's name
// from its file path, deciding whether it opens read-only in the grid, and the small guard that stops
// the webview↔document update loop. Separated from configEditors.ts so this mapping is unit-testable
// node-side (no Extension Host). No vscode, no I/O.
import * as path from "node:path";

/**
 * The bare code-set name for a file path — its basename without the .csv/.toml extension. A code set
 * is one file (codesets/<name>.csv|.toml), so this is the identity `codeset show/upsert --name` uses.
 * Accepts both `/` and `\\` separators so it is platform-agnostic (Windows paths included).
 */
export function codeSetNameFromPath(fsPath: string): string {
  const base = fsPath.split(/[\\/]/).pop() ?? fsPath;
  return base.replace(/\.(csv|toml)$/i, "");
}

/** True when a code-set file opens read-only in the grid: a `.toml` code set is hand-authored/legacy
 *  and the grid only ever writes CSV, so it is view-only (edit the TOML by hand). */
export function isReadOnlyCodeSet(fsPath: string): boolean {
  return /\.toml$/i.test(fsPath);
}

/**
 * The webview↔document loop guard. The provider writes the file by shelling the CLI; that on-disk
 * write makes VS Code fire onDidChangeTextDocument for the SAME document, which would otherwise re-push
 * content into the webview and clobber it. `shouldPushDocumentChange` returns false for the change the
 * provider itself just caused (tracked by a per-document "saving" flag) and true for a genuine external
 * edit — so an external change still refreshes the form, but our own save does not echo back.
 *
 * The "saving" flag is reset by the provider on a fail-safe timer after each write settles — NOT only
 * when this guard swallows an echo. A byte-identical CLI write fires no onDidChangeTextDocument at all,
 * so relying on the echo-swallow path alone would leave the flag latched and silently swallow the NEXT
 * genuine external edit; the timer guarantees it drops regardless (see configEditors.ts).
 */
export function shouldPushDocumentChange(opts: {
  savingFromWebview: boolean;
  changedText: string;
  lastRenderedText: string | undefined;
}): boolean {
  if (opts.savingFromWebview) {
    return false; // our own CLI write — swallow exactly one echo
  }
  return opts.changedText !== opts.lastRenderedText; // external edit → refresh only if content differs
}

/**
 * Whether the opened `documentFsPath` lives under the extension's configured config dir. The custom
 * editors read/write via the CLI's `--config <configDir>`, so they only faithfully represent a file
 * that is actually the config-dir's own connections.toml or a codesets CSV. A same-named file elsewhere
 * in the workspace (the selector globs match by filename across the whole workspace) would otherwise be
 * shown — and saved — as the config-dir file. When this returns false the provider falls back to the
 * plain text editor instead of silently editing a different file.
 *
 * `configDir` may be workspace-relative (the default `samples/config`, or `./samples/config`, `.`) or
 * absolute, a root such as `/` included; relative is resolved against `workspaceDir`, and dot segments
 * on both sides are resolved before comparing. Case is folded only on `win32` and `darwin`, whose
 * default filesystems are case-insensitive; elsewhere a wrong-cased path names a different file, so
 * it is outside the config dir (BACKLOG #5832). A case-sensitive volume on `darwin` is the accepted
 * miss. `platform` defaults to the host's; it is a parameter so tests pin each rule on any runner.
 */
export function isUnderConfigDir(
  documentFsPath: string,
  workspaceDir: string,
  configDir: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const p = platform === "win32" ? path.win32 : path.posix;
  const caseInsensitive = platform === "win32" || platform === "darwin";
  const fold = (s: string): string => (caseInsensitive ? s.toLowerCase() : s);
  const base = fold(p.resolve(workspaceDir, configDir));
  const file = fold(p.resolve(documentFsPath));
  // `relative` is "" for the dir itself, absolute across Windows drives, and starts with a `..`
  // SEGMENT when outside -- not merely those characters, so a child dir named "..x" is still inside.
  const rel = p.relative(base, file);
  return !p.isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${p.sep}`);
}

/** A connection summary the connections customEditor lists (name/direction/transport) — the fields it
 *  needs from `connection list` to render its picker. */
export interface ConnectionListItem {
  name: string;
  direction: string;
  transport: string;
}

/** Choose which connection the connections customEditor shows first: the requested name if it still
 *  exists, else the first connection, else undefined (an empty file → the blank "new" form). */
export function pickCurrentConnection(
  entries: ConnectionListItem[],
  requested: string | undefined,
): string | undefined {
  if (requested && entries.some((e) => e.name === requested)) {
    return requested;
  }
  return entries[0]?.name;
}
