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
 * The `codeset upsert` argv for a save from the code-set custom editor, or the error to show instead.
 * The editor IS the opened file, so every save is an edit of that file's stem: it passes `--name
 * <stem>`, which the CLI reads as edit intent (`create = --name is None`, #240). Without it the CLI
 * took each save as a create and refused it as a collision with the file being edited (BACKLOG
 * #5834). Refused here, before any write: a read-only code set; a file whose content never loaded
 * into the grid (`codeset show` failed on a non-empty file, so the grid is the empty fallback, and an
 * edit would replace rows nobody saw); and a posted name other than the stem, which would write some
 * other file than the one the tab shows. The caller must also hold that the tab IS
 * `<configDir>/codesets/<stem>.csv` ({@link isConfigDirCodeSetFile}), since the CLI writes that path.
 */
export function codeSetEditorUpsertArgs(
  configDir: string,
  stem: string,
  state: { readonly: boolean; unloaded: boolean },
  detail: { name: string },
): { args: string[] } | { error: string } {
  if (state.readonly) {
    return { error: `code set ${stem} is read-only here (a .toml code set); edit the TOML as text.` };
  }
  if (state.unloaded) {
    return {
      error:
        `code set ${stem} did not load into the grid, so saving would replace its rows with the empty ` +
        "grid (nothing was written). Fix the file as text, then reopen it here.",
    };
  }
  if (detail.name !== stem) {
    return {
      error:
        `this tab edits code set ${stem}, but the grid posted the name ${JSON.stringify(detail.name)} ` +
        "(nothing was written). Rename a code set from the Translation Tables tree.",
    };
  }
  return { args: ["codeset", "upsert", "--config", configDir, "--data", JSON.stringify(detail), "--name", stem] };
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
 * The path of `documentFsPath` inside the configured config dir, as segments, or undefined when it is
 * outside. `configDir` may be workspace-relative (the default `samples/config`, or `./samples/config`,
 * `.`) or absolute, a root such as `/` included; relative is resolved against `workspaceDir`, and dot
 * segments on both sides are resolved before comparing. Case is folded, so the segments come back
 * lower-cased, only on `win32` and `darwin`, whose default filesystems are case-insensitive; elsewhere
 * a wrong-cased path names a different file, so it is outside (BACKLOG #5832). Only ASCII A-Z is
 * folded: toLowerCase() maps at least U+212A KELVIN SIGN onto "k", a name NTFS keeps apart from "k",
 * so a different directory would pass; a non-ASCII case difference reads as outside instead, which
 * falls back to the text editor. Folding misses at least a case-sensitive volume or directory on
 * those two platforms. `platform` defaults to the host's; it is a parameter so tests pin each rule on
 * any runner.
 */
function configDirSegments(
  documentFsPath: string,
  workspaceDir: string,
  configDir: string,
  platform: NodeJS.Platform,
): string[] | undefined {
  const p = platform === "win32" ? path.win32 : path.posix;
  const caseInsensitive = platform === "win32" || platform === "darwin";
  const fold = (s: string): string => (caseInsensitive ? s.replace(/[A-Z]+/g, (m) => m.toLowerCase()) : s);
  // Compared segment by segment, not with path.relative: win32.relative lower-cases both sides with
  // toLowerCase() itself, which would undo the ASCII-only fold.
  // Spelled out per platform, not as p.resolve, so the path-join census (tests/
  // test_file_path_join_census.py) still counts these two resolves.
  const dir = fold(
    platform === "win32"
      ? path.win32.resolve(workspaceDir, configDir)
      : path.posix.resolve(workspaceDir, configDir),
  );
  const doc = fold(
    platform === "win32" ? path.win32.resolve(documentFsPath) : path.posix.resolve(documentFsPath),
  );
  const root = p.parse(dir).root;
  if (p.parse(doc).root !== root) {
    return undefined; // another drive or share
  }
  const segments = (s: string): string[] =>
    s
      .slice(root.length)
      .split(p.sep)
      .filter((seg) => seg !== "");
  const dirSegs = segments(dir);
  const docSegs = segments(doc);
  if (docSegs.length < dirSegs.length || dirSegs.some((seg, i) => seg !== docSegs[i])) {
    return undefined;
  }
  return docSegs.slice(dirSegs.length);
}

/**
 * Whether `documentFsPath` IS the config dir's own `connections.toml` ({@link configDirSegments} says
 * how the two paths are resolved and compared). The custom editors read and
 * write via the CLI's `--config <configDir>`, so they faithfully represent only the exact file the CLI
 * edits. The selector globs match by file name across the whole workspace, so a same-named file
 * elsewhere, or nested deeper under the config dir, would otherwise be shown and saved as the config
 * dir's file. When this returns false the provider falls back to the plain text editor.
 */
export function isConfigDirConnectionsFile(
  documentFsPath: string,
  workspaceDir: string,
  configDir: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const segs = configDirSegments(documentFsPath, workspaceDir, configDir, platform);
  return segs?.length === 1 && segs[0] === "connections.toml";
}

/** Whether `documentFsPath` IS a code-set file the CLI edits, `<configDir>/codesets/<stem>.csv|.toml`
 *  ({@link isConfigDirConnectionsFile} says why the exact path matters). */
export function isConfigDirCodeSetFile(
  documentFsPath: string,
  workspaceDir: string,
  configDir: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const segs = configDirSegments(documentFsPath, workspaceDir, configDir, platform);
  // No /i: the segments are already folded where the filesystem folds, and elsewhere the CLI looks up
  // only the lower-case extensions. A file name holding a `\` is refused: on posix it is one segment,
  // but codeSetNameFromPath splits on `\` too, so `a\b.csv` would be edited and saved as code set `b`
  // (BACKLOG #5834).
  return segs?.length === 2 && segs[0] === "codesets" && !segs[1].includes("\\") && /\.(csv|toml)$/.test(segs[1]);
}

/**
 * Whether a document IS the config-dir file the CLI edits: an on-disk `file:` document whose path
 * `isConfigDirFile` accepts. The path alone is not enough. A `git:` revision tab, among others, carries
 * the working copy's fsPath. The forms render from the CLI's read of the working copy, not from the
 * document, so that tab would show working-copy data under a revision's label, and a save or remove
 * from it would write the working copy; for a file since deleted from disk, the blank form's save
 * would create it (BACKLOG #5834).
 */
export function isConfigDirDocument(
  uri: { readonly scheme: string; readonly fsPath: string },
  workspaceDir: string,
  configDir: string,
  isConfigDirFile: (fsPath: string, ws: string, dir: string) => boolean,
): boolean {
  return uri.scheme === "file" && isConfigDirFile(uri.fsPath, workspaceDir, configDir);
}

/**
 * The static page a config custom editor shows instead of its form: a one-line `notice`, and, for a
 * document that is not a `file:` document ({@link isConfigDirDocument}), that document's own `text`,
 * so a diff side shows what that revision holds. Both are escaped, and its CSP allows no script.
 */
export function configNoticeHtml(notice: string, text?: string): string {
  const esc = (s: string): string =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const body = text === undefined ? "" : `<pre style='white-space:pre-wrap'>${esc(text)}</pre>`;
  return (
    `<!DOCTYPE html><html><head><meta charset="utf-8">` +
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">` +
    `</head><body style='font-family:sans-serif;padding:1rem'><p>${esc(notice)}</p>${body}</body></html>`
  );
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
