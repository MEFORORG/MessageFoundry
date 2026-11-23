// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Resolve a workspace-relative setting to a directory that is provably inside the workspace folder.
//
// `messagefoundry.configDir` and its siblings are window-scoped, so a checked-in
// `.vscode/settings.json` can set them. A command that WRITES under such a setting must not follow it
// out of the folder (BACKLOG #5410): an absolute path, a `..` climb, or a symlink or junction inside
// the folder that points elsewhere, dangling ones included. The check compares real paths, so the
// link cases are caught too. It is vscode-free so the node-side unit suite can drive it.
import * as fs from "node:fs";
import * as path from "node:path";
// ASCII-only case fold on Windows: path.relative folded with toLowerCase(), so a sibling named with
// U+212A KELVIN SIGN for "k" read as the workspace (BACKLOG #5832).
import { isPathWithin as isWithin } from "./pathFold";

function realpath(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch (e) {
    // The native call fails with EISDIR on some Windows volumes (RAM disks, some virtual drives),
    // where the JS implementation still answers; an ENOENT is the caller's to handle.
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw e;
    }
    return fs.realpathSync(p);
  }
}

/**
 * `p`'s real path: the real path of its nearest existing ancestor, with the missing components
 * appended. `undefined` when that cannot be read, or when a "missing" component is really a dangling
 * link, which a later write could follow out of the folder.
 */
function realpathOfNearestExisting(p: string): string | undefined {
  const tail: string[] = [];
  let cur = p;
  for (;;) {
    try {
      return path.join(realpath(cur), ...tail);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
        return undefined;
      }
    }
    try {
      fs.lstatSync(cur);
      return undefined; // the entry exists but its target does not: a dangling link
    } catch {
      // truly absent: keep walking up
    }
    const parent = path.dirname(cur);
    if (parent === cur) {
      return undefined;
    }
    tail.unshift(path.basename(cur));
    cur = parent;
  }
}

/**
 * `dir` (relative to `ws`, or absolute) resolved against `ws`, when both its spelling and its real
 * path are the workspace folder or inside it, else `undefined`. The path returned keeps the workspace's own
 * spelling (a junction, a mapped drive), so editors keyed on the workspace path still match it.
 */
export function resolveInsideWorkspace(ws: string, dir: string): string | undefined {
  const logical = path.resolve(ws, dir);
  // Spelling first, with no I/O: a path that is outside by its spelling (absolute elsewhere, a UNC
  // share, a `..` climb) is refused before the filesystem is touched, so a crafted setting cannot
  // make the extension host open a remote share.
  if (!isWithin(path.resolve(ws), logical)) {
    return undefined;
  }
  const root = realpathOfNearestExisting(path.resolve(ws));
  const target = realpathOfNearestExisting(logical);
  if (root === undefined || target === undefined) {
    return undefined;
  }
  return isWithin(root, target) ? logical : undefined;
}

/**
 * `value` as a workspace-relative path with forward slashes, for a file committed to the repository
 * such as the pre-commit hook, or undefined when its spelling does not lie inside `ws`. A user-scope
 * absolute path is the operator's own and names a file on this machine only, so a hook committed
 * with it would point every other clone at that machine's layout. Spelling only, with no I/O.
 */
export function committedRelativePath(ws: string, value: string): string | undefined {
  const root = path.resolve(ws);
  const target = path.resolve(root, value);
  if (!isWithin(root, target)) {
    return undefined;
  }
  const rel = path.relative(root, target);
  return rel === "" ? "." : rel.split(path.sep).join("/");
}

/** `name` without its trailing spaces, in linear time. A `/ +$/` replace backtracks quadratically on
 *  a long run of spaces followed by another character, and a path setting is workspace-supplied. */
function dropTrailingSpaces(name: string): string {
  let end = name.length;
  while (end > 0 && name.charCodeAt(end - 1) === 0x20) {
    end--;
  }
  return name.slice(0, end);
}

/** Whether, on Windows (`win32`), any folder or file name in `rel` meets `bad`. Either separator
 *  splits `rel`, since Windows takes both. Spelling only, with no I/O. */
function someWin32Name(rel: string, win32: boolean, bad: (name: string) => boolean): boolean {
  return win32 && rel.split(/[\\/]/).some(bad);
}

/**
 * Whether `rel`, a path relative to a folder with its `..` components already collapsed, has a folder
 * or file name ending in a dot or a space, when `win32` (by default, on Windows). A `.` component,
 * the folder itself, is not such a name. Node reads the name as written and, finding no such entry,
 * reports a missing path, while the CLI's open goes through Windows path normalization, which can
 * drop the ending: it opens `cfg` for `cfg.`. A check Node makes on the name then says nothing of
 * what the CLI opens, a link out of the folder included. Either separator splits `rel`, since Windows
 * takes both. Spelling only, with no I/O. Shared by {@link escapesByLink} and securityConfigTarget.
 *
 * A name holding a colon is refused by {@link hasColonInName}, and a reserved device name by
 * {@link hasReservedDeviceName}.
 */
export function hasTrailingDotOrSpaceName(rel: string, win32: boolean = path.sep === "\\"): boolean {
  return someWin32Name(rel, win32, (part) => part !== "." && (part.endsWith(".") || part.endsWith(" ")));
}

/**
 * Whether `rel`, a path relative to a folder, has a folder or file name holding a colon, when `win32`
 * (by default, on Windows). Both callers pass the part below the workspace folder, so the drive is
 * not in it. Pass no absolute path: its drive colon would count, and a leading `x:` in `rel` is a
 * one-letter name, not a drive, so it is not skipped. A Win32 open reads
 * `name:stream` as an NTFS alternate data stream on the entry `name`. With `cfg` a junction out of
 * the folder, Python's open of `cfg:x` wrote a stream on the folder outside (measured in review, 2026-11-19),
 * while Node's real-path read finds no such entry and the real-path check passes the name. Behind a
 * file symbolic link Node can resolve the stream, so the real-path check may refuse that case
 * itself; this refuses either before any read. Either separator splits `rel`. Spelling only, with no
 * I/O. Shared by {@link escapesByLink} and securityConfigTarget (BACKLOG #5404 item 1).
 */
export function hasColonInName(rel: string, win32: boolean = path.sep === "\\"): boolean {
  return someWin32Name(rel, win32, (part) => part.includes(":"));
}

/** The DOS device names Windows reserves: CPython's `ntpath.isreserved` list, where the superscript
 *  digits one to three are device digits too, and COM0 and LPT0, which Microsoft's file-naming
 *  guidance also lists. Upper case. */
const RESERVED_DEVICE_NAMES: ReadonlySet<string> = new Set([
  "CON",
  "PRN",
  "AUX",
  "NUL",
  "CONIN$",
  "CONOUT$",
  ...["COM", "LPT"].flatMap((p) => [..."0123456789\u00b9\u00b2\u00b3"].map((d) => p + d)),
]);

/**
 * Whether `rel`, a path relative to a folder, has a folder or file name that is a reserved DOS
 * device name ({@link RESERVED_DEVICE_NAMES}, in any case), when `win32` (by default, on Windows).
 * The name is read as CPython's `ntpath.isreserved` reads it: the part before its first dot, with trailing
 * spaces dropped, so `nul.txt`, `con .toml` and `Com1.x` count too. A Win32 open of a bare device
 * name opens the device, not a file in the folder: Python 3.14.7 on Windows 11 resolves `nul` to
 * `\\.\nul` (measured 2026-11-20). There a stem with an extension is a plain file, but Windows 10
 * and earlier map it to the device as well, so it is refused on every Windows version. That is
 * how `ntpath.isreserved` reads a device name; this check covers device names only, not the
 * reserved characters `isreserved` also refuses, and its list adds COM0 and LPT0. A device
 * opened in a file's place is a read or write the real-path check cannot see: Node finds no entry
 * by that name and reports a missing path. Either separator splits `rel`. Spelling only, with no
 * I/O. Shared by {@link escapesByLink} and securityConfigTarget (BACKLOG #5404 item 3).
 */
export function hasReservedDeviceName(rel: string, win32: boolean = path.sep === "\\"): boolean {
  return someWin32Name(rel, win32, (part) =>
    RESERVED_DEVICE_NAMES.has(dropTrailingSpaces(part.split(".")[0]).toUpperCase()),
  );
}

/** The workspace-relative path settings a writer checks. */
export type PathSettingKey = "configDir" | "serviceConfig" | "messageSetsDir";

/**
 * Whether a writer must refuse `value`, a path setting's value, because though its spelling lies
 * inside the workspace folder `ws`, the file the CLI or the writer would open may not (BACKLOG #5404
 * item 1). {@link containedPathSetting} compares spellings only, so without this a writer would follow
 * a symlink or junction inside the folder out of it, a dangling one included, or act on a path whose
 * real path cannot be read. The repository supplies the link whichever scope named the path, so the
 * manifest default and a relative user value are checked too. A value spelled outside the folder can
 * only be the operator's own user value, theirs to point anywhere, so it is not checked, and the
 * spelling test runs first, with no I/O.
 *
 * At least these spellings are refused outright, before any I/O. A `..` component: the real-path check collapses
 * `..` by spelling, but on POSIX the CLI's kernel follows a link before it applies the `..` after it,
 * so `link/../x` could land outside the folder although its spelling is `x`. And, on Windows, a name
 * {@link hasTrailingDotOrSpaceName}, {@link hasColonInName} or {@link hasReservedDeviceName} names,
 * which the real-path check can pass although the CLI's Win32 open reaches another entry or a device.
 *
 * Open limits. The check reads the named path only: a link BELOW it, such as a linked `codesets`
 * folder under `configDir`, is not caught here. The real-path reads are synchronous, because cli.ts
 * `writerPathSetting` answers synchronously to its many callers, so a workspace on a slow share stalls
 * the extension host for each writer command, and a link inside the folder is followed wherever it
 * leads while its real path is read. Only a trusted window runs the check (cli.ts `writerSetting`),
 * where the repository's own code already runs.
 */
export function escapesByLink(ws: string | undefined, value: string, win32: boolean = path.sep === "\\"): boolean {
  if (ws === undefined) {
    return false;
  }
  const rel = committedRelativePath(ws, value);
  if (rel === undefined) {
    return false;
  }
  // A backslash separates components on Windows only; on POSIX it is part of a name.
  if (value.split(win32 ? /[\\/]/ : /[/]/).includes("..")) {
    return true;
  }
  if (hasTrailingDotOrSpaceName(rel, win32) || hasColonInName(rel, win32) || hasReservedDeviceName(rel, win32)) {
    return true;
  }
  return resolveInsideWorkspace(ws, value) === undefined;
}

/**
 * The refusal a writer shows when {@link escapesByLink} holds. It names the setting, never the value
 * or the link's target (docs/REVIEW-STANDARDS.md R12). Its first remedy works for every writer. The
 * second, an absolute path in user settings, which {@link escapesByLink} does not check, is named
 * with the two writers that decline one: the New Route wizard writes only inside the workspace
 * folder, and version-control setup commits no hook for a folder outside it. It also says to remove
 * the workspace value, since a value the workspace sets inside the folder wins over the user's. `fallback` names the
 * file checked in place of a blank value, which the CLI opens then (cli.ts `writerSetting`).
 */
export function linkEscapeRefusal(key: PathSettingKey, fallback?: string): string {
  const subject =
    fallback === undefined
      ? `messagefoundry.${key} names a path`
      : `messagefoundry.${key} is blank, so the CLI opens ${fallback}, a path`;
  return (
    `MessageFoundry: nothing was written or started. ${subject} inside the workspace folder that may ` +
    "lead out of it, or that Windows may open as another name or a device. At least one of these holds: " +
    "a symbolic link or junction on the path leads out, the path climbs with '..', a folder or file name " +
    "on it is a Windows device name such as nul or com1, a folder or file name on it " +
    "ends in a dot or a space or holds a colon, or its real path cannot be read. Remove the link, the " +
    "'..' or the colon, rename the folder or file, correct the setting value, or make the workspace " +
    "folder readable, so the path is a plain " +
    "folder or file inside the workspace folder. Commands other than New Route and the commit hook " +
    "also take the target of a link, named with an absolute path in user settings, once any value " +
    "for the setting in workspace settings is removed, since a workspace value wins over a user value."
  );
}

/** The scopes of a setting that {@link containedPathSetting} reads: VS Code's `inspect()` answer.
 *  A folder value is not read: these settings are read with no resource, so `get` ignores it too. */
export interface PathSettingScopes {
  readonly defaultValue?: unknown;
  readonly globalValue?: unknown;
  readonly workspaceValue?: unknown;
}

/**
 * The value a workspace-relative path setting (`messagefoundry.configDir`, `serviceConfig`,
 * `messageSetsDir`) takes, contained to the workspace folder (BACKLOG #5404).
 *
 * A value the workspace's own settings set, which a repository's `.vscode/settings.json` or
 * `.code-workspace` file can, counts only when, as spelled, it is the workspace folder `ws` or lies
 * inside it. One that is absolute elsewhere, climbs out by `..`, is not text, or is set with no
 * folder open, is dropped for the next scope down, as VS Code drops a restricted setting in
 * Restricted Mode: the user's own value, else the manifest default, else `fallback`. That holds in a
 * trusted window too, because trust is granted to run the folder's code, not to let its settings
 * point the extension at files outside it. A file elsewhere is named in user settings. `ws` is the
 * first workspace folder, the one every CLI call runs in, so in a multi-root workspace a value
 * naming another of its folders is dropped too: the fail-closed reading.
 *
 * A user-set value is the operator's own choice and is returned as written when it is text. One that
 * is not text is dropped too, for the default, so no caller hands a number or an object to
 * `node:path`, which throws on one. No answer at all (`seen` undefined) gives `fallback`, so an
 * unread scope is never taken as permission. The answer also names the scope the value came from
 * and which scope's value, if any, was dropped, so a caller never re-derives either from the raw
 * scopes. A command that writes or launches under the setting refuses a dropped value rather than
 * act on the one used in its place, and shows {@link writerRefusal} (cli.ts `writerPathSetting`).
 *
 * Open limit: this compares spellings only, with no file-system call, because every CLI call reads
 * these settings. It does not catch at least a link or junction inside the folder that leads out of
 * it, a Windows name ending in a dot or a space, a Windows name holding a colon, or a Windows
 * device name. A writer that needs those checks makes them itself
 * ({@link escapesByLink}, {@link resolveInsideWorkspace}, securityConfigTarget).
 */
export function containedPathSetting(
  seen: PathSettingScopes | undefined,
  ws: string | undefined,
  fallback: string,
): ContainedPathSetting {
  if (seen === undefined) {
    return { value: fallback, source: "default", dropped: false };
  }
  const v = seen.workspaceValue;
  if (typeof v === "string" && ws && isWithin(path.resolve(ws), path.resolve(ws, v))) {
    return { value: v, source: "workspace", dropped: false };
  }
  const u = seen.globalValue;
  if (typeof u === "string") {
    return { value: u, source: "user", dropped: v !== undefined ? "workspace" : false };
  }
  // A workspace drop is named first: it is the value the operator is most likely to be reading.
  const dropped = v !== undefined ? "workspace" : u !== undefined ? "user" : false;
  const value = typeof seen.defaultValue === "string" ? seen.defaultValue : fallback;
  return { value, source: "default", dropped };
}

/** The scope whose value {@link containedPathSetting} dropped: a workspace value that is not inside
 *  the folder (or set with no folder open), or a user value that is not text. */
export type DroppedScope = "workspace" | "user";

/** {@link containedPathSetting}'s answer: the value, the scope it came from, and which scope's value
 *  was dropped on the way, if any. */
export interface ContainedPathSetting {
  readonly value: string;
  readonly source: "workspace" | "user" | "default";
  readonly dropped: DroppedScope | false;
}

/** Why `messagefoundry.<key>` was dropped, as both notices below say it. It names the setting and
 *  the scope it was written in, never the value (docs/REVIEW-STANDARDS.md R12). */
function droppedWhy(key: string, dropped: DroppedScope): string {
  return dropped === "workspace"
    ? `messagefoundry.${key}, set in workspace settings, is not a path inside the workspace folder, is not ` +
        "text, or no folder is open"
    : `messagefoundry.${key}, set in user settings, is not text`;
}

/** The warning a READER shows once per dropped value: it goes on with the value used in its place,
 *  and so do the other readers, Test Bench Run and Debug, Live Debug and validate-on-save among them.
 *  Writers, and Start and Restart, refuse instead (writerRefusal), for a workspace or a user value. */
export function droppedNotice(key: string, dropped: DroppedScope): string {
  const fix =
    dropped === "workspace"
      ? "until it is removed; a path elsewhere goes in user settings."
      : "until it is corrected.";
  return (
    `${droppedWhy(key, dropped)}, so it is not used. Commands that read settings, at least Test Bench ` +
    "Run and Debug, Live Debug and validate-on-save, go on with the value used in its place. Commands " +
    `that write, and Start and Restart, refuse ${fix}`
  );
}

/**
 * The refusal a command that WRITES or LAUNCHES under a path setting shows instead of acting, when a
 * value the operator wrote was dropped (BACKLOG #5404). A reader may go on with the value used in
 * the dropped one's place; a writer must not, because the operator named a different file or folder,
 * and an alert rule, code set, connection, generated message, reload or engine Start aimed at the
 * substitute lands where nobody chose. A user value does not lift a workspace refusal, so the fix
 * names the workspace value; a path elsewhere goes in user settings once that value is gone.
 */
export function writerRefusal(key: string, dropped: DroppedScope): string {
  const fix =
    dropped === "workspace"
      ? "Correct or remove the workspace value; to use a path elsewhere, remove it and set the path in user settings."
      : "Correct the user value.";
  return `MessageFoundry: ${droppedWhy(key, dropped)}, so nothing was written or started. ${fix}`;
}

/** The log line a background reader writes when it refuses a dropped value rather than act on the
 *  one used in its place (BACKLOG #5404). `skipped` says what did not happen. */
export function droppedSkipped(key: string, dropped: DroppedScope, skipped: string): string {
  return `${droppedWhy(key, dropped)}, so ${skipped}`;
}

