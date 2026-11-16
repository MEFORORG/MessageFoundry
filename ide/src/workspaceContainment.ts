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

function isWithin(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return !(path.isAbsolute(rel) || rel === ".." || rel.startsWith(`..${path.sep}`));
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
 * these settings. It does not catch a link or junction inside the folder that leads out of it, or a
 * Windows name ending in a dot or a space. A writer that needs those checks makes them itself
 * ({@link resolveInsideWorkspace}, securityConfigTarget).
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

/** The warning a READER shows once per dropped value: it goes on with the value used in its place.
 *  Commands that write or start something refuse instead, while the workspace value is there. */
export function droppedNotice(key: string, dropped: DroppedScope): string {
  const use =
    dropped === "workspace"
      ? " Commands that write or start something refuse until it is removed; a path elsewhere goes in user settings."
      : "";
  return `${droppedWhy(key, dropped)}, so it is not used.${use}`;
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

