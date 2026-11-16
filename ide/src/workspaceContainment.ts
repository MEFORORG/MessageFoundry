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
 * A user-set value is the operator's own choice and is returned as written. No answer at all (`seen`
 * undefined) gives `fallback`, so an unread scope is never taken as permission. The answer also
 * names the scope the value came from and whether a workspace value was dropped, so a caller never
 * re-derives either from the raw scopes.
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
  const dropped = v !== undefined;
  if (seen.globalValue !== undefined) {
    // As written even when it is not text, as `get` returned it, so a malformed user value still
    // reaches the callers' own refusals (connectionServiceConfig names it as an empty path).
    return { value: seen.globalValue as string, source: "user", dropped };
  }
  const value = typeof seen.defaultValue === "string" ? seen.defaultValue : fallback;
  return { value, source: "default", dropped };
}

/** {@link containedPathSetting}'s answer: the value, the scope it came from, and whether a
 *  workspace value was dropped on the way. */
export interface ContainedPathSetting {
  readonly value: string;
  readonly source: "workspace" | "user" | "default";
  readonly dropped: boolean;
}

