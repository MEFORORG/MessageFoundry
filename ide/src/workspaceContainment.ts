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
