// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Resolve a workspace-relative setting to a directory that is provably inside the workspace folder.
//
// `messagefoundry.configDir` and its siblings are window-scoped, so a checked-in
// `.vscode/settings.json` can set them. A command that WRITES under such a setting must not follow it
// out of the folder (BACKLOG #5410): an absolute path, a `..` climb, or a symlink or junction inside
// the folder that points elsewhere. The check compares real paths, so the last case is caught too.
// It is vscode-free so the node-side unit suite can drive it.
import * as fs from "node:fs";
import * as path from "node:path";

/** `p`'s real path, or `undefined` when it cannot be read (fails closed on anything but ENOENT). */
function realpathOfNearestExisting(p: string): string | undefined {
  const tail: string[] = [];
  let cur = p;
  for (;;) {
    try {
      return path.join(fs.realpathSync.native(cur), ...tail);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
        return undefined;
      }
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
 * The real path of `dir` (relative to `ws`, or absolute) when it is the workspace folder or inside
 * it, else `undefined`. Components that do not exist yet are kept as given; they will be created
 * fresh, so no link can sit among them.
 */
export function resolveInsideWorkspace(ws: string, dir: string): string | undefined {
  const root = realpathOfNearestExisting(path.resolve(ws));
  const target = realpathOfNearestExisting(path.resolve(ws, dir));
  if (root === undefined || target === undefined) {
    return undefined;
  }
  const rel = path.relative(root, target);
  if (path.isAbsolute(rel) || rel === ".." || rel.startsWith(`..${path.sep}`)) {
    return undefined;
  }
  return target;
}
