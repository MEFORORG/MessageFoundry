// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Case-insensitive path comparison that folds ASCII A-Z only (BACKLOG #5404, #5832).
//
// toLowerCase() folds more than ASCII: at least U+212A KELVIN SIGN becomes "k", a name NTFS keeps
// apart from "k". path.win32.relative calls toLowerCase() on both sides, so a directory whose name
// differs from the workspace's only by such a character read as inside it. These helpers fold only
// A-Z, so a non-ASCII case difference reads as a different path: the fail-closed reading. This misses
// at least a non-ASCII name NTFS does fold, which now reads as outside or as another file. A leaf
// module, so every caller can import it without a cycle; it is vscode-free for the unit suite.
import * as path from "node:path";

/** `s` with ASCII A-Z lower-cased and every other character, non-ASCII letters included, unchanged. */
export function foldAsciiCase(s: string): string {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

/**
 * Whether `target` is `root` or lies inside it, both absolute. On Windows (`win32`, by default when
 * running there) the two are compared with only ASCII case folded, root first (drive or UNC share)
 * and then segment by segment; elsewhere they are compared exactly. Not path.relative, whose win32
 * form folds with toLowerCase() and would undo the ASCII-only fold.
 */
export function isPathWithin(root: string, target: string, win32: boolean = path.sep === "\\"): boolean {
  const p = win32 ? path.win32 : path.posix;
  const fold = (s: string): string => (win32 ? foldAsciiCase(s) : s);
  const r = fold(p.resolve(root));
  const t = fold(p.resolve(target));
  const rootPart = p.parse(r).root;
  if (p.parse(t).root !== rootPart) {
    return false; // another drive or share
  }
  const segments = (s: string): string[] =>
    s
      .slice(rootPart.length)
      .split(p.sep)
      .filter((seg) => seg !== "");
  const rs = segments(r);
  const ts = segments(t);
  return ts.length >= rs.length && rs.every((seg, i) => seg === ts[i]);
}
