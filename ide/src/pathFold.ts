// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Case-insensitive path comparison that folds ASCII A-Z only (BACKLOG #5404, #5832).
//
// The fact every ASCII-fold site in the IDE links here for: toLowerCase() folds more than ASCII, at
// least U+212A KELVIN SIGN becomes "k", a name NTFS keeps apart from "k". path.win32.relative calls toLowerCase() on both sides, so a directory whose name
// differs from the workspace's only by such a character read as inside it. These helpers fold only
// A-Z, so a non-ASCII case difference reads as a different path. That is not a pure tightening: a
// non-ASCII case difference NTFS does fold, such as e-acute against E-acute, also reads as another
// path, and a caller that skips a check for a path outside the folder would skip it there.
// {@link nonAsciiCaseVariant} finds that case, so such a caller can ask the file system instead. The
// ASCII fold still reads as one path at least two names a case-sensitive directory keeps apart
// (fsutil setCaseSensitiveInfo, or one WSL created) that differ in ASCII case. A leaf module, so
// every caller can import it without a cycle; it is vscode-free for the unit suite.
// {@link segmentsBelowOnDisk} is the one helper here that reads the file system, for a caller whose
// outside answer only switches a convenience off.
import * as fs from "node:fs";
import * as path from "node:path";

/** `s` with ASCII A-Z lower-cased and every other character, non-ASCII letters included, unchanged. */
export function foldAsciiCase(s: string): string {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

/** Whether `a` and `b` are one name under at least two JavaScript case folds: toLowerCase(), as
 *  path.win32.relative folds, and upper-then-lower, which also joins U+017F LONG S to "s". Each
 *  covers the ASCII fold. Open limit: no case fold joins the NFC and NFD forms of one letter, which
 *  a normalization-insensitive file system (APFS or HFS+, reached over SMB) treats as one name. */
export function sameIgnoringAnyCase(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase() || a.toUpperCase().toLowerCase() === b.toUpperCase().toLowerCase();
}

/** `s` resolved, as its root (drive, UNC share or `/`) and its non-empty segments. */
function parts(p: path.PlatformPath, s: string): { root: string; segments: string[] } {
  const r = p.resolve(s);
  const root = p.parse(r).root;
  return {
    root,
    segments: r
      .slice(root.length)
      .split(p.sep)
      .filter((seg) => seg !== ""),
  };
}

/** `target`'s parts, and the number of its segments that spell `root`, when `same` matches the
 *  roots and each of `root`'s segments; else undefined. */
function under(
  root: string,
  target: string,
  win32: boolean,
  same: (a: string, b: string) => boolean,
): { root: string; segments: string[]; depth: number } | undefined {
  const p = win32 ? path.win32 : path.posix;
  const r = parts(p, root);
  const t = parts(p, target);
  if (!same(r.root, t.root) || t.segments.length < r.segments.length) {
    return undefined; // another drive or share, or above the root
  }
  return r.segments.every((seg, i) => same(seg, t.segments[i]))
    ? { root: t.root, segments: t.segments, depth: r.segments.length }
    : undefined;
}

/** The exact comparison POSIX makes, and the ASCII-only one Windows (`win32`) makes. */
function asciiSame(win32: boolean): (a: string, b: string) => boolean {
  return win32 ? (a, b) => foldAsciiCase(a) === foldAsciiCase(b) : (a, b) => a === b;
}

/**
 * The segments of `target` below `root`, both absolute, as `target` spells them, when `target` is
 * `root` (no segments) or lies inside it; else undefined. On Windows (`win32`, by default when
 * running there) the two are compared with only ASCII case folded, root first (drive or UNC share)
 * and then segment by segment; elsewhere they are compared exactly. Not path.relative, whose win32
 * form folds with toLowerCase() and would undo the ASCII-only fold.
 */
export function segmentsBelow(root: string, target: string, win32: boolean = path.sep === "\\"): string[] | undefined {
  const t = under(root, target, win32, asciiSame(win32));
  return t === undefined ? undefined : t.segments.slice(t.depth);
}

/** Whether `target` is `root` or lies inside it, as {@link segmentsBelow} compares them. */
export function isPathWithin(root: string, target: string, win32: boolean = path.sep === "\\"): boolean {
  return segmentsBelow(root, target, win32) !== undefined;
}

/** Whether `a` and `b` are one path, as {@link segmentsBelow} compares them. */
export function isSamePath(a: string, b: string, win32: boolean = path.sep === "\\"): boolean {
  return segmentsBelow(a, b, win32)?.length === 0;
}

/**
 * On Windows (`win32`), when `target` is spelled outside `root` by {@link isPathWithin} only because
 * a segment, or the root itself, differs by a case outside A-Z: `head`, the folder `target` names
 * at `root`'s depth, and `rest`, its segments below that. A case-insensitive file system may fold
 * that difference, so `head` may be `root` itself (e-acute against E-acute on NTFS), or may be
 * another folder (U+212A KELVIN SIGN against "k"); only the file system can say which. Undefined
 * when `target` is within `root` by the ASCII fold, when it is outside under every case fold, and
 * always elsewhere, where paths are compared exactly. Spelling only, with no I/O.
 */
export function nonAsciiCaseVariant(
  root: string,
  target: string,
  win32: boolean = path.sep === "\\",
): { readonly head: string; readonly rest: readonly string[] } | undefined {
  if (!win32 || isPathWithin(root, target, win32)) {
    return undefined;
  }
  const t = under(root, target, win32, sameIgnoringAnyCase);
  if (t === undefined) {
    return undefined;
  }
  return { head: path.win32.join(t.root, ...t.segments.slice(0, t.depth)), rest: t.segments.slice(t.depth) };
}

/** `p`'s real path. The native call fails with EISDIR on some Windows volumes (RAM disks, some
 *  virtual drives), where the JS implementation still answers, as workspaceContainment.ts's does. */
function realpathOf(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw e;
    }
    return fs.realpathSync(p);
  }
}

/** Whether `a` and `b` name one folder on disk: by real path, or, where the real path keeps the
 *  spelling's case (the JS fallback), by device and a non-zero file id; a volume that reports file
 *  id 0 cannot tell two folders apart. A path that does not exist or cannot be read gives false,
 *  which every caller reads as "outside". */
function sameFolderOnDisk(a: string, b: string, win32: boolean): boolean {
  try {
    if (isSamePath(realpathOf(a), realpathOf(b), win32)) {
      return true;
    }
    const x = fs.statSync(a, { bigint: true });
    const y = fs.statSync(b, { bigint: true });
    return x.ino !== 0n && x.dev === y.dev && x.ino === y.ino;
  } catch {
    // ENOENT is the usual case: a U+212A spelling names no folder NTFS would fold onto root. Any
    // other read failure also reads as outside, which only switches a convenience off.
    return false;
  }
}

/**
 * {@link segmentsBelow}, except where `target` is outside only by a case difference outside A-Z
 * ({@link nonAsciiCaseVariant}): then the file system is asked whether the folder `target` names at
 * `root`'s depth is `root` itself, and when it is, the segments below it are returned. So e-acute
 * against E-acute, which NTFS folds, reads as inside, and U+212A KELVIN SIGN against "k", which it
 * does not, reads as outside. A folder that does not exist or cannot be read reads as outside too,
 * so this suits only a caller for which outside switches a convenience off (the editor toolbar, the
 * config-dir watcher), never one that skips a check for a path outside. It makes no file-system call
 * unless such a variant exists, so none off Windows.
 */
export function segmentsBelowOnDisk(
  root: string,
  target: string,
  win32: boolean = path.sep === "\\",
): string[] | undefined {
  const below = segmentsBelow(root, target, win32);
  if (below !== undefined) {
    return below;
  }
  const variant = nonAsciiCaseVariant(root, target, win32);
  return variant !== undefined && sameFolderOnDisk(root, variant.head, win32) ? [...variant.rest] : undefined;
}
