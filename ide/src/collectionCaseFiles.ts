// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The transient files a Test Bench collection run feeds to `dryrun` (BACKLOG #5415, ADR 0121). The case
// bodies are PHI held in SecretStorage, and `dryrun` reads only files, so a run writes them to disk.
// How long they can stay there is in the deleteCaseDir and sweepStaleCaseDirs docblocks below, the
// source of record for this cleanup. No `vscode` import, so this is unit-testable in isolation.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** Every run's directory starts with this, which is how a later run finds one left behind. */
export const CASE_DIR_PREFIX = "mefor-testbench-";

/**
 * How long after a run directory was last modified sweepStaleCaseDirs may try to delete it. Its
 * docblock says what sets that time, and that a run still going after this long can be swept.
 */
export const STALE_CASE_DIR_MS = 60 * 60 * 1000;

/** Case `i`'s file name. Unique within a run, so a dry-run row maps back to its case by basename. */
export function caseFileName(i: number): string {
  return `case_${String(i).padStart(4, "0")}.hl7`;
}

/** The only names a run directory's deletion unlinks. It matches every name caseFileName writes, and
 *  also names it never writes, such as `case_00001.hl7`. */
const CASE_FILE = /^case_\d{4,}\.hl7$/;

/**
 * Write each input to its own file in a fresh directory under `base`, and return the directory. The
 * directory is 0700 and each file is created exclusively at 0600, which on POSIX keeps every other
 * local account from reading a body while the run lasts. Windows ignores those modes, so there the
 * temp directory's own ACL governs: owner-only for the default per-user TEMP, not for a shared
 * directory TEMP is pointed at. If a write fails, removeCaseDir is called on the directory before
 * the error is rethrown; deleteCaseDir says what that can leave.
 */
export function materializeCases(inputs: readonly string[], base: string = os.tmpdir()): string {
  const dir = fs.mkdtempSync(path.join(base, CASE_DIR_PREFIX)); // mkdtemp makes it 0700 on POSIX
  try {
    inputs.forEach((input, i) => {
      fs.writeFileSync(path.join(dir, caseFileName(i)), input, { encoding: "utf8", mode: 0o600, flag: "wx" });
    });
  } catch (e) {
    removeCaseDir(dir);
    throw e;
  }
  return dir;
}

/** Unlink `file`, retrying `retries` times 100 ms apart on EBUSY or EPERM, as a scanner or indexer
 *  briefly holding a just-written case file on Windows causes. Each wait blocks the calling thread.
 *  A file already gone is not an error. */
function unlinkWithRetries(file: string, retries: number): void {
  for (let attempt = 0; ; attempt++) {
    try {
      fs.unlinkSync(file);
      return;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        return;
      }
      if (attempt >= retries || (code !== "EBUSY" && code !== "EPERM")) {
        throw e;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
    }
  }
}

/** Whether the OS resolves `p` to exactly `expected`, every link on the way followed. The compare is
 *  exact, never case-insensitive: path.relative's lowercasing folds U+212A KELVIN SIGN onto `k`, so
 *  it matches a junction to a different directory whose name differs only so (measured on Node
 *  v24.20.0). Callers build `expected` from the OS's own resolution and listing, which agree on case.
 *  The `.native` form is the one that resolves the junction deleteCaseDir's step 1 describes; plain
 *  realpathSync, which walks by lstat, returns it unresolved (measured on Node v24.20.0). Throws if
 *  `p` cannot be resolved. */
export function isAt(p: string, expected: string): boolean {
  return fs.realpathSync.native(p) === expected;
}

/**
 * Delete a run's directory without recursing. This docblock and sweepStaleCaseDirs's are the source
 * of record for what the Test Bench's temp-file cleanup does (ADR 0121, BACKLOG #5415); other
 * documents point here.
 *
 * What it does, in order:
 * 1. Check `dir`'s identity. Its expected path is its name under its parent's real path, as the OS
 *    resolves it (realpathSync.native). `dir` must lstat as a plain directory, and the OS must
 *    resolve it to exactly that expected path (isAt). Anything else throws, and nothing is removed:
 *    at least a symlink, a junction to a drive-letter path (which lstats as a link), and a junction
 *    to a `\\?\Volume{GUID}\` path, which lstats as its target does, so as a plain directory, with
 *    the target's modification time, when the target is one, but resolves elsewhere (measured on
 *    Node v24.20.0). So does a `dir` already gone, or one the OS cannot resolve: at least on a volume
 *    where realpathSync.native fails, as it does with EISDIR on some RAM disks and virtual drives
 *    (workspaceContainment.ts records this), step 1 refuses every run directory.
 * 2. List `dir`; a listing that fails throws at once, and nothing is removed. An entry whose name
 *    matches CASE_FILE (`case_`, at least four digits, `.hl7`), that lstats as a regular file, and
 *    that the OS resolves to its own name under `dir`'s expected path, is unlinked. A matching regular
 *    file that resolves elsewhere is not unlinked and counts as a failed entry in step 3. Every other
 *    entry is left, at least a name that does not match and a matching name that is a directory, a
 *    link or another non-regular entry. No entry is entered, so a link among the entries is not
 *    followed.
 * 3. An unlink that fails with EBUSY or EPERM is tried `retries` more times, 100 ms apart, each wait
 *    blocking the calling thread; removeCaseDir passes 3 and sweepStaleCaseDirs 0. An lstat or an
 *    identity check is not retried. An entry that lstats as not found is skipped: at least one
 *    already gone, and a `\\?\Volume{GUID}\` junction to a file, which lstats as not found (measured
 *    on Node v24.20.0) and then keeps `dir`, since the rmdir fails on it. An entry whose lstat or
 *    identity check fails, or whose unlink still fails, does not stop the others: once every listed
 *    entry has been tried, the first such error is thrown and `dir` is not removed.
 * 4. Otherwise `dir` is removed with rmdir, which is not retried. Apart from the open limits
 *    below, it throws, and leaves `dir`, if any entry is still in it or the rmdir fails for any
 *    other reason.
 *
 * So, apart from the open limits below, the directory goes only once it is empty, and not always
 * then. At least an entry step 2 leaves, or a case file step 3 cannot unlink, keeps the directory,
 * and that file, on disk. Each unlink also updates `dir`'s modification time (measured on NTFS),
 * which sweepStaleCaseDirs's age gate reads.
 *
 * Why no recursive rmSync: in the VS Code extension host (measured on its Node v24.21.0) a recursive
 * rmSync follows a junction and deletes its target's files.
 *
 * Open limits, at least these. `dir` is checked once, by step 1, and each entry once, by its lstat
 * and identity check in step 2. The listing, every lstat, check and unlink, and the rmdir all go by
 * path, so each check holds only at the moment it is made.
 * - If a directory above `dir` is swapped for a link, the steps after the swap act on the same
 *   names inside the link's target. A swap before step 1 is not caught, since the expected path is
 *   read through the swapped parent: regular files there named as case files can be unlinked, and
 *   the directory there removed once it is empty. After step 1, each entry's check still expects a
 *   path under the original parent and refuses an entry in the target, so an unlink acts there only
 *   when the swap falls between that entry's check and its unlink, the retry waits included. A
 *   refused entry throws before step 4, so the rmdir acts there only when no entry was refused, and
 *   removes the directory there if it is empty.
 * - If `dir` is replaced by another plain directory at any time before the rmdir, before step 1,
 *   after it and after the last unlink included, the steps after the replacement act on that
 *   directory instead. An empty plain directory placed there after the last unlink is removed by the
 *   rmdir, and sweepStaleCaseDirs counts it as a directory removed.
 * - If `dir` itself is swapped for a link after step 1, the rest goes through the link. A swap before
 *   the listing lists the target's entries; a swap before an entry's check acts on the listed names
 *   in the target, where an entry's check then expects a path under `dir` and refuses one there; a
 *   swap after a check and before its unlink, the retry waits included, unlinks that name in the
 *   target. A refused entry throws before step 4. Only when no entry was refused does the rmdir of
 *   step 4 act on the link itself: on Windows it removes a junction even when its target still
 *   holds entries (measured on Node v24.20.0, outside the extension host), and sweepStaleCaseDirs
 *   counts that as a directory removed.
 * - If an entry is swapped between its identity check and its unlink, whatever is then at that name
 *   is unlinked if it can be: a symlink or a drive-letter junction is unlinked itself, not its
 *   target. A directory there fails to unlink: on Windows with EPERM, a `\\?\Volume{GUID}\`
 *   junction included (measured on Node v24.20.0), which step 3 retries; elsewhere the error can
 *   differ, at least EISDIR on Linux, which step 3 does not retry.
 */
function deleteCaseDir(dir: string, retries: number): void {
  const expected = path.join(fs.realpathSync.native(path.dirname(dir)), path.basename(dir));
  if (!fs.lstatSync(dir).isDirectory() || !isAt(dir, expected)) {
    throw new Error("not a plain directory");
  }
  let first: unknown;
  for (const name of fs.readdirSync(dir)) {
    if (!CASE_FILE.test(name)) {
      continue;
    }
    const file = path.join(dir, name);
    try {
      if (fs.lstatSync(file).isFile()) {
        if (!isAt(file, path.join(expected, name))) {
          throw new Error("not a plain file");
        }
        unlinkWithRetries(file, retries);
      }
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
        first ??= e;
      }
    }
  }
  if (first !== undefined) {
    throw first;
  }
  fs.rmdirSync(dir);
}

/** Delete a run's directory as deleteCaseDir does, with 3 retries for each case file's unlink. Any
 *  error is dropped rather than thrown, with no log line or notice, so a cleanup error cannot
 *  replace the run's own result or error; what it can leave is in deleteCaseDir, and when a later
 *  sweep tries again is in sweepStaleCaseDirs. */
export function removeCaseDir(dir: string): void {
  try {
    deleteCaseDir(dir, 3);
  } catch {
    /* dropped on purpose; see the docblock */
  }
}

/**
 * Try to delete the run directories left under `base`, the OS temp directory by default. With
 * deleteCaseDir's docblock, the source of record for this cleanup.
 *
 * When it runs: the Test Bench calls it when it creates its panel, not when it reveals one already
 * open, and at the start of each collection run that finds its collection and a workspace folder,
 * before that run writes its own directory (testBench.ts). Nothing else calls it, so with no later
 * panel creation or run a directory stays on disk with no bound.
 *
 * Which entries it tries: a name starting with CASE_DIR_PREFIX that lstats as a directory, last
 * modified more than `maxAgeMs` (STALE_CASE_DIR_MS, one hour) before `now`, and, on POSIX, owned by
 * this process's effective uid, since the OS temp directory can be shared there, as `/tmp` is. On
 * Windows no owner is checked: the default TEMP is per-user, but a TEMP pointed at a shared
 * directory is not. A symlink and a drive-letter junction do not lstat as a directory. A junction to
 * a `\\?\Volume{GUID}\` path lstats as its target does (deleteCaseDir's step 1), so the type and age
 * gates read its target: one whose target is a directory last modified over the hour ago passes
 * them, deleteCaseDir's step 1 identity check then refuses it, and it is not counted. Each entry
 * tried is deleted by deleteCaseDir with no in-pass retry, and any error is dropped, with no log line
 * or notice. A directory that is not removed is tried again by each later sweep that finds it past
 * these gates. So a case file a sweep could not unlink goes once a later sweep can unlink it, while
 * a directory still holding an entry deleteCaseDir leaves stays on every sweep.
 *
 * The age gate reads the directory's modification time, which at least the run's own case-file
 * writes set and each unlink in it updates, so a partial deletion restarts the hour. It cannot tell
 * whether a run is still going: the dry-run has no timeout, so a run whose directory was last
 * modified more than an hour ago can have its case files unlinked by any later sweep, from another
 * window included, while its dry-run may still read them.
 *
 * At least these stay until a sweep that reaches them can remove them: a directory left by a process
 * that ended before the run's `finally` ran, such as a crash, or a window close or reload while the
 * dry-run is pending (deactivate removes nothing); a directory whose dry-run never returns, since
 * the dry-run has no timeout and the run's `finally` does not run while it is pending; and a case
 * file deleteCaseDir could not unlink. A directory holding an entry deleteCaseDir leaves stays on
 * every sweep, as above, and so does every run directory on a volume where deleteCaseDir's step 1
 * cannot resolve paths.
 *
 * Open limit, at least this one, besides deleteCaseDir's: the gates are read from one lstat, and
 * deleteCaseDir re-checks only that the entry is a plain directory at its expected path, so a
 * directory swapped in between is tried without the owner and age gates.
 *
 * Returns how many directories it removed; an unreadable `base` returns 0.
 */
export function sweepStaleCaseDirs(
  base: string = os.tmpdir(),
  now: number = Date.now(),
  maxAgeMs: number = STALE_CASE_DIR_MS,
): number {
  let names: string[];
  try {
    names = fs.readdirSync(base);
  } catch {
    return 0;
  }
  const uid = process.geteuid?.(); // a new directory gets the effective uid
  let removed = 0;
  for (const name of names) {
    if (!name.startsWith(CASE_DIR_PREFIX)) {
      continue;
    }
    const dir = path.join(base, name);
    try {
      const st = fs.lstatSync(dir);
      if (!st.isDirectory() || (uid !== undefined && st.uid !== uid) || now - st.mtimeMs <= maxAgeMs) {
        continue;
      }
      deleteCaseDir(dir, 0);
      removed++;
    } catch {
      /* dropped on purpose; see the docblock */
    }
  }
  return removed;
}

/**
 * The `dryrun` arguments for one run: the run's directory, never one path per case, so the command
 * line stays the same length however many cases the collection holds. `dryrun --messages` reads a
 * directory's `*.hl7` files in sorted order.
 */
export function caseDryRunArgs(config: string, dir: string): string[] {
  return ["dryrun", "--config", config, "--show-phi", "--messages", dir];
}
