// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The transient files a Test Bench collection run feeds to `dryrun` (BACKLOG #5415, ADR 0121). The case
// bodies are PHI held in SecretStorage, and `dryrun` reads only files, so a run writes them to disk for
// as long as the dry-run takes. No `vscode` import, so this is unit-testable in isolation.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** Every run's directory starts with this, which is how a later run finds one a crash left behind. */
export const CASE_DIR_PREFIX = "mefor-testbench-";

/**
 * How old a run's directory must be before a later run deletes it as left behind. A run deletes its
 * own directory when it ends, so only a crash leaves one; the margin keeps a sweep from deleting the
 * directory of a run still going in another window.
 */
export const STALE_CASE_DIR_MS = 60 * 60 * 1000;

/** Case `i`'s file name. Unique within a run, so a dry-run row maps back to its case by basename. */
export function caseFileName(i: number): string {
  return `case_${String(i).padStart(4, "0")}.hl7`;
}

/** A name caseFileName writes, the only name a run directory's deletion unlinks. */
const CASE_FILE = /^case_\d{4,}\.hl7$/;

/**
 * Write each input to its own file in a fresh directory under `base`, and return the directory. The
 * directory is 0700 and each file is created exclusively at 0600, which on POSIX keeps every other
 * local account from reading a body while the run lasts. Windows ignores those modes, so there the
 * temp directory's own ACL governs: owner-only for the default per-user TEMP, not for a shared
 * directory TEMP is pointed at. On any failure the directory is removed, best effort, before the
 * error is rethrown; a removal that fails leaves it for a later sweep.
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
 *  briefly holding a just-written case file on Windows causes. A file already gone is not an error. */
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

/**
 * Delete a run's directory without ever recursing. `dir` must lstat as a plain directory; in it,
 * only a regular file named as caseFileName names one is unlinked, then `dir` itself is removed with
 * rmdir, which fails and leaves it if anything else is still in it. No recursive rmSync, because in
 * the VS Code extension host (measured on its Node v24.21.0) a recursive rmSync follows a junction
 * and deletes its target's files. A case file that cannot be removed does not stop the others: the
 * rest are still unlinked, then the first error is thrown. Throws on any failure, a directory
 * already gone included. Open limit: `dir` is checked once, by path, so a directory swapped for a
 * link between that lstat and the listing is followed.
 */
function deleteCaseDir(dir: string, retries: number): void {
  if (!fs.lstatSync(dir).isDirectory()) {
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

/** Remove a run's directory. Best effort: a cleanup error must not mask the run's own result. */
export function removeCaseDir(dir: string): void {
  try {
    deleteCaseDir(dir, 3);
  } catch {
    /* gone already, or a later sweep retries it (sweepStaleCaseDirs); one holding anything but
       case files stays */
  }
}

/**
 * Delete the run directories under `base` that a crashed run left behind: a real directory (never a
 * symlink) named with CASE_DIR_PREFIX, last modified more than `maxAgeMs` before `now`, and, on POSIX,
 * owned by this process's user. The OS temp directory is shared there, so the prefix alone does not
 * say who made an entry. On Windows the default TEMP is per-user. Each is deleted as removeCaseDir
 * deletes one but with no retry, without recursing, so a link inside it is never followed, and a
 * directory holding anything but case files is left, on every later sweep too. Returns how many it removed. Best effort: an entry it cannot
 * read or remove is skipped.
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
      /* gone already, or not ours to remove */
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
