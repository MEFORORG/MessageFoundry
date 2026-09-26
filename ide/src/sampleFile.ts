// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// A hard-capped read of a sample file the user picked (ASVS 5.1.1, BACKLOG #1127). The IDE's local file
// pickers are 5.1.1 upload features by owner ruling of 2026-09-23, and `docs/CONNECTIONS.md` lists them.
// The engine's `dryrun` already refuses an over-cap fixture, but the Steps view also reads its picked
// sample itself, to list its segments, and that read happens before `dryrun` sees the file.
//
// Unlike `symbolIndex.readCapped`, which is a best-effort guard, this is a HARD bound: it reads at most
// `cap + 1` bytes into a buffer sized up front, so a file that grows after the size check still cannot
// land in memory whole. No vscode import, so it is unit-testable.
import * as fs from "node:fs";

/** The engine's `MAX_FIXTURE_FILE_BYTES` (`messagefoundry/pipeline/dryrun.py`), 16 MiB: the default cap
 *  `dryrun` applies to the same file. `tests/test_asvs_file_surface_inventory.py` pins the two equal. */
export const MAX_SAMPLE_FILE_BYTES = 16 * 1024 * 1024;

/** A picked sample over the cap. Its message names the file and the cap, for the user to read. */
export class SampleTooLargeError extends Error {
  constructor(file: string, cap: number) {
    super(`${file} is over the ${cap}-byte sample file cap; pick a smaller sample file`);
    this.name = "SampleTooLargeError";
  }
}

/** Throw {@link SampleTooLargeError} if `file` reports a size over `cap`. Other errors propagate. Used at
 *  pick time, so an over-cap sample is refused before it is ever stored for reuse. */
export function checkSampleSize(file: string, cap: number = MAX_SAMPLE_FILE_BYTES): void {
  if (fs.statSync(file).size > cap) {
    throw new SampleTooLargeError(file, cap);
  }
}

/**
 * `file` as UTF-8, reading at most `cap + 1` bytes. Throws {@link SampleTooLargeError} when the file is
 * over `cap`, whether it said so up front or grew during the read. Other errors (a missing or unreadable
 * file) propagate as the `fs` error.
 */
export function readSampleCapped(file: string, cap: number = MAX_SAMPLE_FILE_BYTES): string {
  const fd = fs.openSync(file, "r");
  try {
    const size = fs.fstatSync(fd).size;
    if (size > cap) {
      throw new SampleTooLargeError(file, cap);
    }
    // Sized to what the file reports, plus one byte to notice growth, so a small sample costs a small
    // buffer. Only a file that grew during the read gets the full `cap + 1` buffer.
    let buf = Buffer.alloc(size + 1);
    let got = fillFrom(fd, buf, 0);
    if (got > size) {
      const bigger = Buffer.alloc(cap + 1);
      buf.copy(bigger, 0, 0, got);
      buf = bigger;
      got = fillFrom(fd, buf, got);
    }
    if (got > cap) {
      throw new SampleTooLargeError(file, cap);
    }
    return buf.toString("utf8", 0, got);
  } finally {
    fs.closeSync(fd);
  }
}

/** Read from `fd` into `buf` from offset `got` until end of file or a full buffer; the new fill level. */
function fillFrom(fd: number, buf: Buffer, got: number): number {
  while (got < buf.length) {
    const n = fs.readSync(fd, buf, got, buf.length - got, null);
    if (n === 0) {
      break;
    }
    got += n;
  }
  return got;
}
