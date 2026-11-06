// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Time stamps for the "MessageFoundry Checks" and "MessageFoundry Engine" output channels (vault
// BACKLOG #2349, #2353).
//
// Both are PLAIN output channels, so the editor stamps nothing on them. checksChannel.ts and
// engineLog.ts own them and write every line through `writeStamped`, which puts an ISO 8601 UTC
// instant at the front. A multi-line block, such as the output of `messagefoundry check`, is split
// first so that no line is left without one.
//
// No `vscode` import: the unit tests drive this with a fixed clock and no Extension Host.

/** Write `text` to `sink`, each line prefixed with the clock's instant as ISO 8601 UTC
 *  (`2026-01-02T03:04:05.678Z`), then `label` where one is given. The Engine channel passes its
 *  level word there, so every line of a multi-line message carries the level as well as the time.
 *
 *  One instant covers the whole block: it is when the block was written, and the lines of one
 *  subprocess result have no separate times of their own to report. */
export function writeStamped(
  sink: { appendLine(line: string): void },
  text: string,
  clock: () => Date = () => new Date(),
  label?: string,
): void {
  const head = label === undefined ? clock().toISOString() : `${clock().toISOString()} ${label}`;
  const lines = text.split(/\r\n|\r|\n/).map((line) => (line === "" ? head : `${head} ${line}`));
  // One write for the block, as before this file existed: check output can run to many lines.
  sink.appendLine(lines.join("\n"));
}

/** The record of the one path that commits past a pre-flight check that did not pass ("Commit
 *  baseline anyway").
 *
 *  Written BEFORE git runs, so the stamp on it is the time of the user's choice, and it is on the
 *  channel even if the commit then fails. It says in plain words that the hooks were skipped and by
 *  whom, because a stamped line that only said "baseline commit" would not record a bypass.
 *
 *  It gives the code the pre-flight returned and does not say a check "failed" or "exited": the
 *  runner also returns a non-zero code for a check that could not be started. It makes no claim about later commits either, because
 *  whether the hook is wired is decided elsewhere. */
export function baselineBypassRecord(checkExitCode: number): string {
  return (
    "--- baseline commit: commit hooks SKIPPED by the user's choice of 'Commit baseline anyway' " +
    `(git commit --no-verify); the pre-flight 'messagefoundry check' returned code ${checkExitCode} ---`
  );
}
