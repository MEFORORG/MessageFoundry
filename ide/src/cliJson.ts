// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Turning one `messagefoundry ... --json` result into a value or an error. No `vscode` import, so the
// unit suite runs it; cli.ts wraps it around the real child process.
//
// PHI (ASVS 14.2.6, vault BACKLOG #1187, ground d2). A failure here becomes text the user sees: a
// CodeLens title, a status-bar tooltip, an error toast. So the message is OURS, and never quotes what
// the CLI wrote. Two paths used to quote it:
//   * stdout that is not JSON. The CLI runs config modules in its own process, so a print() in one
//     can write to stdout ahead of the JSON. JSON.parse then fails, and V8's message quotes the
//     start of the text, which is whatever that print wrote. (`dryrun` now sends an author's print
//     to stderr; `validate` and `graph`, which also import config modules, do not.)
//   * empty stdout. The message used to be the CLI's stderr, which can carry a traceback or a
//     warning quoting a value.
// Either text stays out of the message. It is not logged either: the extension's output channels are
// pasted into bug reports (see engineLog.ts), so they are no safer than a toast.
//
// The CLI's own `{"error": "..."}` body is different, and passes through. The paths that compose it in
// `dryrun`, `validate` and `graph` were traced on this branch (vault BACKLOG #1187, 2026-10-01). At
// least these exist, and each is built from configuration and path facts, from class-only text, or
// from `safe_exc`-scrubbed text:
//   * `dryrun` and `graph`: a `WiringError` from `load_config`, before any message is read.
//   * `dryrun`: `read_messages`' refusals (paths, sizes, `strerror`), before any message is read.
//   * `dryrun`, plain and `--trace json` alike: a `ValueError`/`KeyError` that stops the per-message
//     loop. `select_inbound`'s refusals keep their text (connection names). Anything else is
//     reported by class only, since it can come from reading a message: `_dryrun_loop_error` in
//     `__main__.py`, pinned by tests/test_cli.py. The loop's ordinary failures (decode, the HL7
//     parse, strict validation, the Router and Handlers) never reach it: `dry_run` catches them into
//     the message's own `safe_error`-gated `error` field.
//   * any command: the dispatch-level catch in `cli_common.run_cli` (BACKLOG #1863) prints an
//     uncaught exception as `safe_exc` text. That scrubber is not de-identification (it can miss a
//     lone identifier), so it is the weakest of these.
// The one unvetted fact-path text is `WiringError`'s "error loading config module <file>:
// <exception>", which quotes what a config module raised at import: the author's own code, run
// before any sample is read. Every command that imports config modules can print it, `connection
// upsert` and `remove` included.
import { looksLikeUnknownArgument } from "./stepsModel";

export interface CliResult {
  stdout: string;
  stderr: string;
  code: number;
}

/** The synthetic stderr cli.ts returns, without running anything, in an untrusted workspace. */
export const UNTRUSTED_WORKSPACE_STDERR =
  "workspace not trusted — MessageFoundry CLI disabled until you trust this workspace";

/**
 * A CLI result that could not become a value. Its `message` is fixed text plus at most a byte count;
 * the CLI's own output is never in it. Two flags carry the facts some callers need from that output,
 * decided here so they never read it. `argumentRejected`: an argument parser refused a flag or a
 * verb, in any common wording (stepsModel.isUnknownArgumentError retries without the flag).
 * `argparseRejection`: argparse's own two wordings only, which connectionSchemaModel reads as "this
 * engine predates the command" and must not widen.
 */
export class CliOutputError extends Error {
  constructor(
    message: string,
    readonly argumentRejected: boolean,
    readonly argparseRejection: boolean = false,
  ) {
    super(message);
  }
}

/** Argparse's rejection of a verb or flag it does not have, and nothing broader. */
const ARGPARSE_REJECTION = /invalid choice|unrecognized arguments/i;

/** The subcommand words of an argv, for a message: our own arguments up to the first flag, at most two. */
export function commandLabel(args: string[]): string {
  const words: string[] = [];
  for (const arg of args) {
    if (arg.startsWith("-") || words.length === 2) {
      break;
    }
    words.push(arg);
  }
  return words.join(" ") || "command";
}

function byteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

/** An argparse usage blob printed to stdout instead of stderr. Tested here; never quoted. */
const USAGE_ON_STDOUT = /^\s*usage:/i;

/**
 * Parse a `--json` CLI result's stdout. An `{"error": ...}` body throws an `Error` carrying the CLI's
 * composed message. Every other failure throws a {@link CliOutputError} whose message quotes nothing
 * the CLI printed.
 */
export function parseJsonResult<T>(res: CliResult, args: string[]): T {
  const label = commandLabel(args);
  const text = res.stdout.trim();
  if (!text) {
    if (res.stderr.trim() === UNTRUSTED_WORKSPACE_STDERR) {
      throw new CliOutputError(UNTRUSTED_WORKSPACE_STDERR, false); // our own text, not the CLI's
    }
    throw new CliOutputError(
      `messagefoundry ${label} exited with code ${res.code} and printed no JSON. Its error output ` +
        `(${byteLength(res.stderr)} bytes) is not shown here because it can quote message data. Run ` +
        "the same command with --json in a terminal to read it.",
      looksLikeUnknownArgument(res.stderr),
      ARGPARSE_REJECTION.test(res.stderr),
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CliOutputError(
      `messagefoundry ${label} exited with code ${res.code} and printed ${byteLength(res.stdout)} ` +
        "bytes that are not valid JSON. The output is not shown here because it can quote message " +
        "data. One cause is a print() at the top level of a config module. Run the same command " +
        "with --json in a terminal to read it.",
      USAGE_ON_STDOUT.test(text) || looksLikeUnknownArgument(res.stderr),
      USAGE_ON_STDOUT.test(text) || ARGPARSE_REJECTION.test(res.stderr),
    );
  }
  // The CLI prints {"error": "..."} (e.g. on a WiringError) instead of the expected array/object;
  // surface it as a thrown Error so every caller's try/catch shows the real message.
  if (
    parsed !== null &&
    typeof parsed === "object" &&
    !Array.isArray(parsed) &&
    typeof (parsed as { error?: unknown }).error === "string"
  ) {
    throw new Error((parsed as { error: string }).error);
  }
  return parsed as T;
}
