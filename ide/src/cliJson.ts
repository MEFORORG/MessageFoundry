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
// The CLI's own `{"error": "..."}` body is different. It is a message the CLI composed on purpose for
// this caller, from its own wording (a missing file, a wiring error, an ambiguous --inbound), so it
// still passes through as before.
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
 * the CLI's own output is never in it. `argumentRejected` carries the one fact some callers need from
 * that output, decided here so they never read it: an argument parser refused a flag or a verb, which
 * means the installed engine predates the command (see stepsModel.isUnknownArgumentError and
 * connectionSchemaModel.isEnginePredatesSchema).
 */
export class CliOutputError extends Error {
  constructor(
    message: string,
    readonly argumentRejected: boolean,
  ) {
    super(message);
  }
}

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
        "the command with --json in a terminal to read it.",
      looksLikeUnknownArgument(res.stderr),
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CliOutputError(
      `messagefoundry ${label} exited with code ${res.code} and printed ${byteLength(res.stdout)} ` +
        "bytes that are not valid JSON. The output is not shown here because it can quote message " +
        "data. A print() in a config module can cause this. Run the command with --json in a " +
        "terminal to read it.",
      USAGE_ON_STDOUT.test(text) || looksLikeUnknownArgument(res.stderr),
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
