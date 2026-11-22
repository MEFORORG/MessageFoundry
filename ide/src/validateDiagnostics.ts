// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Where a `messagefoundry validate --json` diagnostic lands in the Problems panel (BACKLOG #5847).
// vscode-free so the node-side unit suite can drive it; validate.ts turns the result into a Uri.
import * as path from "node:path";
import { IS_WIN32, resolveAgainst } from "./pathIdentity";

/** One entry of `validate --json`: the engine's `Diagnostic` (config/wiring.py) carries no line field. */
export interface ValidateDiagnostic {
  message: string;
  file: string | null;
  severity: string;
}

/** An absolute file and a 0-based line for one diagnostic. */
export interface DiagnosticLocation {
  file: string;
  line: number;
}

// The engine writes a module's own load failure as "error loading config module <name>: <Type> at line
// N (...)" (wiring.py, _module_failure and _failure_detail). Any other shape names a line somewhere
// else: "<Type> in <helper>.py at line N" is a helper's line, and a helper-preload refusal quotes the
// helper's own detail. So only that exact shape, naming this file, places the diagnostic.
const OWN_LINE_RE = /^error loading config module (.+?): \S+ at line (\d+)\b/;

/**
 * Locate `d` for the Problems panel. The CLI runs in `cwd` (the workspace), so a relative `file` is
 * resolved against it rather than against the filesystem root, and a diagnostic with no file falls
 * back to the config directory, which may itself be absolute. The line is the engine's own "at line N"
 * when the message places the failure in this file, else the first line.
 */
export function diagnosticLocation(
  d: ValidateDiagnostic,
  cwd: string,
  configDir: string,
  win32: boolean = IS_WIN32,
): DiagnosticLocation {
  const file = resolveAgainst(cwd, d.file || configDir, win32);
  const m = d.file ? OWN_LINE_RE.exec(d.message) : null;
  let line = 0;
  if (m) {
    const name = (win32 ? path.win32 : path.posix).basename(file);
    const same = win32 ? m[1].toLowerCase() === name.toLowerCase() : m[1] === name;
    if (same) {
      line = Math.max(Number(m[2]) - 1, 0);
    }
  }
  return { file, line };
}
