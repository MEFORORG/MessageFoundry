// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Where a `messagefoundry validate --json` diagnostic lands in the Problems panel (BACKLOG #5847).
// vscode-free so the node-side unit suite can drive it; validate.ts turns the result into a Uri.
import { resolveAgainst } from "./pathIdentity";

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

// The engine writes a load failure's place as "<Type> at line N" when the line is in the reported file,
// and "<Type> in <name>.py at line N" when it is in a helper the file imported (wiring.py, the located
// detail). Only the first is a line in `file`, so a ".py" right before it means the line is elsewhere.
const OWN_LINE_RE = /(?<!\.py) at line (\d+)\b/;

/**
 * Locate `d` for the Problems panel. The CLI runs in `cwd` (the workspace), so a relative `file` is
 * resolved against it rather than against the filesystem root, and a diagnostic with no file falls
 * back to the config directory, which may itself be absolute. The line is the engine's own "at line N"
 * when the message names one in this file, else the first line.
 */
export function diagnosticLocation(
  d: ValidateDiagnostic,
  cwd: string,
  configDir: string,
  win32?: boolean,
): DiagnosticLocation {
  const file = resolveAgainst(cwd, d.file ?? configDir, win32);
  const m = d.file ? OWN_LINE_RE.exec(d.message) : null;
  const line = m ? Math.max(Number(m[1]) - 1, 0) : 0;
  return { file, line };
}
