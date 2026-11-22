// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Path identity for paths the CLI reports back to the extension (BACKLOG #5835, #5847).
//
// The CLI runs with the workspace folder as its cwd, so a relative path it prints is relative to that
// folder, never to the extension host's own process cwd. And on Windows VS Code's `Uri.fsPath` lower-cases
// the drive letter while Python keeps whatever case the path was given in, so two spellings of one file
// differ in case. These helpers resolve against the folder the CLI ran in and compare case-insensitively
// on Windows. They are vscode-free so the node-side unit suite can drive them.
import * as path from "node:path";

/** Whether this host is Windows: the default for every `win32` parameter here. */
export const IS_WIN32 = path.sep === "\\";

/** `p` made absolute against `base` (the folder the CLI ran in) when it is relative, and normalized. */
export function resolveAgainst(base: string, p: string, win32: boolean = IS_WIN32): string {
  return win32 ? path.win32.resolve(base, p) : path.posix.resolve(base, p);
}

/**
 * A comparison key for the file `p` names, resolved against `base` first. On Windows (by default, when
 * running there) it is lower-cased, because the file system ignores case and the two sides spell the
 * drive letter differently. Two paths name the same file when their keys are equal.
 */
export function fileKey(base: string, p: string, win32: boolean = IS_WIN32): string {
  const resolved = resolveAgainst(base, p, win32);
  return win32 ? resolved.toLowerCase() : resolved;
}
