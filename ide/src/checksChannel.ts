// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The "MessageFoundry Checks" output channel, and the only two things a caller may do with it.
//
// The channel object is not exported. A caller can write through `logChecks`, which stamps every
// line in UTC, or reveal the channel, and nothing else, so no line reaches it without a time
// (vault BACKLOG #2349, #2353).
//
// It stays a PLAIN channel on purpose. A LogOutputChannel would add the editor's own stamp, in a
// format this extension cannot set, in front of ours.
import * as vscode from "vscode";

import { writeStamped } from "./checksLog";

let channel: vscode.OutputChannel | undefined;
function out(): vscode.OutputChannel {
  channel ??= vscode.window.createOutputChannel("MessageFoundry Checks");
  return channel;
}

/** Write to the Checks channel. Each line of `text` gets its own UTC time stamp. */
export function logChecks(text: string): void {
  writeStamped(out(), text);
}

/** Reveal the Checks channel. */
export function showChecks(): void {
  out().show();
}
