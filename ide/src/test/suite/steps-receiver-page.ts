// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as fs from "fs";
import * as path from "path";

import {
  buildHandlerViewModels,
  renderHandlersHtml,
  renderStepsContextMenuHtml,
  type LensParseResult,
} from "../../stepsModel";
import { SHAPE_HELPERS, STARTUP_BANNERS, guardScript } from "../../webviewMessaging";

// The Steps page as its receiver sees it (BACKLOG #5943), shared by steps-rowsource-rebase.test.ts and
// webview-receivers.test.ts. Not a test file itself: mocha only loads `*.test.js`.

const STEPS_JS = fs.readFileSync(path.join(__dirname, "..", "..", "..", "media", "stepsWebview.js"), "utf8");

/** The source `stepsReceiverBody` projects: handler `h`, with one set_field row at line 2. */
export const STEPS_RECEIVER_SOURCE = 'def h(msg):\n    msg.set_field("PID-3", "A")\n';

/** One handler `h` with a set_field row at line 2, as the provider renders it, for projection 1. */
export function stepsReceiverBody(): string {
  const parse: LensParseResult = {
    module: "m",
    handlers: [
      {
        handler: "h",
        module: "m",
        def_line: 1,
        role: "handler",
        rows: [
          {
            kind: "action",
            action: "set_field",
            line_start: 2,
            line_end: 2,
            nesting: 0,
            suite: "1",
            params: { path: "PID-3", value: "A" },
            literal_params: ["path", "value"],
          },
        ],
      },
    ],
  };
  const rows = renderHandlersHtml(buildHandlerViewModels(parse, STEPS_RECEIVER_SOURCE));
  return (
    `<meta name="mf-projection" content="1" />${STARTUP_BANNERS}` +
    `<div class="bar"><input id="stepsFilter" type="search" /><select id="insertAction"></select>` +
    `<button id="addAction" disabled>Add</button><button id="pickSample">Pick</button>` +
    `<button id="test">Test</button><button id="openText">Code</button></div>` +
    rows +
    renderStepsContextMenuHtml()
  );
}

/** The page's two scripts in the provider's order: the inline guard and shape helpers, then the file. */
export function stepsReceiverScripts(token: string): [string, string] {
  return [`${guardScript(token)}\n${SHAPE_HELPERS}`, STEPS_JS];
}

/** The same two scripts joined, for a loader that runs one script. */
export function stepsReceiverScript(token: string): string {
  return stepsReceiverScripts(token).join("\n");
}
