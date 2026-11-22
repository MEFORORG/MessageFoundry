// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { STARTUP_BANNERS } from "../../webviewMessaging";

import {
  addMenuGroups,
  buildHandlerViewModels,
  renderHandlersHtml,
  renderStepsContextMenuHtml,
  type LensHandler,
  type LensParseResult,
  type LensRow,
  type RowDropContext,
} from "../../stepsModel";

// Shared fixtures and a jsdom page loader for the batch 622 group g09 Steps tests (BACKLOG #5830,
// #5838-#5842). Not a test file itself: mocha only loads `*.test.js`. Node-side only, like
// steps-mirror.test.ts: DOM values stay loosely typed because the base tsconfig has no DOM lib.

export interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib (see steps-mirror.test.ts).
  [key: string]: any;
}
interface JsdomWindow {
  document: DomNode;
  MouseEvent: new (type: string, init?: Record<string, unknown>) => unknown;
  Event: new (type: string, init?: Record<string, unknown>) => unknown;
  [key: string]: unknown;
}
interface JsdomModule {
  JSDOM: new (html: string, options?: Record<string, unknown>) => { window: JsdomWindow };
  VirtualConsole: new () => { on(event: string, handler: (err: unknown) => void): void };
}
const { JSDOM, VirtualConsole } = require("jsdom") as JsdomModule;

const WEBVIEW_SRC = fs.readFileSync(
  path.join(__dirname, "..", "..", "..", "media", "stepsWebview.js"),
  "utf8",
);

export interface Fixture {
  parse: LensParseResult;
  source: string;
}

function sourceOf(lineCount: number): string {
  return Array.from({ length: lineCount }, (_v, i) => `    stmt_${i + 1}()`).join("\n");
}

function handlerOf(
  name: string,
  defLine: number,
  rows: LensRow[],
  role: "handler" | "router" = "handler",
): LensHandler {
  return { handler: name, module: "m", def_line: defLine, rows, role };
}

function setField(line: number, suite: string, nesting = 0): LensRow {
  return {
    kind: "action",
    action: "set_field",
    line_start: line,
    line_end: line,
    nesting,
    suite,
    params: { path: "PID-3", value: "A" },
    literal_params: ["path", "value"],
  };
}

function send(line: number, suite: string): LensRow {
  return { kind: "send", line_start: line, line_end: line, nesting: 0, suite, outbounds: ["OB_Q"] };
}

/** Two Handlers in one module: `first` (def line 1) and `second` (def line 6). */
export function twoHandlers(): Fixture {
  return {
    parse: {
      module: "m",
      handlers: [
        handlerOf("first", 1, [setField(2, "1"), setField(3, "1"), send(4, "1")]),
        handlerOf("second", 6, [setField(7, "6"), setField(8, "6"), send(9, "6")]),
      ],
    },
    source: sourceOf(9),
  };
}

/** A Router `pick` (def line 1, route row at line 3) and a Handler `H_ONE` (def line 5) in one module. */
export function routerAndHandler(): Fixture {
  const route: LensRow = {
    kind: "route",
    line_start: 3,
    line_end: 3,
    nesting: 0,
    suite: "1",
    handlers: ["H_ONE"],
  };
  return {
    parse: {
      module: "m",
      handlers: [
        handlerOf("pick", 1, [setField(2, "1"), route], "router"),
        handlerOf("H_ONE", 5, [setField(6, "5"), setField(7, "5"), send(8, "5")]),
      ],
    },
    source: sourceOf(8),
  };
}

/** One Handler whose body holds an if (line 2) / else (line 4) block and a for loop (line 6). */
export function withControls(): Fixture {
  const ctrl = (control: "if" | "else" | "for", line: number): LensRow => ({
    kind: "control",
    control,
    line_start: line,
    line_end: line,
    nesting: 0,
    suite: "1",
    test_src: control === "else" ? null : "x",
    recognized: true,
  });
  return {
    parse: {
      module: "m",
      handlers: [
        handlerOf("h", 1, [
          ctrl("if", 2),
          setField(3, "2", 1),
          ctrl("else", 4),
          setField(5, "4", 1),
          ctrl("for", 6),
          setField(7, "6", 1),
          send(8, "1"),
        ]),
      ],
    },
    source: sourceOf(8),
  };
}

/** The model's drop contexts for every row of every handler, each carrying its own handler name. */
export function dropRows(f: Fixture): RowDropContext[] {
  return buildHandlerViewModels(f.parse, f.source).flatMap((h) =>
    h.rows.map((vm) => {
      const draggable = vm.movable === true || vm.kind === "code";
      return {
        handler: h.handler,
        lineStart: vm.lineStart,
        lineEnd: vm.lineEnd,
        nesting: vm.nesting,
        suite: vm.suite ?? "",
        kind: vm.kind,
        draggable,
        isControlHeader: vm.kind === "control" && draggable,
        control: vm.control as RowDropContext["control"],
        appended: vm.appended,
        scaffold: vm.scaffold,
      };
    }),
  );
}

function pageShell(bodyHtml: string): string {
  const options = [`<option value="">[select item]</option>`]
    .concat(
      addMenuGroups().map(
        ({ group, items }) =>
          `<optgroup label="${group}">` +
          items
            .map(
              (item) =>
                `<option value="${item.id}"` +
                (item.anchorConstraint ? ` data-anchor="${item.anchorConstraint}"` : "") +
                `>${item.label}</option>`,
            )
            .join("") +
          `</optgroup>`,
      ),
    )
    .join("");
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>steps</title></head><body>` +
    STARTUP_BANNERS +
    `<div class="bar"><input id="stepsFilter" type="search" />` +
    `<select id="insertAction">${options}</select><button id="addAction" disabled>Add</button>` +
    `<button id="pickSample">Pick</button><button id="test">Test</button>` +
    `<button id="openText">Code</button></div>` +
    bodyHtml +
    renderStepsContextMenuHtml() +
    `</body></html>`
  );
}

export interface Page {
  window: JsdomWindow;
  doc: DomNode;
  hook: Record<string, (...args: any[]) => any>;
  posted: Record<string, unknown>[];
  row(lineStart: number): DomNode;
  rightClick(el: DomNode): void;
  menuItem(selector: string): DomNode;
}

/** Render `f` through the real renderer and run the shipped stepsWebview.js against it under jsdom. */
export function loadPage(f: Fixture): Page {
  const errors: unknown[] = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e: unknown) => errors.push(e));
  const html = renderHandlersHtml(buildHandlerViewModels(f.parse, f.source));
  const dom = new JSDOM(pageShell(html), {
    runScripts: "dangerously",
    virtualConsole: vc,
    url: "https://localhost/",
  });
  const window = dom.window;
  const posted: Record<string, unknown>[] = [];
  let state: unknown = undefined;
  window.acquireVsCodeApi = (): Record<string, unknown> => ({
    postMessage: (m: Record<string, unknown>): void => {
      posted.push(m);
    },
    getState: (): unknown => state,
    setState: (v: unknown): void => {
      state = v;
    },
  });
  window.__mfStepsTestExportsEnabled = true;
  const script = window.document.createElement("script");
  script.textContent = WEBVIEW_SRC;
  window.document.body.appendChild(script);
  const hook = window.__mfStepsTestExports as Record<string, (...args: any[]) => any> | undefined;
  assert.ok(hook, `stepsWebview.js did not load: ${errors.map(String).join(" | ")}`);
  const doc = window.document;
  return {
    window,
    doc,
    hook,
    posted,
    row: (lineStart: number): DomNode => doc.querySelector(`li.row[data-line-start="${lineStart}"]`),
    rightClick: (el: DomNode): void => {
      el.dispatchEvent(
        new window.MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 5, clientY: 5 }),
      );
    },
    menuItem: (selector: string): DomNode => doc.querySelector(`#stepsCtxMenu ${selector}`),
  };
}

/** Rebuild a jsdom-realm value with this realm's prototypes, so deepStrictEqual compares values only.
 * Keeps `undefined`-valued keys, as steps-mirror.test.ts's `plain` does and for the same reason. */
export function plain<T>(value: T): T {
  if (Array.isArray(value)) {
    // Not `.map()`: it would build the result through the jsdom array's own constructor.
    const out: unknown[] = [];
    for (const item of value as unknown[]) {
      out.push(plain(item));
    }
    return out as unknown as T;
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>)) {
      out[key] = plain((value as Record<string, unknown>)[key]);
    }
    return out as unknown as T;
  }
  return value;
}
