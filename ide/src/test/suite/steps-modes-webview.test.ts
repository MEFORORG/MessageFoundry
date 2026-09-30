// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  type LensRow,
  buildRowViewModel,
  readEditMessage,
  readPickPartMessage,
  renderHandlerHtml,
  renderStepsContextMenuHtml,
} from "../../stepsModel";

// BACKLOG #237 step 3: the per-argument mode selector, driven in the REAL `media/stepsWebview.js` under
// jsdom. The markup comes from stepsModel's renderer, the script is the shipped file, and every message
// the page posts is read back through the provider's own guards (readEditMessage, readPickPartMessage),
// so a message the page builds wrong fails here rather than being dropped in the Extension Host.
//
// Node-side only, like steps-mirror.test.ts: no `vscode` import, so it runs on every `ide` CI leg. DOM
// values stay loosely typed because the base tsconfig has no DOM lib (see steps-mirror.test.ts).

interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib.
  [key: string]: any;
}
interface JsdomWindow {
  document: DomNode;
  Event: new (type: string, init?: Record<string, unknown>) => unknown;
  MouseEvent: new (type: string, init?: Record<string, unknown>) => unknown;
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

// Contract-2 rows in the shape the engine sends. The argument payloads match the verbatim engine rows
// in steps-modes.test.ts; the line numbers are this page's own, and each row carries a `suite` so the
// page's row wiring sees siblings.
const STATIC_VALUE: LensRow = {
  kind: "action",
  action: "set_field",
  params: { path: "PID-5.1", value: "SMITH" },
  literal_params: ["path", "value"],
  line_start: 6,
  line_end: 6,
  nesting: 0,
  suite: "5",
  param_modes: { path: "static", value: "static" },
  param_parts: {},
  template_params: ["value"],
};
const TEMPLATED_VALUE: LensRow = {
  kind: "action",
  action: "set_field",
  params: { path: "PID-5.2", value: "f\"MRN {msg['PID-3.1']} / {msg['PID-5.1']}\"" },
  literal_params: ["path"],
  line_start: 7,
  line_end: 7,
  nesting: 0,
  suite: "5",
  param_modes: { path: "static", value: "templated" },
  param_parts: {
    value: [{ text: "MRN " }, { path: "PID-3.1" }, { text: " / " }, { path: "PID-5.1" }],
  },
  template_params: ["value"],
};
const DYNAMIC_VALUE: LensRow = {
  kind: "action",
  action: "set_field",
  params: { path: "PID-5.3", value: 'msg["PID-5.1"] + "x"' },
  literal_params: ["path"],
  line_start: 8,
  line_end: 8,
  nesting: 0,
  suite: "5",
  param_modes: { path: "static", value: "dynamic" },
  param_parts: {},
  template_params: [],
};
// The same shape an engine without Amendment E sends: no mode maps at all.
const NO_MODES: LensRow = {
  kind: "action",
  action: "set_field",
  params: { path: "PID-5.4", value: "JONES" },
  literal_params: ["path", "value"],
  line_start: 9,
  line_end: 9,
  nesting: 0,
  suite: "5",
};

const LINES = Array.from({ length: 12 }, (_v, i) => `    line_${i + 1}("a & b")`);

interface Page {
  window: JsdomWindow;
  doc: DomNode;
  posted: Record<string, unknown>[];
  scriptErrors: unknown[];
  /** The `.field` element of one param of the row at `line`. */
  field(line: number, name: string): DomNode;
}

/** Every page a test opened, closed in teardown so no window outlives its test. */
const OPEN_WINDOWS: JsdomWindow[] = [];

/** Load the shipped webview script over the rendered rows, recording every postMessage. */
function loadPage(rows: LensRow[]): Page {
  const vms = rows.map((r, i) => buildRowViewModel(r, i, LINES));
  const body = renderHandlerHtml({ handler: "h", defLine: 5, role: "handler", rows: vms });
  const shell =
    `<!doctype html><html><head><meta charset="utf-8"></head><body>` +
    `<div class="bar"><input id="stepsFilter" type="search" />` +
    `<select id="insertAction"><option value="">[select item]</option></select>` +
    `<button id="addAction" disabled>Add</button><button id="pickSample">Pick</button>` +
    `<button id="test">Test</button><button id="openText">Code</button></div>` +
    body +
    renderStepsContextMenuHtml() +
    `</body></html>`;
  const scriptErrors: unknown[] = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e: unknown) => scriptErrors.push(e));
  const dom = new JSDOM(shell, { runScripts: "dangerously", virtualConsole, url: "https://localhost/" });
  const window = dom.window;
  const posted: Record<string, unknown>[] = [];
  let state: unknown = undefined;
  window.acquireVsCodeApi = (): Record<string, unknown> => ({
    postMessage: (m: Record<string, unknown>): void => {
      // A structured clone, as the real webview channel makes: nothing the page holds stays linked.
      posted.push(JSON.parse(JSON.stringify(m)) as Record<string, unknown>);
    },
    getState: (): unknown => state,
    setState: (v: unknown): void => {
      state = v;
    },
  });
  OPEN_WINDOWS.push(window);
  const script = window.document.createElement("script");
  script.textContent = WEBVIEW_SRC;
  window.document.body.appendChild(script);
  const doc = window.document;
  return {
    window,
    doc,
    posted,
    scriptErrors,
    field(line: number, name: string): DomNode {
      const li = doc.querySelector(`li.row[data-line-start="${line}"]`);
      assert.ok(li, `no row at line ${line}`);
      const hit = Array.from(li.querySelectorAll(".field") as DomNode[]).find(
        (f: DomNode) => f.querySelector("label")?.textContent === name,
      );
      assert.ok(hit, `no field ${name} on line ${line}`);
      return hit;
    },
  };
}

/** Everything the page posted after `from`, minus its own diagnostics. */
function sent(p: Page, from = 0): Record<string, unknown>[] {
  return p.posted.slice(from).filter((m) => m.command !== "stepsDiag");
}

function change(p: Page, el: DomNode, value?: string): void {
  if (value !== undefined) {
    el.value = value;
  }
  el.dispatchEvent(new p.window.Event("change", { bubbles: true }));
}

function click(p: Page, el: DomNode): void {
  el.dispatchEvent(new p.window.MouseEvent("click", { bubbles: true, cancelable: true }));
}

const CHIP_INPUTS = ".tparts .tpart .tpart-input";

suite("Steps modes webview: the selector and the parts editor post only what the engine accepts", () => {
  teardown(() => {
    for (const w of OPEN_WINDOWS.splice(0)) {
      (w as unknown as { close(): void }).close();
    }
  });

  test("the page loads over moded rows with no script error", () => {
    const p = loadPage([STATIC_VALUE, TEMPLATED_VALUE, DYNAMIC_VALUE, NO_MODES]);
    assert.deepStrictEqual(p.scriptErrors, []);
    const diag = p.posted.filter((m) => m.command === "stepsDiag" && m.level === "error");
    assert.deepStrictEqual(diag, [], "no wiring reported a failure");
  });

  test("editing a text part posts the whole template as parts, with the row's coordinates", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const inputs = p.field(7, "value").querySelectorAll(CHIP_INPUTS);
    const before = p.posted.length;
    change(p, inputs[0], "ID ");
    const msgs = sent(p, before);
    assert.strictEqual(msgs.length, 1);
    const read = readEditMessage(msgs[0]);
    assert.ok(read && "edit" in read, "the provider's guard accepts the posted template");
    assert.deepStrictEqual(read.edit, {
      command: "edit",
      handler: "h",
      lineStart: 7,
      lineEnd: 7,
      name: "value",
      value: { parts: [{ text: "ID " }, { path: "PID-3.1" }, { text: " / " }, { path: "PID-5.1" }] },
      expectSrc: LINES[6],
    });
  });

  test("a typed field path is a {path} part, never Python source", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const inputs = p.field(7, "value").querySelectorAll(CHIP_INPUTS);
    const before = p.posted.length;
    change(p, inputs[1], "PID-3.4");
    const [msg] = sent(p, before);
    assert.deepStrictEqual((msg.value as { parts: unknown[] }).parts[1], { path: "PID-3.4" });
    assert.ok(!JSON.stringify(msg).includes("msg["), "no source is ever built in the webview");
  });

  test("removing a part posts the template without it", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const chips = p.field(7, "value").querySelectorAll(".tpart");
    const before = p.posted.length;
    click(p, chips[2].querySelector(".tpart-del"));
    const [msg] = sent(p, before);
    assert.deepStrictEqual(msg.value, {
      parts: [{ text: "MRN " }, { path: "PID-3.1" }, { path: "PID-5.1" }],
    });
    assert.strictEqual(p.field(7, "value").querySelectorAll(".tpart").length, 3);
  });

  test("a part's field picker asks the provider for that part, carrying unsaved typing", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const field = p.field(7, "value");
    // Typed but not yet committed: the pick must carry it, or the pick's write would drop it.
    field.querySelectorAll(CHIP_INPUTS)[0].value = "UNSAVED ";
    const before = p.posted.length;
    click(p, field.querySelectorAll(".tpart")[3].querySelector(".tpart-pick"));
    const msgs = sent(p, before);
    assert.strictEqual(msgs.length, 1, "the pick posts one request and no racing edit");
    const pick = readPickPartMessage(msgs[0]);
    assert.ok(pick, "the provider's guard accepts the pick request");
    assert.strictEqual(pick.index, 3);
    assert.deepStrictEqual(pick.parts[0], { text: "UNSAVED " });
  });

  test("Add field asks for a new path part at the end", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const before = p.posted.length;
    click(p, p.field(7, "value").querySelector(".tpart-add-path"));
    const pick = readPickPartMessage(sent(p, before)[0]);
    assert.ok(pick);
    assert.strictEqual(pick.index, 4);
    assert.strictEqual(pick.parts.length, 4);
  });

  test("Add text adds an empty chip and posts nothing until the text is committed", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const field = p.field(7, "value");
    const before = p.posted.length;
    click(p, field.querySelector(".tpart-add-text"));
    assert.deepStrictEqual(sent(p, before), [], "adding an empty chip writes nothing");
    const inputs = field.querySelectorAll(CHIP_INPUTS);
    assert.strictEqual(inputs.length, 5);
    change(p, inputs[4], " end");
    const [msg] = sent(p, before);
    assert.deepStrictEqual((msg.value as { parts: unknown[] }).parts[4], { text: " end" });
  });

  test("a part button never selects the row or blurs a typed chip first", () => {
    // The page default-selects the LAST row, so the templated row goes first to start unselected.
    const p = loadPage([TEMPLATED_VALUE, STATIC_VALUE]);
    const row = p.doc.querySelector('li.row[data-line-start="7"]');
    assert.ok(!row.classList.contains("selected"), "the templated row starts unselected");
    const btn = p.field(7, "value").querySelector(".tpart-add-path");
    const down = new p.window.MouseEvent("mousedown", { bubbles: true, cancelable: true }) as DomNode;
    btn.dispatchEvent(down);
    assert.strictEqual(down.defaultPrevented, true, "mousedown on a part button keeps the focus");
    click(p, btn);
    assert.ok(!row.classList.contains("selected"), "a part button click does not select its row");
  });

  test("switching modes only shows the other pane, and writes nothing", () => {
    const p = loadPage([STATIC_VALUE]);
    const field = p.field(6, "value");
    const sel = field.querySelector("select.mode-select");
    const pane = (m: string): DomNode => field.querySelector(`.mode-pane[data-pane="${m}"]`);
    assert.strictEqual(pane("static").hidden, false);
    assert.strictEqual(pane("templated").hidden, true);
    const before = p.posted.length;
    change(p, sel, "templated");
    assert.strictEqual(pane("static").hidden, true);
    assert.strictEqual(pane("templated").hidden, false);
    assert.deepStrictEqual(sent(p, before), [], "a mode switch alone never writes");
    // The templated pane starts from the literal, so the first field pick keeps the text.
    click(p, field.querySelector(".tpart-add-path"));
    const pick = readPickPartMessage(sent(p, before)[0]);
    assert.ok(pick);
    assert.deepStrictEqual(pick.parts, [{ text: "SMITH" }]);
    assert.strictEqual(pick.index, 1);
  });

  test("a templated argument switched to static posts a plain string", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const field = p.field(7, "value");
    change(p, field.querySelector("select.mode-select"), "static");
    const input = field.querySelector('.mode-pane[data-pane="static"] input.edit');
    assert.strictEqual(input.value, "", "the static pane starts empty");
    const before = p.posted.length;
    change(p, input, "SMITH");
    const read = readEditMessage(sent(p, before)[0]);
    assert.ok(read && "edit" in read);
    assert.strictEqual(read.edit.value, "SMITH");
    assert.strictEqual(read.edit.name, "value");
  });

  test("a dynamic argument has no enabled control and posts nothing", () => {
    const p = loadPage([DYNAMIC_VALUE]);
    const field = p.field(8, "value");
    assert.strictEqual(field.querySelector("select, button"), null);
    const inputs = Array.from(field.querySelectorAll("input") as DomNode[]);
    assert.ok(inputs.length === 1 && inputs[0].disabled === true, "one disabled input: its source");
    const before = p.posted.length;
    change(p, inputs[0], "anything");
    assert.deepStrictEqual(sent(p, before), []);
  });

  test("a row with no modes still posts its literal edit exactly as before", () => {
    const p = loadPage([NO_MODES]);
    const field = p.field(9, "value");
    assert.strictEqual(field.querySelector(".mode-select, .mode-tag, .tparts"), null);
    const before = p.posted.length;
    change(p, field.querySelector("input.edit"), "DOE");
    assert.deepStrictEqual(sent(p, before), [
      {
        command: "edit",
        handler: "h",
        lineStart: 9,
        lineEnd: 9,
        name: "value",
        value: "DOE",
        expectSrc: LINES[8],
      },
    ]);
  });
});
