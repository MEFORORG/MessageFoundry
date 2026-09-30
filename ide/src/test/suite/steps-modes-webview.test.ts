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
  KeyboardEvent: new (type: string, init?: Record<string, unknown>) => unknown;
  FocusEvent: new (type: string, init?: Record<string, unknown>) => unknown;
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

/** Focus leaving `from` for `to` (null: out of the page), as a browser reports it. */
function leave(p: Page, from: DomNode, to: DomNode | null): void {
  const target = from.querySelector(".tpart-input") ?? from;
  target.dispatchEvent(new p.window.FocusEvent("focusout", { bubbles: true, relatedTarget: to }));
}

/** Click an editor's Add button and return the chip it added (the last chip). */
function addChipBy(p: Page, box: DomNode, button: string): DomNode {
  click(p, box.querySelector(button));
  const chips = box.querySelectorAll(".tpart");
  return chips[chips.length - 1];
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

  test("a template is written once, when focus leaves its editor, with the row's coordinates", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const field = p.field(7, "value");
    const inputs = field.querySelectorAll(CHIP_INPUTS);
    const before = p.posted.length;
    change(p, inputs[0], "ID ");
    change(p, inputs[2], " - ");
    assert.deepStrictEqual(sent(p, before), [], "typing across chips writes nothing yet");
    // Moving between chips of the same editor is still one pass.
    leave(p, field.querySelector(".tparts"), inputs[1]);
    assert.deepStrictEqual(sent(p, before), [], "focus moving inside the editor does not end the pass");
    leave(p, field.querySelector(".tparts"), null);
    const msgs = sent(p, before);
    assert.strictEqual(msgs.length, 1, "one write for the whole pass");
    const read = readEditMessage(msgs[0]);
    assert.ok(read && "edit" in read, "the provider's guard accepts the posted template");
    assert.deepStrictEqual(read.edit, {
      command: "edit",
      handler: "h",
      lineStart: 7,
      lineEnd: 7,
      name: "value",
      value: { parts: [{ text: "ID " }, { path: "PID-3.1" }, { text: " - " }, { path: "PID-5.1" }] },
      expectSrc: LINES[6],
    });
    // Nothing changed since: leaving again writes nothing.
    leave(p, field.querySelector(".tparts"), null);
    assert.strictEqual(sent(p, before).length, 1);
  });

  test("Enter in a chip ends the pass and writes", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const input = p.field(7, "value").querySelectorAll(CHIP_INPUTS)[1];
    const before = p.posted.length;
    input.value = "PID-3.4";
    input.dispatchEvent(new p.window.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    const [msg] = sent(p, before);
    assert.deepStrictEqual((msg.value as { parts: unknown[] }).parts[1], { path: "PID-3.4" });
    assert.ok(!JSON.stringify(msg).includes("msg["), "no source is ever built in the webview");
  });

  test("a pass with no field, or an empty one, is held back with a hint, not sent", () => {
    const p = loadPage([STATIC_VALUE]);
    const field = p.field(6, "value");
    change(p, field.querySelector("select.mode-select"), "templated");
    const box = field.querySelector(".tparts");
    const hint = box.querySelector(".tpart-hint");
    assert.strictEqual(hint.hidden, true);
    const before = p.posted.length;
    // Only text: the engine would refuse it, and its refusal would re-project the page.
    change(p, box.querySelectorAll(CHIP_INPUTS)[0], "Mr SMITH");
    leave(p, box, null);
    assert.deepStrictEqual(sent(p, before), [], "a template with no field is not sent");
    assert.strictEqual(hint.hidden, false, "the hint says why");
    // Typing a path into a new field chip completes it; the pass is then written.
    const chip = addChipBy(p, box, ".tpart-add-path");
    const pickReq = sent(p, before);
    assert.strictEqual(pickReq.length, 1, "Add field asks for a pick");
    change(p, chip.querySelector(".tpart-input"), "");
    leave(p, box, null);
    assert.strictEqual(sent(p, before).length, 1, "an empty field is held back too");
    assert.strictEqual(hint.hidden, false);
    change(p, chip.querySelector(".tpart-input"), "PID-3");
    leave(p, box, null);
    const msgs = sent(p, before);
    assert.strictEqual(msgs.length, 2);
    assert.deepStrictEqual(msgs[1].value, { parts: [{ text: "Mr SMITH" }, { path: "PID-3" }] });
    assert.strictEqual(hint.hidden, true);
  });

  test("removing a part writes the template without it", () => {
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
    change(p, field.querySelectorAll(CHIP_INPUTS)[0], "UNSAVED ");
    const before = p.posted.length;
    click(p, field.querySelectorAll(".tpart")[3].querySelector(".tpart-pick"));
    const msgs = sent(p, before);
    assert.strictEqual(msgs.length, 1, "the pick posts one request and no racing edit");
    const pick = readPickPartMessage(msgs[0]);
    assert.ok(pick, "the provider's guard accepts the pick request");
    assert.strictEqual(pick.index, 3);
    assert.deepStrictEqual(pick.parts[0], { text: "UNSAVED " });
    // The pick's write carries the pass, so leaving afterwards writes nothing more.
    leave(p, field.querySelector(".tparts"), null);
    assert.strictEqual(sent(p, before).length, 1);
  });

  test("Add field adds an empty field chip and asks the picker to fill it", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const box = p.field(7, "value").querySelector(".tparts");
    const before = p.posted.length;
    addChipBy(p, box, ".tpart-add-path");
    const pick = readPickPartMessage(sent(p, before)[0]);
    assert.ok(pick, "the provider's guard accepts it: the index names the new empty path part");
    assert.strictEqual(pick.index, 4);
    assert.deepStrictEqual(pick.parts[4], { path: "" });
    assert.strictEqual(box.querySelectorAll(".tpart").length, 5, "the chip stays for a typed path");
  });

  test("Add text adds an empty chip and writes nothing until the pass ends", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const box = p.field(7, "value").querySelector(".tparts");
    const before = p.posted.length;
    const chip = addChipBy(p, box, ".tpart-add-text");
    assert.deepStrictEqual(sent(p, before), [], "adding an empty chip writes nothing");
    assert.strictEqual(chip.dataset.part, "text");
    change(p, chip.querySelector(".tpart-input"), " end");
    leave(p, box, null);
    const [msg] = sent(p, before);
    assert.deepStrictEqual((msg.value as { parts: unknown[] }).parts[4], { text: " end" });
  });

  test("a part button's mousedown keeps the focus, so a click never ends the pass first", () => {
    const p = loadPage([TEMPLATED_VALUE]);
    const btn = p.field(7, "value").querySelector(".tpart-add-path");
    const down = new p.window.MouseEvent("mousedown", { bubbles: true, cancelable: true }) as DomNode;
    btn.dispatchEvent(down);
    assert.strictEqual(down.defaultPrevented, true);
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
    addChipBy(p, field.querySelector(".tparts"), ".tpart-add-path");
    const pick = readPickPartMessage(sent(p, before)[0]);
    assert.ok(pick);
    assert.deepStrictEqual(pick.parts, [{ text: "SMITH" }, { path: "" }]);
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
