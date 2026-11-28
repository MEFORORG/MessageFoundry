// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  EditLoopGuard,
  QueuedEditRebaser,
  drainEdits,
  drainHeldEdits,
  physicalLines,
  readEditMessage,
  readPickPartMessage,
  type AppliedRewrite,
  type EditMessage,
  type RowSourceAck,
} from "../../stepsModel";
import { CHANNEL_FIELD } from "../../webviewMessaging";
import { StepsPanelProjection } from "../../stepsPanel";
import { stepsReceiverBody, stepsReceiverScripts } from "./steps-receiver-page";

// BACKLOG #5943, the remainder: a typed edit queued behind a field pick was sent with its projected
// source, and the rebaser's pruning, which ordered buffers by last use, could drop the buffer of the
// projection the page shows. Both fell back to the engine's stale refusal. And the host could not tell
// which writes a page had shown, so it could not carry an edit over them without guessing: the page
// now receives a row-source acknowledgement after each typed write it already shows, and stamps its
// edits with the version it applied.
//
// The fake engine keeps the F7 guard: it refuses an edit whose expectSrc is not the live row. The row
// has two params, so an edit of one can be told from an edit of the other.

const ROW = (p: string, v: string): string => `    msg.set("${p}", "${v}")`;

function source(p = "PID-5", v = "OLD"): string {
  return ["@handler", "def h(msg):", ROW(p, v), "    return msg"].join("\n");
}

class FakeEditor {
  text: string;
  readonly refused: string[] = [];
  readonly applied: string[] = [];
  readonly acks: RowSourceAck[] = [];
  readonly rebaser = new QueuedEditRebaser();
  private gate: Promise<void> | undefined;
  private open: (() => void) | undefined;

  constructor(text: string) {
    this.text = text;
    this.rebaser.project(1, text);
  }

  hold(): void {
    this.gate = new Promise<void>((resolve) => {
      this.open = resolve;
    });
  }

  release(): void {
    this.open?.();
  }

  get rebase(): { rebaser: QueuedEditRebaser; readSource: () => string; onAck: (a: RowSourceAck) => void } {
    return { rebaser: this.rebaser, readSource: () => this.text, onAck: (a) => void this.acks.push(a) };
  }

  apply = async (msg: EditMessage): Promise<AppliedRewrite | void> => {
    const before = this.text;
    const gate = this.gate;
    this.gate = undefined;
    if (gate) {
      await gate;
    }
    const lines = physicalLines(before);
    const row = lines.slice(msg.lineStart - 1, msg.lineEnd).join("\n");
    if (msg.expectSrc !== undefined && msg.expectSrc !== row) {
      this.refused.push(String(msg.value));
      return undefined;
    }
    const m = /msg\.set\("([^"]*)", "([^"]*)"\)/.exec(row);
    assert.ok(m, `the fake row is not a set call: ${row}`);
    lines[msg.lineStart - 1] = msg.name === "path" ? ROW(String(msg.value), m[2]) : ROW(m[1], String(msg.value));
    const after = lines.join("\n");
    this.text = after;
    this.applied.push(String(msg.value));
    return { before, after };
  };
}

function edit(value: string, name = "value", expectSrc = ROW("PID-5", "OLD"), projection = 1): EditMessage {
  return { command: "edit", handler: "h", lineStart: 3, lineEnd: 3, name, value, expectSrc, projection };
}

/** Run `msg` through the field-picker drain, with the slot claimed the way applyPickedEdit claims it. */
async function pick(guard: EditLoopGuard, ed: FakeEditor, msg: EditMessage): Promise<void> {
  assert.ok(guard.beginEdit(), "the pick claims the slot");
  await drainHeldEdits(guard, msg, "pick", ed.apply, undefined, undefined, ed.rebase);
}

suite("Steps edit -- the field-picker drain carries a queued typed edit over the pick (BACKLOG #5943)", () => {
  test("a typed edit of another param, queued behind a pick, is sent with the pick's row", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const picking = pick(guard, ed, edit("PID-7", "path"));
    // Typed on the same page while the pick's lens rewrite was in flight.
    await drainEdits(guard, edit("NEW"), ed.apply, undefined, undefined, ed.rebase);
    ed.release();
    await picking;
    assert.deepStrictEqual(ed.refused, [], "the queued typed edit is not refused as stale");
    assert.deepStrictEqual(ed.applied, ["PID-7", "NEW"]);
    assert.strictEqual(ed.text, source("PID-7", "NEW"), "both the picked path and the typed value stand");
    assert.strictEqual(guard.isEditing, false);
  });

  test("a typed edit of the picked param is sent as posted: the page never showed the pick", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const picking = pick(guard, ed, edit("PID-7", "path"));
    await drainEdits(guard, edit("PID-9", "path"), ed.apply, undefined, undefined, ed.rebase);
    ed.release();
    await picking;
    assert.deepStrictEqual(ed.refused, ["PID-9"], "rebasing it would write a value typed over the pre-pick path");
    assert.strictEqual(ed.text, source("PID-7", "OLD"));
  });

  test("a pick is carried over the same page's typed write of either param, never another page's", async () => {
    // Review round 1 finding 3: a pick replaces the param with a value the page's own field seeded, so
    // a typed write of that param from the same page is one the pick already saw.
    for (const name of ["value", "path"]) {
      const ed = new FakeEditor(source());
      const guard = new EditLoopGuard();
      await drainEdits(guard, edit("TYPED", name), ed.apply, undefined, undefined, ed.rebase);
      // The pick was requested on the same page after that write, before it was re-projected.
      await pick(guard, ed, { ...edit("PID-7", "path"), arrival: ed.rebaser.arrive() });
      assert.deepStrictEqual(ed.refused, [], `a pick after a typed ${name} write`);
      assert.deepStrictEqual(ed.applied, ["TYPED", "PID-7"]);
    }
    // The control: the typed write came from projection 1, and the pick from projection 2, whose page
    // was projected before that write landed, so it never showed it.
    const ed = new FakeEditor(source());
    const at = ed.rebaser.mark(source());
    ed.rebaser.project(2, source(), at);
    const guard = new EditLoopGuard();
    await drainEdits(guard, edit("TYPED", "path"), ed.apply, undefined, undefined, ed.rebase);
    await pick(guard, ed, { ...edit("PID-7", "path", ROW("PID-5", "OLD"), 2), arrival: ed.rebaser.arrive() });
    assert.deepStrictEqual(ed.refused, ["PID-7"]);
  });

  test("a pick is not carried over a typed write of its param that arrived after the pick request", async () => {
    // Review round 2 finding 1: the user types into the field while the picker is open. The pick's
    // value was built from what the page held at the request, so carrying it would revert the typing.
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    const request = ed.rebaser.arrive(); // the pick request arrives, and the picker opens
    await drainEdits(guard, edit("TYPED", "path"), ed.apply, undefined, undefined, ed.rebase);
    await pick(guard, ed, { ...edit("PID-7", "path"), arrival: request });
    assert.deepStrictEqual(ed.refused, ["PID-7"], "refused as stale, as on main, never written over the typing");
    assert.strictEqual(ed.text, source("TYPED"));
  });

  test("a typed edit is checked against a pick even when the pick's output repeats an earlier buffer", async () => {
    // c2 round 2 finding 4: positions, not buffer text, decide which writes an edit is carried over.
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    await drainEdits(guard, edit("A"), ed.apply, undefined, undefined, ed.rebase);
    await drainEdits(guard, edit("OLD", "value", ROW("PID-5", "A")), ed.apply, undefined, undefined, ed.rebase);
    assert.strictEqual(ed.text, source(), "the value was typed back: the buffer repeats the projected one");
    await pick(guard, ed, edit("P", "value", ROW("PID-5", "OLD")));
    assert.strictEqual(ed.text, source("PID-5", "P"));
    // Typed on the page before the pick landed: it shows OLD for the value, never P.
    await drainEdits(guard, edit("B"), ed.apply, undefined, undefined, ed.rebase);
    assert.deepStrictEqual(ed.refused, ["B"], "not carried over the pick of its own param");
    assert.strictEqual(ed.text, source("PID-5", "P"));
  });
});

suite("Steps edit -- the rebaser keeps the shown projection's buffer by position (BACKLOG #5943)", () => {
  // Two renders that finish out of order: R2 reads the buffer after write A, R3 reads it after write B
  // and finishes first. The page left showing is R2's, which shows A but not B.
  function outOfOrder(): { r: QueuedEditRebaser; b1: string; b2: string } {
    const r = new QueuedEditRebaser();
    const b0 = source();
    const b1 = source("PID-5", "A");
    const b2 = source("PID-5", "B");
    r.project(1, b0);
    r.record(edit("A"), { before: b0, after: b1 }, "typed");
    const r2 = r.mark(b1); // render R2 reads the buffer, then awaits its parse
    r.record(edit("B", "value", ROW("PID-5", "A")), { before: b1, after: b2 }, "typed");
    r.project(2, b2, r.mark(b2)); // render R3 finishes first
    r.project(3, b1, r2); // R2 finishes last: the page shows projection 3, projected from b1
    return { r, b1, b2 };
  }

  test("an edit of another param from the page the late render left is carried, not refused", () => {
    // On main the pruning ordered buffers by last use and deleted b1 here, so this was refused.
    const { r, b2 } = outOfOrder();
    const msg = edit("PID-7", "path", ROW("PID-5", "A"), 3);
    assert.strictEqual(r.rebase(msg, () => b2).expectSrc, ROW("PID-5", "B"));
  });

  test("an edit of the param that page does not show the latest value of is sent as posted", () => {
    // c2 round 2 finding 3: write B came from projection 1, and projection 3 still shows A.
    const { r, b2 } = outOfOrder();
    const msg = edit("C", "value", ROW("PID-5", "A"), 3);
    assert.strictEqual(r.rebase(msg, () => b2), msg);
  });

  test("the projection before keeps its base, and one projection further back is dropped", () => {
    const { r, b2 } = outOfOrder();
    const fromTwo = edit("C", "value", ROW("PID-5", "B"), 2);
    assert.strictEqual(r.rebase(fromTwo, () => b2), fromTwo, "nothing written since its base: as posted");
    const fromOne = edit("C");
    assert.strictEqual(r.rebase(fromOne, () => b2), fromOne, "projection 1 is no longer kept");
  });

  test("a mark taken before the chain was replaced does not name a position in the new chain", () => {
    const r = new QueuedEditRebaser();
    const b0 = source();
    const b1 = source("PID-5", "A");
    r.project(1, b0);
    const stale = r.mark(b0);
    r.latch();
    r.project(2, b1, stale); // b1 is not the end of any chain: a new chain starts there
    r.record(edit("X", "value", ROW("PID-5", "A"), 2), { before: b1, after: source("PID-5", "X") }, "typed");
    const msg = edit("Y", "path", ROW("PID-5", "A"), 2);
    assert.strictEqual(r.rebase(msg, () => source("PID-5", "X")).expectSrc, ROW("PID-5", "X"));
  });
});

suite("Steps edit -- the row-source acknowledgement (BACKLOG #5943)", () => {
  test("a typed write from the page shown is acknowledged with the row as the page holds it and after", () => {
    const ed = new FakeEditor(source());
    const r = ed.rebaser;
    const a1 = r.record(edit("A"), { before: source(), after: source("PID-5", "A") }, "typed");
    assert.ok(a1);
    assert.deepStrictEqual(
      { from: a1.from, to: a1.to, projection: a1.projection, line: a1.lineStart, command: a1.command },
      { from: ROW("PID-5", "OLD"), to: ROW("PID-5", "A"), projection: 1, line: 3, command: "rowSource" },
    );
    const a2 = r.record(edit("B", "value", ROW("PID-5", "A")), {
      before: source("PID-5", "A"),
      after: source("PID-5", "B"),
    }, "typed");
    assert.ok(a2);
    assert.strictEqual(a2.from, ROW("PID-5", "A"), "the next one starts from the row the first one gave the page");
    assert.ok(a2.version > a1.version);
    // An edit stamped with a version the page applied, carrying that version's row.
    const stamped: EditMessage = { ...edit("C", "path", ROW("PID-5", "A")), rowVer: a1.version };
    assert.strictEqual(r.rebase(stamped, () => source("PID-5", "B")).expectSrc, ROW("PID-5", "B"));
  });

  test("a version the host never sent that page, for that row, is not trusted", () => {
    const r = new QueuedEditRebaser();
    r.project(1, source());
    const a1 = r.record(edit("A"), { before: source(), after: source("PID-5", "A") }, "typed");
    assert.ok(a1);
    const live = (): string => source("PID-5", "A");
    for (const forged of [
      { ...edit("C", "path", ROW("PID-5", "A")), rowVer: a1.version + 7 },
      { ...edit("C", "path", ROW("PID-5", "A"), 2), rowVer: a1.version },
      { ...edit("C", "path", ROW("PID-5", "A")), lineStart: 4, lineEnd: 4, rowVer: a1.version },
    ]) {
      assert.strictEqual(r.rebase(forged, live), forged);
    }
  });

  test("no acknowledgement for a pick, for an older page's write, or over a write the page did not show", () => {
    const r = new QueuedEditRebaser();
    r.project(1, source());
    assert.strictEqual(r.record(edit("PID-7", "path"), { before: source(), after: source("PID-7") }, "pick"), undefined);
    // A typed write of another param after the pick: the page still does not show the picked path.
    const after = source("PID-7", "A");
    assert.strictEqual(
      r.record(edit("A", "value", ROW("PID-7", "OLD")), { before: source("PID-7"), after }, "typed"),
      undefined,
    );
    // A write from projection 1 after projection 2 is shown is not acknowledged to either.
    r.project(2, after);
    const after2 = source("PID-7", "B");
    assert.strictEqual(r.record(edit("B", "value", ROW("PID-7", "A")), { before: after, after: after2 }, "typed"), undefined);
    // Nor is projection 2's own write after it: page 2 never showed projection 1's value B.
    const after3 = source("PID-7", "C");
    assert.strictEqual(r.record(edit("C", "value", ROW("PID-7", "B"), 2), { before: after2, after: after3 }, "typed"), undefined);
    // Once a page is projected from that buffer, its own typed write is acknowledged from its base.
    r.project(3, after3);
    const own = r.record(edit("D", "value", ROW("PID-7", "C"), 3), { before: after3, after: source("PID-7", "D") }, "typed");
    assert.ok(own, "projection 3's own typed write is acknowledged");
    assert.strictEqual(own.from, ROW("PID-7", "C"), "from the row projection 3 was projected with");
  });

  test("drainEdits posts the acknowledgement, and a throwing poster latches the rebase off", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    await drainEdits(guard, edit("A"), ed.apply, undefined, undefined, ed.rebase);
    assert.strictEqual(ed.acks.length, 1);
    const logged: string[] = [];
    const throwing = {
      rebaser: ed.rebaser,
      readSource: () => ed.text,
      log: (t: string) => void logged.push(t),
      onAck: (): void => {
        throw new Error("panel gone");
      },
    };
    await drainEdits(guard, edit("B", "value", ROW("PID-5", "A")), ed.apply, undefined, undefined, throwing);
    assert.ok(logged.some((t) => t.includes("panel gone")));
    const next = edit("C", "path", ROW("PID-5", "A"));
    assert.strictEqual(ed.rebaser.rebase(next, () => ed.text), next, "latched: sent as posted");
    assert.strictEqual(guard.isEditing, false);
  });

  test("the page's stamp is read from an edit and a pick request, and a malformed one is dropped", () => {
    const base = { command: "edit", handler: "h", lineStart: 3, lineEnd: 3, name: "value", value: "A", expectSrc: "x" };
    const read = readEditMessage({ ...base, projection: 2, rowVer: 5, arrival: 1 });
    assert.ok(read && "edit" in read);
    assert.strictEqual(read.edit.rowVer, 5);
    assert.strictEqual(read.edit.projection, 2);
    assert.strictEqual(read.edit.arrival, undefined, "the arrival order is the provider's, never the page's");
    for (const bad of ["5", 1.5, Number.NaN, null]) {
      const r = readEditMessage({ ...base, rowVer: bad });
      assert.ok(r && "edit" in r);
      assert.strictEqual(r.edit.rowVer, undefined, `rowVer ${String(bad)}`);
    }
    const pickPart = readPickPartMessage({
      ...base,
      command: "pickPart",
      parts: [{ path: "PID-3" }],
      index: 0,
      projection: 4,
      rowVer: 9,
    });
    assert.ok(pickPart);
    assert.strictEqual(pickPart.projection, 4);
    assert.strictEqual(pickPart.rowVer, 9);
  });
});

// ---- the page: its one receiver, under jsdom -------------------------------------------------------

interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib (see steps-mirror.test.ts).
  [key: string]: any;
}
interface JsdomWindow {
  document: DomNode;
  origin: string;
  MessageEvent: new (type: string, init?: Record<string, unknown>) => unknown;
  Event: new (type: string, init?: Record<string, unknown>) => unknown;
  dispatchEvent(event: unknown): boolean;
  close(): void;
  [key: string]: unknown;
}
interface JsdomModule {
  JSDOM: new (html: string, options?: Record<string, unknown>) => { window: JsdomWindow };
  VirtualConsole: new () => { on(event: string, handler: (...args: unknown[]) => void): void };
}
const { JSDOM, VirtualConsole } = require("jsdom") as JsdomModule;

const TOKEN = "STEPStokenSTEPStokenST00";
interface StepsPage {
  window: JsdomWindow;
  posted: Record<string, unknown>[];
  warnings: string[];
  errors: unknown[];
  deliver(data: Record<string, unknown>, token?: string): void;
  field(name: string): DomNode;
}

const opened: JsdomWindow[] = [];

function loadSteps(): StepsPage {
  const errors: unknown[] = [];
  const warnings: string[] = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e: unknown) => errors.push(e));
  vc.on("warn", (...args: unknown[]) => warnings.push(args.map(String).join(" ")));
  const dom = new JSDOM(`<!DOCTYPE html><body>${stepsReceiverBody()}</body>`, {
    runScripts: "dangerously",
    virtualConsole: vc,
    url: "https://localhost/",
  });
  const window = dom.window;
  opened.push(window);
  const posted: Record<string, unknown>[] = [];
  window.acquireVsCodeApi = () => ({
    getState: () => null,
    setState: () => undefined,
    postMessage: (m: Record<string, unknown>) => void posted.push(m),
  });
  // Two script elements, as the provider serves them: the inline guard, then the static file.
  for (const text of stepsReceiverScripts(TOKEN)) {
    const el = window.document.createElement("script");
    el.textContent = text;
    window.document.body.appendChild(el);
  }
  assert.deepStrictEqual(errors.map(String), [], "the Steps page threw while loading");
  return {
    window,
    posted,
    warnings,
    errors,
    deliver(data, token = TOKEN): void {
      window.dispatchEvent(
        new window.MessageEvent("message", { origin: window.origin, source: null, data: { ...data, [CHANNEL_FIELD]: token } }),
      );
    },
    field: (name) => window.document.querySelector(`input.edit[data-name="${name}"]`),
  };
}

suite("Steps page -- the row-source receiver (BACKLOG #5943)", () => {
  teardown(() => {
    for (const w of opened.splice(0)) {
      w.close();
    }
  });

  const ack = (from: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({
    command: "rowSource",
    projection: 1,
    handler: "h",
    lineStart: 2,
    lineEnd: 2,
    from,
    to: '    msg.set_field("PID-3", "B")',
    version: 4,
    ...over,
  });

  test("an acknowledgement moves the row's source and version, and the next edit echoes both", () => {
    const p = loadSteps();
    const value = p.field("value");
    assert.ok(value, "the row renders an editable value field");
    const from = value.dataset.expectSrc as string;
    p.deliver(ack(from));
    assert.deepStrictEqual(p.errors.map(String), []);
    for (const el of p.window.document.querySelectorAll('[data-line-start="2"][data-expect-src]')) {
      assert.strictEqual(el.dataset.expectSrc, '    msg.set_field("PID-3", "B")');
      assert.strictEqual(el.dataset.rowVer, "4");
    }
    const pathField = p.field("path");
    pathField.value = "PID-9";
    pathField.dispatchEvent(new p.window.Event("change"));
    const sent = p.posted.filter((m) => m.command === "edit");
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0].expectSrc, '    msg.set_field("PID-3", "B")');
    assert.strictEqual(sent[0].rowVer, 4);
    assert.strictEqual(sent[0].projection, 1);
  });

  test("an acknowledgement moves the selection's source too, so a delete of the row carries it", () => {
    const p = loadSteps();
    const row = p.window.document.querySelector('li.row[data-line-start="2"]');
    row.dispatchEvent(new p.window.Event("click", { bubbles: true }));
    p.deliver(ack(row.dataset.expectSrc as string));
    p.window.document.querySelector('#stepsCtxMenu .ctx-item[data-cmd="deleteRow"]').click();
    const del = p.posted.filter((m) => m.command === "deleteRow");
    assert.strictEqual(del.length, 1);
    assert.strictEqual(del[0].expectSrc, '    msg.set_field("PID-3", "B")');
  });

  test("an edit posted before any acknowledgement carries no version", () => {
    const p = loadSteps();
    const pathField = p.field("path");
    pathField.value = "PID-9";
    pathField.dispatchEvent(new p.window.Event("change"));
    const sent = p.posted.filter((m) => m.command === "edit");
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0].rowVer, undefined);
  });

  test("one for another projection, another row, or a row that no longer reads `from` changes nothing", () => {
    const p = loadSteps();
    const from = p.field("value").dataset.expectSrc as string;
    const before = p.window.document.body.innerHTML;
    for (const over of [{ projection: 2 }, { lineStart: 3, lineEnd: 3 }, { handler: "other" }, { from: `${from}x` }]) {
      p.deliver(ack(from, over));
    }
    assert.strictEqual(p.window.document.body.innerHTML, before);
    assert.deepStrictEqual(p.warnings, [], "a well-formed acknowledgement is never reported as discarded");
  });

  test("an unstamped or wrongly stamped one is ignored, and a malformed one is discarded and reported", () => {
    const p = loadSteps();
    const from = p.field("value").dataset.expectSrc as string;
    const before = p.window.document.body.innerHTML;
    p.deliver(ack(from), "not-the-token");
    assert.strictEqual(p.window.document.body.innerHTML, before);
    assert.deepStrictEqual(p.warnings, []);
    p.deliver(ack(from, { version: "4" }));
    assert.strictEqual(p.window.document.body.innerHTML, before);
    assert.deepStrictEqual(p.warnings, ["MessageFoundry Steps: discarded a malformed message"]);
  });
});

suite("Steps edit -- the provider wires the acknowledgement and the pick drain (BACKLOG #5943)", () => {
  const read = (...p: string[]): string => fs.readFileSync(path.join(__dirname, "..", "..", "..", ...p), "utf8");

  test("a pick request's arrival is taken before the picker is awaited, and rides on the pick", () => {
    const src = read("src", "stepsView.ts");
    const body = src.slice(src.indexOf("const pickThenApply = async"), src.indexOf("// Undo / redo the document"));
    const arrive = body.indexOf("const arrival = rebaser.arrive();");
    const picker = body.indexOf("await pickHl7Path(");
    assert.ok(arrive >= 0 && picker > arrive, "stamped on receipt, before the modal");
    assert.ok(body.includes('applyPickedEdit({ command: "edit", ...coords, arrival, value: build(picked) })'));
  });

  test("applyPickedEdit drains through the rebasing drain as a pick, never a bare applyOne loop", () => {
    const src = read("src", "stepsView.ts");
    const body = src.slice(src.indexOf("const applyPickedEdit = async"), src.indexOf("const refuseAnchor ="));
    assert.ok(/drainHeldEdits\(\s*guard,\s*msg,\s*"pick",\s*applyOne,/.test(body), "the pick goes through drainHeldEdits");
    assert.ok(/\brebase,\s*\);/.test(body), "with the same rebase the typed drain takes");
    assert.ok(!/takePending\(\)/.test(body), "no second drain loop of its own");
  });

  test("render marks the chain where it reads the buffer, before the parse is awaited", () => {
    const src = read("src", "stepsView.ts");
    const render = src.slice(src.indexOf("const render = async"), src.indexOf("const applyOne = async"));
    const readAt = render.indexOf("const source = document.getText();");
    const mark = render.indexOf("const at = rebaser.mark(source);");
    const parse = render.indexOf("await lensParseStdin(");
    assert.ok(readAt >= 0 && mark > readAt && parse > mark, "the mark is taken with the read, before the await");
    assert.ok(render.includes("rebaser.project(projection, source, at);"));
  });

  test("the acknowledgement is posted with the channel token, only to the projection it names", () => {
    const src = read("src", "stepsView.ts");
    const onAck = src.slice(src.indexOf("onAck: (ack) =>"), src.indexOf("const applyEdit = (msg"));
    assert.ok(onAck.includes("ack.projection === projectionId"));
    assert.ok(onAck.includes("postToWebview(panel.webview,"));
    assert.ok(src.includes("const { nonce: n, token } = openChannel(webview);"));
    assert.ok(/<script nonce="\$\{n\}">\$\{guardScript\(token\)\}/.test(src), "the guard is inline and nonced");
  });

  test("the panel's row record moves with an acknowledgement, so an insert anchor keeps its flags", () => {
    // Review round 1 finding 1: anchorFor matches on the row's source, and the page sends the moved one.
    const panel = new StepsPanelProjection();
    const row = {
      kind: "send" as const,
      lineStart: 3,
      lineEnd: 3,
      nesting: 0,
      expectSrc: "    yield Send('OB')",
      appended: true,
    };
    panel.update({ module: "m", handlers: [] }, [{ handler: "h", rows: [row] } as never]);
    const at = { handler: "h", lineStart: 3, lineEnd: 3, kind: "send" };
    assert.strictEqual(panel.anchorFor({ ...at, expectSrc: "    yield Send('OB2')" })?.appended, false, "control");
    panel.reSource("h", 3, 3, "    something else", "    yield Send('OB2')");
    assert.strictEqual(panel.anchorFor({ ...at, expectSrc: "    yield Send('OB2')" })?.appended, false, "not from `from`");
    panel.reSource("h", 3, 3, "    yield Send('OB')", "    yield Send('OB2')");
    assert.strictEqual(panel.anchorFor({ ...at, expectSrc: "    yield Send('OB2')" })?.appended, true);
    const src = read("src", "stepsView.ts");
    const onAck = src.slice(src.indexOf("onAck: (ack) =>"), src.indexOf("const applyEdit = (msg"));
    assert.ok(onAck.includes("panelState.reSource(ack.handler, ack.lineStart, ack.lineEnd, ack.from, ack.to);"));
  });

  test("every post that writes a row echoes the projection and the row version", () => {
    const js = read("media", "stepsWebview.js");
    assert.strictEqual((js.match(/projection: projectionId\(\)/g) ?? []).length, 3);
    assert.strictEqual((js.match(/rowVer: rowVerOf\(/g) ?? []).length, 3);
  });
});
