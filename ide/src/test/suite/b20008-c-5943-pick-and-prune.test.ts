// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  EditLoopGuard,
  QueuedEditRebaser,
  drainEdits,
  physicalLines,
  readEditMessage,
  readPickPartMessage,
  type AppliedRewrite,
  type EditMessage,
} from "../../stepsModel";
import { loadPage, withControls } from "./b622-g09-steps-page";

// BACKLOG #5943, the two remainders PR 3136 named (#8295 items 42 and 43):
//  42. the field-picker drain sent every typed edit queued behind a pick as posted, so one on the
//      picked row was refused as stale even when only another field changed, or nothing did;
//  43. project() pruned chain buffers by last use, so renders that finished out of order deleted the
//      current projection's own buffer, and its edits fell back to the engine's stale refusal.
// Neither fix rebases an edit on a field that a write its page does not show rewrote: a pick, or a
// typed write made on another page. That edit is still sent as posted and refused, as on main.
// The fake engine below keeps the engine's stale guard: it refuses an edit whose expectSrc does not
// match the live buffer's row, as `lens rewrite` does.

const LINE = 3;

function row(pathValue: string, value: string): string {
  return `    msg.set("${pathValue}", "${value}")`;
}

function source(pathValue = "PID-5", value = "OLD"): string {
  return ["@handler", "def h(msg):", row(pathValue, value), "    return msg"].join("\n");
}

function rowOf(src: string): string {
  return physicalLines(src)[LINE - 1];
}

function edit(name: "path" | "value", value: string, expectSrc: string, projection?: number): EditMessage {
  const msg: EditMessage = { command: "edit", handler: "h", lineStart: LINE, lineEnd: LINE, name, value, expectSrc };
  if (projection !== undefined) {
    msg.projection = projection;
  }
  return msg;
}

/** A fake document plus a fake `lens rewrite` of `msg.set(path, value)` that keeps the stale guard. */
class FakeEditor {
  text: string;
  readonly refused: string[] = [];
  readonly applied: string[] = [];
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

  apply = async (msg: EditMessage): Promise<AppliedRewrite | void> => {
    const before = this.text;
    const gate = this.gate;
    this.gate = undefined;
    if (gate) {
      await gate;
    }
    const lines = physicalLines(before);
    const found = /^ {4}msg\.set\("([^"]*)", "([^"]*)"\)$/.exec(lines[LINE - 1]);
    if (found === null || (msg.expectSrc !== undefined && msg.expectSrc !== lines[LINE - 1])) {
      this.refused.push(`${msg.name}=${String(msg.value)}`);
      return undefined;
    }
    const [, p, v] = found;
    lines[LINE - 1] = msg.name === "path" ? row(String(msg.value), v) : row(p, String(msg.value));
    const after = lines.join("\n");
    this.text = after;
    this.applied.push(`${msg.name}=${String(msg.value)}`);
    return { before, after };
  };

  /** The drain's rebase option. Built as a variable, so an unknown option compiles against any drain. */
  options(firstIsPick: boolean): { rebaser: QueuedEditRebaser; readSource: () => string } {
    const opts = { rebaser: this.rebaser, readSource: (): string => this.text, firstIsPick };
    return opts;
  }
}

/**
 * `first` held in flight while `queued` arrive as typed edits, then the drain runs on. `first` is a
 * field pick ("pick"), a typed edit ("typed"), or a pick under the old pick drain, which had no rebase
 * ("none").
 */
async function drainWithQueued(
  ed: FakeEditor,
  first: EditMessage,
  queued: EditMessage[],
  kind: "pick" | "typed" | "none" = "pick",
): Promise<void> {
  const guard = new EditLoopGuard();
  ed.hold();
  const opts = kind === "none" ? undefined : ed.options(kind === "pick");
  const running = drainEdits(guard, first, ed.apply, undefined, undefined, opts);
  for (const q of queued) {
    await drainEdits(guard, q, ed.apply, undefined, undefined, ed.options(false));
  }
  ed.release();
  await running;
  assert.strictEqual(guard.isEditing, false);
}

suite("b20008 C #5943 item 42 -- a typed edit queued behind a field pick", () => {
  const S0 = source();

  test("the provider's pick drain is drainEdits with firstIsPick, not its own applyOne loop", () => {
    const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "stepsView.ts"), "utf8");
    const start = src.indexOf("const applyPickedEdit = async");
    const end = src.indexOf("const refuseAnchor = ", start);
    assert.ok(start >= 0 && end > start, "applyPickedEdit and the declaration after it were found");
    const body = src.slice(start, end);
    assert.ok(/await drainEdits\(/.test(body), "the pick drain runs through drainEdits");
    assert.ok(/firstIsPick: true/.test(body), "the pick is marked as the drain's first edit");
    assert.ok(!/await applyOne\(/.test(body), "no queued edit is sent past the rebaser");
  });

  test("a typed edit on another field of the picked row is carried over the pick", async () => {
    const ed = new FakeEditor(S0);
    await drainWithQueued(ed, edit("path", "PID-9", rowOf(S0), 1), [edit("value", "NEW", rowOf(S0), 1)]);
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["path=PID-9", "value=NEW"]);
    assert.strictEqual(rowOf(ed.text), row("PID-9", "NEW"));
  });

  test("control: the old pick drain, with no rebase, refuses that same edit as stale", async () => {
    const ed = new FakeEditor(S0);
    await drainWithQueued(ed, edit("path", "PID-9", rowOf(S0), 1), [edit("value", "NEW", rowOf(S0), 1)], "none");
    assert.deepStrictEqual(ed.refused, ["value=NEW"]);
  });

  test("a typed edit on the picked field itself is sent as posted, so the pick is not written over", async () => {
    const ed = new FakeEditor(S0);
    await drainWithQueued(ed, edit("path", "PID-9", rowOf(S0), 1), [edit("path", "PID-5", rowOf(S0), 1)]);
    assert.deepStrictEqual(ed.applied, ["path=PID-9"]);
    assert.deepStrictEqual(ed.refused, ["path=PID-5"]);
    assert.strictEqual(rowOf(ed.text), row("PID-9", "OLD"));
  });

  test("a pick that wrote nothing still lets the queued edit carry over an earlier typed rewrite", async () => {
    const ed = new FakeEditor(S0);
    await drainEdits(new EditLoopGuard(), edit("value", "A", rowOf(S0), 1), ed.apply, undefined, undefined, ed.options(false));
    assert.deepStrictEqual(ed.applied, ["value=A"]);
    // The pick was made on the page from before that rewrite, so the engine refuses it as stale.
    await drainWithQueued(ed, edit("path", "PID-9", rowOf(S0), 1), [edit("value", "B", rowOf(S0), 1)]);
    assert.deepStrictEqual(ed.refused, ["path=PID-9"]);
    assert.deepStrictEqual(ed.applied, ["value=A", "value=B"]);
  });

  test("the pick itself is sent as posted, never carried over an earlier rewrite", async () => {
    const ed = new FakeEditor(S0);
    await drainEdits(new EditLoopGuard(), edit("value", "A", rowOf(S0), 1), ed.apply, undefined, undefined, ed.options(false));
    await drainWithQueued(ed, edit("path", "PID-9", rowOf(S0), 1), []);
    assert.deepStrictEqual(ed.refused, ["path=PID-9"]);
  });

  test("an edit on the picked field from a projection made after the pick is carried as usual", async () => {
    const ed = new FakeEditor(S0);
    await drainWithQueued(ed, edit("path", "PID-9", rowOf(S0), 1), []);
    const S1 = ed.text;
    ed.rebaser.project(2, S1);
    await drainWithQueued(ed, edit("value", "X", rowOf(S1), 2), [edit("path", "PID-7", rowOf(S1), 2)], "typed");
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["path=PID-9", "value=X", "path=PID-7"]);
  });

  test("a page projected from a pre-pick buffer after the pick still cannot rebase over the pick", async () => {
    const ed = new FakeEditor(S0);
    await drainWithQueued(ed, edit("path", "PID-9", rowOf(S0), 1), []);
    ed.rebaser.project(2, ed.text);
    ed.rebaser.project(3, S0); // a render that read the buffer before the pick finished last
    const S1 = ed.text;
    const onPicked = edit("path", "PID-5", rowOf(S0), 3);
    assert.strictEqual(ed.rebaser.rebase(onPicked, () => S1), onPicked, "the picked field is sent as posted");
    const other = ed.rebaser.rebase(edit("value", "NEW", rowOf(S0), 3), () => S1);
    assert.strictEqual(other.expectSrc, rowOf(S1), "another field of the row is still carried");
  });

  test("a pick that meets a busy slot is not queued as a typed edit", async () => {
    const ed = new FakeEditor(S0);
    const guard = new EditLoopGuard();
    assert.ok(guard.beginEdit());
    await drainEdits(guard, edit("path", "PID-9", rowOf(S0), 1), ed.apply, undefined, undefined, ed.options(true));
    assert.strictEqual(guard.pendingCount, 0);
    assert.deepStrictEqual(ed.applied, []);
  });

  test("readPickPartMessage and readEditMessage carry a safe-integer projection id, and drop any other", () => {
    const coords = { handler: "h", lineStart: LINE, lineEnd: LINE, name: "value", expectSrc: rowOf(S0) };
    const pick = { command: "pickPart", ...coords, parts: [{ path: "PID-3" }], index: 0 };
    assert.strictEqual(readPickPartMessage({ ...pick, projection: 7 })?.projection, 7);
    assert.strictEqual(readPickPartMessage({ ...pick, projection: 1.5 })?.projection, undefined);
    const typed = readEditMessage({ command: "edit", ...coords, value: "X", projection: 7 });
    assert.ok(typed !== undefined && "edit" in typed && typed.edit.projection === 7);
  });

  test("a pick with no projection id ends the chain, so an edit queued behind it is sent as posted", async () => {
    const ed = new FakeEditor(S0);
    await drainWithQueued(ed, edit("path", "PID-9", rowOf(S0)), [edit("value", "NEW", rowOf(S0), 1)]);
    assert.deepStrictEqual(ed.refused, ["value=NEW"]);
  });

  test("webview: a pickPath post echoes the page's projection id", () => {
    const page = loadPage(withControls());
    const meta = page.doc.createElement("meta");
    meta.setAttribute("name", "mf-projection");
    meta.setAttribute("content", "7");
    page.doc.head.appendChild(meta);
    const button = page.doc.querySelector("button.pickpath");
    assert.ok(button, "the fixture renders a field picker button");
    button.click();
    const pick = page.posted.find((m) => m.command === "pickPath");
    assert.ok(pick, "a pickPath was posted");
    assert.strictEqual(pick.projection, 7);
  });
});

suite("b20008 C #5943 item 43 -- project() never prunes a kept projection's buffer", () => {
  const S0 = source();
  const S1 = source("PID-5", "A");
  const S2 = source("PID-5", "B");

  /** Two writes on one row from projection 1, then two renders that finish out of order. */
  function outOfOrder(): QueuedEditRebaser {
    const r = new QueuedEditRebaser();
    r.project(1, S0);
    r.record(edit("value", "A", rowOf(S0), 1), { before: S0, after: S1 });
    r.record(edit("value", "B", rowOf(S1), 1), { before: S1, after: S2 });
    r.project(2, S2); // the render that read S2 finished first
    r.project(3, S1); // the render that read S1, before the second write, finished last
    return r;
  }

  test("an edit from the projection shown last is rebased onto the live row", () => {
    const got = outOfOrder().rebase(edit("path", "PID-7", rowOf(S1), 3), () => S2);
    assert.strictEqual(got.expectSrc, rowOf(S2));
  });

  test("but not on a field a write made on another page rewrote after that page's buffer", () => {
    // Page 3 shows value A, but the second write, typed on page 1, made it B. Rebasing page 3's value
    // (a template's parts, say) would write A's parts back over B with no error.
    const sent = edit("value", "C", rowOf(S1), 3);
    assert.strictEqual(outOfOrder().rebase(sent, () => S2), sent);
  });

  test("through the drain, that edit lands instead of being refused as stale", async () => {
    const ed = new FakeEditor(S0);
    const guard = new EditLoopGuard();
    await drainEdits(guard, edit("value", "A", rowOf(S0), 1), ed.apply, undefined, undefined, ed.options(false));
    const after1 = ed.text;
    await drainEdits(guard, edit("value", "B", rowOf(S0), 1), ed.apply, undefined, undefined, ed.options(false));
    ed.rebaser.project(2, ed.text);
    ed.rebaser.project(3, after1);
    await drainEdits(guard, edit("path", "PID-7", rowOf(after1), 3), ed.apply, undefined, undefined, ed.options(false));
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["value=A", "value=B", "path=PID-7"]);
  });

  test("control: a buffer from before every kept projection is still pruned", () => {
    const r = outOfOrder();
    // Were S0 still in the chain, projecting it would keep projection 3, and its edit would rebase.
    r.project(4, S0);
    const sent = edit("path", "PID-7", rowOf(S1), 3);
    assert.strictEqual(r.rebase(sent, () => S2), sent);
  });
});
