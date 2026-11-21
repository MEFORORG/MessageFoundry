// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import {
  EditLoopGuard,
  QueuedEditRebaser,
  drainEdits,
  physicalLines,
  rowAfterRewrite,
  type AppliedRewrite,
  type EditMessage,
} from "../../stepsModel";

// BACKLOG #5943: a second edit queued on a row while the first `lens rewrite` of that row is in flight
// was sent with the row's text from before the first rewrite, so the engine's stale guard (F7) refused
// it and the user's edit was reverted. The fake engine below keeps that guard: it refuses an edit whose
// expectSrc does not match the live buffer's row, exactly as `lens rewrite` does.

const ROW = 'msg.set("PID-5", "OLD")';

function source(row: string = ROW): string {
  return ["@handler", "def h(msg):", `    ${row}`, "    return msg"].join("\n");
}

/** A fake document plus a fake `lens rewrite` that keeps the engine's expect_src check. */
class FakeEditor {
  text: string;
  readonly refused: string[] = [];
  readonly applied: string[] = [];
  private gate: Promise<void> | undefined;
  private open: (() => void) | undefined;

  constructor(text: string) {
    this.text = text;
  }

  /** Hold the next apply open until {@link release} is called. */
  hold(): void {
    this.gate = new Promise<void>((resolve) => {
      this.open = resolve;
    });
  }

  release(): void {
    this.open?.();
  }

  /** The value change, applied in place on the row's line; `extraLine` simulates a line-count change. */
  apply = async (msg: EditMessage, extraLine = false): Promise<AppliedRewrite | void> => {
    const before = this.text;
    const gate = this.gate;
    this.gate = undefined;
    if (gate) {
      await gate;
    }
    const lines = physicalLines(this.text);
    const live = lines.slice(msg.lineStart - 1, msg.lineEnd).join("\n");
    if (msg.expectSrc !== undefined && msg.expectSrc !== live) {
      this.refused.push(String(msg.value));
      return undefined;
    }
    // The rewrite reads the buffer sent when the edit started, as `lens rewrite` reads its stdin.
    const sent = physicalLines(before);
    sent[msg.lineStart - 1] = `    msg.set("PID-5", "${String(msg.value)}")`;
    if (extraLine) {
      sent.splice(msg.lineStart, 0, "    # wrapped");
    }
    const after = sent.join("\n");
    this.text = after;
    this.applied.push(String(msg.value));
    return { before, after };
  };
}

function edit(value: string, expectSrc: string = `    ${ROW}`): EditMessage {
  return { command: "edit", handler: "h", lineStart: 3, lineEnd: 3, name: "value", value, expectSrc };
}

suite("Steps edit -- a queued edit on a rewritten row carries its expectSrc over (BACKLOG #5943)", () => {
  test("two rapid edits on one row: the second is sent with the first rewrite's row, not refused", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const run1 = drainEdits(guard, edit("A"), (m) => ed.apply(m), undefined, undefined, () => ed.text);
    // Projected before A landed, so it carries the pre-A row as expectSrc.
    const run2 = drainEdits(guard, edit("B"), (m) => ed.apply(m), undefined, undefined, () => ed.text);
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.refused, [], "the queued edit is not refused as stale");
    assert.deepStrictEqual(ed.applied, ["A", "B"]);
    assert.ok(ed.text.includes('"B"'), "the user's second value is what the buffer holds");
  });

  test("three edits on one row, two queued behind the first, all apply", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const run1 = drainEdits(guard, edit("A"), (m) => ed.apply(m), undefined, undefined, () => ed.text);
    // Distinct field keys so both stay queued (same-field edits coalesce to the latest).
    const b = { ...edit("B"), name: "value" };
    const c = { ...edit("C"), name: "other" };
    const run2 = drainEdits(guard, b, (m) => ed.apply(m), undefined, undefined, () => ed.text);
    const run3 = drainEdits(guard, c, (m) => ed.apply(m), undefined, undefined, () => ed.text);
    ed.release();
    await Promise.all([run1, run2, run3]);
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["A", "B", "C"]);
  });

  test("without readSource the queued edit is sent unchanged (the stale guard still refuses it)", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const run1 = drainEdits(guard, edit("A"), (m) => ed.apply(m));
    const run2 = drainEdits(guard, edit("B"), (m) => ed.apply(m));
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.refused, ["B"]);
  });

  test("a write that changes the line count latches rebasing off", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const apply = (m: EditMessage): Promise<AppliedRewrite | void> => ed.apply(m, m.value === "A");
    const run1 = drainEdits(guard, edit("A"), apply, undefined, undefined, () => ed.text);
    const run2 = drainEdits(guard, edit("B"), apply, undefined, undefined, () => ed.text);
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.refused, ["B"], "the queued edit keeps its projected expectSrc and is refused");
  });

  test("a buffer changed outside the drain (a split-view edit) leaves the queued edit unrebased", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const apply = async (m: EditMessage): Promise<AppliedRewrite | void> => {
      const wrote = await ed.apply(m);
      if (m.value === "A") {
        ed.text = `${ed.text}\n# typed in a split view`;
      }
      return wrote;
    };
    const run1 = drainEdits(guard, edit("A"), apply, undefined, undefined, () => ed.text);
    const run2 = drainEdits(guard, edit("B"), apply, undefined, undefined, () => ed.text);
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.refused, ["B"]);
  });

  test("an unexpected rejection latches rebasing off", async () => {
    const guard = new EditLoopGuard();
    const sent: EditMessage[] = [];
    const apply = async (m: EditMessage): Promise<AppliedRewrite | void> => {
      sent.push(m);
      if (m.value === "A") {
        guard.queue(edit("B"));
        throw new Error("applyEdit rejected");
      }
    };
    await drainEdits(guard, edit("A"), apply, () => undefined, undefined, () => source());
    assert.strictEqual(sent[1].expectSrc, `    ${ROW}`, "the queued edit is sent as projected");
  });
});

suite("Steps edit -- rowAfterRewrite and QueuedEditRebaser (BACKLOG #5943)", () => {
  const before = source();
  const after = source('msg.set("PID-5", "A")');

  test("an in-place rewrite of the row returns the row's new text", () => {
    assert.strictEqual(rowAfterRewrite(edit("A"), { before, after }), '    msg.set("PID-5", "A")');
  });

  test("a change outside the row, a line-count change, or a wrong expectSrc returns undefined", () => {
    const outside = after.replace("def h(msg):", "def h(m):");
    assert.strictEqual(rowAfterRewrite(edit("A"), { before, after: outside }), undefined);
    assert.strictEqual(rowAfterRewrite(edit("A"), { before, after: `${after}\n` }), undefined);
    assert.strictEqual(rowAfterRewrite(edit("A", "    other"), { before, after }), undefined);
    const noExpect: EditMessage = { ...edit("A"), expectSrc: undefined };
    assert.strictEqual(rowAfterRewrite(noExpect, { before, after }), undefined);
  });

  test("a queued edit on a different row, or with an unseen expectSrc, is not rebased", () => {
    const r = new QueuedEditRebaser();
    r.record(edit("A"), { before, after });
    const otherRow: EditMessage = { ...edit("B"), lineStart: 4, lineEnd: 4, expectSrc: "    return msg" };
    assert.strictEqual(r.rebase(otherRow, after), otherRow);
    const unseen = edit("B", "    something else");
    assert.strictEqual(r.rebase(unseen, after), unseen);
    const rebased = r.rebase(edit("B"), after);
    assert.strictEqual(rebased.expectSrc, '    msg.set("PID-5", "A")');
  });

  test("a write recorded with no expectSrc latches rebasing off", () => {
    const r = new QueuedEditRebaser();
    r.record(edit("A"), { before, after });
    r.record({ ...edit("X"), lineStart: 4, lineEnd: 4, expectSrc: undefined }, { before: after, after });
    const queued = edit("B");
    assert.strictEqual(r.rebase(queued, after), queued);
  });
});
