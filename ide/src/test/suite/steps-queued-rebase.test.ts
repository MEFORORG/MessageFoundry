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
  rowAfterRewrite,
  type AppliedRewrite,
  type EditMessage,
} from "../../stepsModel";

// BACKLOG #5943: a second edit on a row whose first `lens rewrite` had not yet been re-projected into the
// webview was sent with the row's text from before the first rewrite, so the engine's stale guard (F7)
// refused it and the user's edit was reverted. The fake engine below keeps that guard: it refuses an edit
// whose expectSrc does not match the live buffer's row, exactly as `lens rewrite` does.

const ROW = 'msg.set("PID-5", "OLD")';

function source(row: string = ROW): string {
  return ["@handler", "def h(msg):", `    ${row}`, "    return msg"].join("\n");
}

/** A fake document plus a fake `lens rewrite` that keeps the engine's expect_src check. */
class FakeEditor {
  text: string;
  readonly refused: string[] = [];
  readonly applied: string[] = [];
  readonly rebaser = new QueuedEditRebaser();
  private gate: Promise<void> | undefined;
  private open: (() => void) | undefined;

  constructor(text: string) {
    this.text = text;
    this.rebaser.project(text); // the webview's first render
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

  get rebase(): { rebaser: QueuedEditRebaser; readSource: () => string } {
    return { rebaser: this.rebaser, readSource: () => this.text };
  }

  /** The value change, applied in place on the row's line; `extraLine` simulates a line-count change. */
  apply = async (msg: EditMessage, extraLine = false): Promise<AppliedRewrite | void> => {
    // The rewrite reads the buffer sent when the edit started, as `lens rewrite` reads its stdin.
    const before = this.text;
    const gate = this.gate;
    this.gate = undefined;
    if (gate) {
      await gate;
    }
    const sent = physicalLines(before);
    const row = sent.slice(msg.lineStart - 1, msg.lineEnd).join("\n");
    if (msg.expectSrc !== undefined && msg.expectSrc !== row) {
      this.refused.push(String(msg.value));
      return undefined;
    }
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

function edit(value: string, name = "value", expectSrc: string = `    ${ROW}`): EditMessage {
  return { command: "edit", handler: "h", lineStart: 3, lineEnd: 3, name, value, expectSrc };
}

suite("Steps edit -- an edit on a rewritten row carries its expectSrc over (BACKLOG #5943)", () => {
  test("two rapid edits on one row: the queued second is sent with the first rewrite's row, not refused", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const run1 = drainEdits(guard, edit("A"), ed.apply, undefined, undefined, ed.rebase);
    // Projected before A landed, so it carries the pre-A row as expectSrc.
    const run2 = drainEdits(guard, edit("B"), ed.apply, undefined, undefined, ed.rebase);
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.refused, [], "the queued edit is not refused as stale");
    assert.deepStrictEqual(ed.applied, ["A", "B"]);
    assert.ok(ed.text.includes('"B"'), "the user's second value is what the buffer holds");
  });

  test("an edit posted after the first drain released, before the re-projection, is also carried over", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    await drainEdits(guard, edit("A"), ed.apply, undefined, undefined, ed.rebase);
    await drainEdits(guard, edit("B"), ed.apply, undefined, undefined, ed.rebase);
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["A", "B"]);
  });

  test("three edits on one row, two queued behind the first, all apply", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const run1 = drainEdits(guard, edit("A"), ed.apply, undefined, undefined, ed.rebase);
    // B shares A's field key, which A's drain has already taken; C's distinct key keeps both queued.
    const run2 = drainEdits(guard, edit("B"), ed.apply, undefined, undefined, ed.rebase);
    const run3 = drainEdits(guard, edit("C", "other"), ed.apply, undefined, undefined, ed.rebase);
    ed.release();
    await Promise.all([run1, run2, run3]);
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["A", "B", "C"]);
  });

  test("without a rebaser the queued edit is sent unchanged (the stale guard still refuses it)", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const run1 = drainEdits(guard, edit("A"), ed.apply);
    const run2 = drainEdits(guard, edit("B"), ed.apply);
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.refused, ["B"]);
  });

  test("a write that changes the line count latches rebasing off", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    ed.hold();
    const apply = (m: EditMessage): Promise<AppliedRewrite | void> => ed.apply(m, m.value === "A");
    const run1 = drainEdits(guard, edit("A"), apply, undefined, undefined, ed.rebase);
    const run2 = drainEdits(guard, edit("B"), apply, undefined, undefined, ed.rebase);
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.refused, ["B"], "the queued edit keeps its projected expectSrc and is refused");
  });

  test("a buffer changed outside these writes (a split-view edit) leaves the edit unrebased", async () => {
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
    const run1 = drainEdits(guard, edit("A"), apply, undefined, undefined, ed.rebase);
    const run2 = drainEdits(guard, edit("B"), apply, undefined, undefined, ed.rebase);
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.refused, ["B"]);
  });

  test("an unexpected rejection after a recorded write latches rebasing off", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    const apply = async (m: EditMessage): Promise<AppliedRewrite | void> => {
      if (m.value === "X") {
        guard.queue(edit("C"));
        throw new Error("applyEdit rejected");
      }
      return ed.apply(m);
    };
    ed.hold();
    const run1 = drainEdits(guard, edit("A"), apply, () => undefined, undefined, ed.rebase);
    // X is on another field so it does not coalesce with C, which the rejection queues.
    const run2 = drainEdits(guard, edit("X", "other"), apply, () => undefined, undefined, ed.rebase);
    ed.release();
    await Promise.all([run1, run2]);
    assert.deepStrictEqual(ed.applied, ["A"]);
    assert.deepStrictEqual(ed.refused, ["C"], "C is sent as posted after the rejection, not rebased");
  });

  test("a throwing readSource sends the edit as posted and the drain does not throw", async () => {
    const ed = new FakeEditor(source());
    const guard = new EditLoopGuard();
    await drainEdits(guard, edit("A"), ed.apply, undefined, undefined, ed.rebase);
    const throwing = {
      rebaser: ed.rebaser,
      readSource: (): string => {
        throw new Error("document closed");
      },
    };
    await drainEdits(guard, edit("B"), ed.apply, undefined, undefined, throwing);
    assert.deepStrictEqual(ed.refused, ["B"]);
    assert.strictEqual(guard.isEditing, false);
  });
});

suite("Steps edit -- rowAfterRewrite and QueuedEditRebaser (BACKLOG #5943)", () => {
  const before = source();
  const after = source('msg.set("PID-5", "A")');
  const afterRow = '    msg.set("PID-5", "A")';

  test("an in-place rewrite of the row returns the row's new text", () => {
    assert.strictEqual(rowAfterRewrite(edit("A"), { before, after }), afterRow);
  });

  test("a change outside the row, a line-count change, or a wrong expectSrc returns undefined", () => {
    const outside = after.replace("def h(msg):", "def h(m):");
    assert.strictEqual(rowAfterRewrite(edit("A"), { before, after: outside }), undefined);
    assert.strictEqual(rowAfterRewrite(edit("A"), { before, after: `${after}\n` }), undefined);
    assert.strictEqual(rowAfterRewrite(edit("A", "value", "    other"), { before, after }), undefined);
    const noExpect: EditMessage = { ...edit("A"), expectSrc: undefined };
    assert.strictEqual(rowAfterRewrite(noExpect, { before, after }), undefined);
  });

  const fresh = (): QueuedEditRebaser => {
    const r = new QueuedEditRebaser();
    r.project(before);
    return r;
  };

  test("an edit on a different row, or with an unseen expectSrc, is not rebased", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    const otherRow: EditMessage = { ...edit("B"), lineStart: 4, lineEnd: 4, expectSrc: "    return msg" };
    assert.strictEqual(r.rebase(otherRow, () => after), otherRow);
    const unseen = edit("B", "value", "    something else");
    assert.strictEqual(r.rebase(unseen, () => after), unseen);
    assert.strictEqual(r.rebase(edit("B"), () => after).expectSrc, afterRow);
  });

  test("a write recorded with no expectSrc ends the chain", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    r.record({ ...edit("X"), lineStart: 4, lineEnd: 4, expectSrc: undefined }, { before: after, after });
    const queued = edit("B");
    assert.strictEqual(r.rebase(queued, () => after), queued);
  });

  test("a recorded write whose input is not the previous output starts a new chain", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    // Something outside the recorded writes changed the buffer, then a write on another row landed.
    const gap = `${after}\n# typed`;
    const gapAfter = gap.replace("    return msg", "    return None");
    r.record({ ...edit("Y"), lineStart: 4, lineEnd: 4, expectSrc: "    return msg" }, { before: gap, after: gapAfter });
    const queued = edit("B");
    assert.strictEqual(r.rebase(queued, () => gapAfter), queued, "the row recorded before the gap is forgotten");
  });

  test("a projection of a buffer in the chain keeps it; one outside the chain ends it", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    r.project(after); // a re-projection mid-drain, of the buffer A wrote
    assert.strictEqual(r.rebase(edit("B"), () => after).expectSrc, afterRow, "kept across an in-chain projection");
    // A structural op moved lines; its re-projection shows a layout the chain never had.
    r.project(`# moved\n${after}`);
    const queued = edit("B");
    assert.strictEqual(r.rebase(queued, () => after), queued, "an undo back to `after` does not revive the chain");
  });

  test("a projection prunes the chain to the buffers since it, and an older one then ends the chain", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    r.project(after);
    r.project(before); // an out-of-order render of the pre-A buffer
    const queued = edit("B");
    assert.strictEqual(r.rebase(queued, () => after), queued);
  });

  test("the live buffer is read only when a recorded row could rebase the edit", () => {
    const r = fresh();
    let reads = 0;
    const read = (): string => {
      reads++;
      return after;
    };
    r.rebase(edit("B"), read);
    assert.strictEqual(reads, 0, "nothing recorded: no buffer copy");
    r.record(edit("A"), { before, after });
    r.rebase(edit("B"), read);
    assert.strictEqual(reads, 1);
  });
});

suite("Steps edit -- the provider wires the rebase (BACKLOG #5943)", () => {
  // stepsView.ts imports vscode, so the wiring is pinned by a source scan.
  const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "stepsView.ts"), "utf8");
  const applyOne = src.slice(src.indexOf("const applyOne = async"), src.indexOf("const applyEdit = (msg"));

  test("applyOne captures the buffer it sends before the rewrite and returns it only after applyEdit lands", () => {
    const capture = applyOne.indexOf("const before = document.getText();");
    const send = applyOne.indexOf("lensRewriteStdin(");
    assert.ok(capture >= 0 && send > capture, "`before` is read before lens rewrite is awaited");
    assert.ok(/spec,\s*before,/.test(applyOne), "the buffer sent is `before` itself");
    const landed = applyOne.indexOf("if (!(await vscode.workspace.applyEdit(edit)))");
    const ret = applyOne.indexOf("return { before, after: outcome.source };");
    assert.ok(landed >= 0 && ret > landed, "the write is returned only after applyEdit reports it landed");
  });

  test("the typed drain gets the panel's rebaser and render() reports each projection's buffer", () => {
    assert.ok(src.includes("{ rebaser, readSource: () => document.getText() }"));
    const html = src.indexOf("panel.webview.html = pageHtml(");
    const project = src.indexOf("rebaser.project(source);");
    assert.ok(html >= 0 && project > html, "the projection is reported once the webview carries it");
  });
});

