// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  EditLoopGuard,
  QueuedEditRebaser,
  drainEdits,
  errorText,
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
    this.rebaser.project(1, text); // the webview's first render is projection 1
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

function edit(value: string, name = "value", expectSrc: string = `    ${ROW}`, projection = 1): EditMessage {
  return { command: "edit", handler: "h", lineStart: 3, lineEnd: 3, name, value, expectSrc, projection };
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
    r.project(1, before);
    return r;
  };

  test("an edit is rebased onto the live row; one on another row, or not reading its projection, is not", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    assert.strictEqual(r.rebase(edit("B"), () => after).expectSrc, afterRow);
    const otherRow: EditMessage = { ...edit("B"), lineStart: 4, lineEnd: 4, expectSrc: "    return msg" };
    assert.strictEqual(r.rebase(otherRow, () => after), otherRow, "an unrewritten row is already current");
    const mismatch = edit("B", "value", "    something else");
    assert.strictEqual(r.rebase(mismatch, () => after), mismatch, "expectSrc must be its projection's row");
  });

  test("an edit with no projection id, or one the rebaser never saw, is sent as posted", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    const noId: EditMessage = { ...edit("B"), projection: undefined };
    assert.strictEqual(r.rebase(noId, () => after), noId);
    const unknown = edit("B", "value", `    ${ROW}`, 7);
    assert.strictEqual(r.rebase(unknown, () => after), unknown);
  });

  test("a write recorded with no projection id, or none of expectSrc, ends the chain", () => {
    for (const bad of [
      { ...edit("X"), lineStart: 4, lineEnd: 4, expectSrc: undefined },
      { ...edit("X"), lineStart: 4, lineEnd: 4, expectSrc: "    return msg", projection: undefined },
    ]) {
      const r = fresh();
      r.record(edit("A"), { before, after });
      r.record(bad, { before: after, after: after.replace("    return msg", "    return None") });
      const queued = edit("B");
      assert.strictEqual(r.rebase(queued, () => after), queued);
    }
  });

  test("a recorded write whose input is neither the chain's output nor its projection's buffer ends the chain", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    // Something outside the recorded writes changed the buffer, then a write on another row landed.
    const gap = `${after}\n# typed`;
    const gapAfter = gap.replace("    return msg", "    return None");
    r.record({ ...edit("Y"), lineStart: 4, lineEnd: 4, expectSrc: "    return msg" }, { before: gap, after: gapAfter });
    const queued = edit("B");
    assert.strictEqual(r.rebase(queued, () => gapAfter), queued);
  });

  test("round 3 finding 1: a write from an older webview cannot restart the chain after a structural op", () => {
    // Projection 1 shows `before`. A structural op inserts a line above the row and its render is
    // projection 2. The old webview (projection 1) still posts edits by its own line numbers, and one
    // lands by coincidence on a row that reads the same text at the shifted line.
    const r = fresh();
    const shifted = `# inserted\n${before}`.replace("    return msg", `    ${ROW}`);
    r.project(2, shifted); // outside the chain: it ends
    // E1 from projection 1 names line 4, and line 4 of `shifted` reads E1's expectSrc, so the engine's
    // stale guard would let E1 through: the coincidental pass. It lands.
    const e1: EditMessage = { ...edit("E1"), lineStart: 4, lineEnd: 4, projection: 1 };
    const e1After = physicalLines(shifted);
    e1After[3] = '    msg.set("PID-5", "E1")';
    r.record(e1, { before: shifted, after: e1After.join("\n") });
    const e2: EditMessage = { ...edit("E2"), lineStart: 4, lineEnd: 4, projection: 1 };
    assert.strictEqual(r.rebase(e2, () => e1After.join("\n")), e2, "E2 is sent as posted, so F7 refuses it");
  });

  test("an in-chain projection keeps the one before it; an older or out-of-chain one is dropped", () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    r.project(2, after); // a re-projection mid-drain, of the buffer A wrote
    assert.strictEqual(r.rebase(edit("B"), () => after).expectSrc, afterRow, "projection 1 is still kept");
    const after2 = source('msg.set("PID-5", "B")');
    r.record(edit("B", "value", afterRow, 2), { before: after, after: after2 });
    r.project(3, after2);
    const old = edit("C");
    assert.strictEqual(r.rebase(old, () => after2), old, "projection 1 is two projections back: dropped");
    const fromTwo = edit("C", "value", afterRow, 2);
    assert.strictEqual(r.rebase(fromTwo, () => after2).expectSrc, '    msg.set("PID-5", "B")');
    // A structural op's layout: the chain ends, and an undo back to `after2` does not revive it.
    r.project(4, `# moved\n${after2}`);
    assert.strictEqual(r.rebase(fromTwo, () => after2), fromTwo);
  });

  test("the live buffer is read only when the edit's projection is in the chain", () => {
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

  test("drainEdits logs a throw from the buffer read", async () => {
    const r = fresh();
    r.record(edit("A"), { before, after });
    const logged: string[] = [];
    const rebase = {
      rebaser: r,
      readSource: (): string => {
        throw new Error("document closed");
      },
      log: (t: string): void => {
        logged.push(t);
      },
    };
    await drainEdits(new EditLoopGuard(), edit("B"), async () => undefined, undefined, undefined, rebase);
    assert.strictEqual(logged.length, 1);
    assert.ok(logged[0].includes("document closed"));
  });

  test("errorText never throws, and a throwing onError does not strand a queued edit", async () => {
    const noProto = Object.create(null) as unknown;
    assert.throws(() => String(noProto), "the control: String() of a null-prototype object throws");
    assert.strictEqual(errorText(noProto), "an unexpected error");
    assert.strictEqual(errorText(new Error("boom")), "boom");
    const guard = new EditLoopGuard();
    const sent: unknown[] = [];
    const apply = async (m: EditMessage): Promise<void> => {
      sent.push(m.value);
      if (m.value === "B") {
        guard.queue(edit("C", "other"));
        throw noProto;
      }
    };
    // The provider's handler as it was: it formats with String(), which throws for this rejection.
    const onError = (err: unknown): void => {
      void `${err instanceof Error ? err.message : String(err)}`;
    };
    await drainEdits(guard, edit("B"), apply, onError);
    assert.deepStrictEqual(sent, ["B", "C"], "the queued edit is still sent");
    assert.strictEqual(guard.isEditing, false);
    const view = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "stepsView.ts"), "utf8");
    assert.ok(view.includes("could not apply the edit — ${errorText(err)}"), "the provider formats with errorText");
  });

  test("a throwing logger, or an error String() cannot convert, does not escape drainEdits", async () => {
    const cases: { thrown: unknown; log: (t: string) => void }[] = [
      {
        thrown: new Error("document closed"),
        log: (): void => {
          throw new Error("logger down");
        },
      },
      { thrown: Object.create(null) as unknown, log: (): void => undefined }, // String() of it throws
    ];
    for (const { thrown, log } of cases) {
      const r = fresh();
      r.record(edit("A"), { before, after });
      const guard = new EditLoopGuard();
      const sent: EditMessage[] = [];
      guard.beginEdit();
      guard.queue(edit("C", "other")); // queued behind B, so a throw would strand it
      guard.endEdit();
      const rebase = {
        rebaser: r,
        readSource: (): string => {
          throw thrown;
        },
        log,
      };
      await drainEdits(
        guard,
        edit("B"),
        async (m) => {
          sent.push(m);
        },
        undefined,
        undefined,
        rebase,
      );
      assert.deepStrictEqual(
        sent.map((m) => m.value),
        ["B", "C"],
        "the drain did not throw and the queued edit was still sent",
      );
      assert.strictEqual(guard.isEditing, false);
    }
  });
});

suite("Steps edit -- the provider wires the rebase (BACKLOG #5943)", () => {
  // stepsView.ts and the page script are pinned by a source scan; each read happens inside its test.
  const read = (...p: string[]): string => fs.readFileSync(path.join(__dirname, "..", "..", "..", ...p), "utf8");

  test("applyOne captures the buffer it sends before the rewrite and returns it only after applyEdit lands", () => {
    const src = read("src", "stepsView.ts");
    const applyOne = src.slice(src.indexOf("const applyOne = async"), src.indexOf("const applyEdit = (msg"));
    const capture = applyOne.indexOf("const before = document.getText();");
    const send = applyOne.indexOf("lensRewriteStdin(");
    assert.ok(capture >= 0 && send > capture, "`before` is read before lens rewrite is awaited");
    assert.ok(/spec,\s*before,/.test(applyOne), "the buffer sent is `before` itself");
    const landed = applyOne.indexOf("if (!(await vscode.workspace.applyEdit(edit)))");
    const ret = applyOne.indexOf("return { before, after: outcome.source };");
    assert.ok(landed >= 0 && ret > landed, "the write is returned only after applyEdit reports it landed");
  });

  test("render() stamps each projection's id into the page and reports it with its buffer", () => {
    const src = read("src", "stepsView.ts");
    const render = src.slice(src.indexOf("const render = async"), src.indexOf("const applyOne = async"));
    const id = render.indexOf("const projection = ++projectionId;");
    const html = render.indexOf("panel.webview.html = pageHtml(");
    const project = render.indexOf("rebaser.project(projection, source);");
    assert.ok(id >= 0 && html > id && project > html, "the id is minted, stamped, then reported");
    assert.ok(src.includes('<meta name="mf-projection" content="${projection}" />'));
    assert.ok(/readSource: \(\) => document\.getText\(\)/.test(src.slice(src.indexOf("const applyEdit = (msg"))));
  });

  test("both edit posts and both pick posts in the page echo the projection id", () => {
    const js = read("media", "stepsWebview.js");
    assert.strictEqual((js.match(/projection: projectionId\(\)/g) ?? []).length, 4);
  });
});
