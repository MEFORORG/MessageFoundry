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
  readPickPartMessage,
  type AppliedRewrite,
  type EditMessage,
} from "../../stepsModel";
import { loadPage, withControls } from "./b622-g09-steps-page";

// BACKLOG #5943, the two remainders engine PR 3136 named (#8295 items 42 and 43):
//  42. the field-picker drain sent every typed edit queued behind a pick as posted, so one on the
//      picked row was refused as stale even when only another param changed;
//  43. project() pruned chain buffers by last use, so renders that finished out of order deleted the
//      current projection's own buffer, and its edits fell back to the engine's stale refusal.
// And the regressions three review rounds found in an earlier attempt, each pinned NOT to happen here:
// a template pick written over a typed write, a false refusal on a value retyped back, a false refusal
// when a projection's buffer reappears in a new chain, and a pick page dropped by re-projections.
//
// The fake engine keeps the engine's stale guard: it refuses an edit whose expectSrc does not match the
// live buffer's row, as `lens rewrite` does. Row 3 is `msg.set(path, value)`; each edit sets one of the
// two params, so "same field" and "other field" are both expressible.

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

/** `edit(...)` marked as a field pick, the way the provider's pick drain marks it. */
function pick(name: "path" | "value", value: string, expectSrc: string, projection?: number): EditMessage {
  return Object.assign(edit(name, value, expectSrc, projection), { pick: true });
}

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

  get rebase(): { rebaser: QueuedEditRebaser; readSource: () => string } {
    return { rebaser: this.rebaser, readSource: (): string => this.text };
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

  /** One drain of `msg` on its own, nothing queued. */
  async drain(msg: EditMessage): Promise<void> {
    await drainEdits(new EditLoopGuard(), msg, this.apply, undefined, undefined, this.rebase);
  }

  /** `first` held in flight while each of `queued` arrives as a typed edit, then the drain runs on. */
  async drainWithQueued(first: EditMessage, queued: EditMessage[]): Promise<void> {
    const guard = new EditLoopGuard();
    this.hold();
    const running = drainEdits(guard, first, this.apply, undefined, undefined, this.rebase);
    for (const q of queued) {
      await drainEdits(guard, q, this.apply, undefined, undefined, this.rebase);
    }
    this.release();
    await running;
    assert.strictEqual(guard.isEditing, false);
  }
}

const VIEW_TS = path.join(__dirname, "..", "..", "..", "src", "stepsView.ts");

suite("b20008 C2 #5943 item 42 -- a typed edit queued behind a field pick", () => {
  const S0 = source();

  test("the provider's pick drain is drainEdits with the pick marked and the rebase given", () => {
    const src = fs.readFileSync(VIEW_TS, "utf8");
    const start = src.indexOf("const applyPickedEdit = async");
    const end = src.indexOf("const refuseAnchor = ", start);
    assert.ok(start >= 0 && end > start, "applyPickedEdit and the declaration after it were found");
    const body = src.slice(start, end);
    assert.ok(
      /await drainEdits\(guard, \{ \.\.\.msg, pick: true \}, applyOne, onEditError, scheduleRerender, rebaseOptions\);/.test(body),
      "the pick drain runs through drainEdits, marked as a pick, with the typed drain's rebase",
    );
    assert.ok(!/await applyOne\(/.test(body), "no queued edit is sent past the rebaser");
    assert.ok(/if \(guard\.isEditing\) \{/.test(body), "a busy slot is declined before the drain");
    const applyEdit = src.slice(src.indexOf("const applyEdit = (msg"), src.indexOf("const applyStructural = async"));
    assert.ok(/\r?\n {8}rebaseOptions,\r?\n/.test(applyEdit), "the typed drain passes the same rebase");
  });

  test("a typed edit on another field of the picked row is carried over the pick", async () => {
    const ed = new FakeEditor(S0);
    await ed.drainWithQueued(pick("path", "PID-9", rowOf(S0), 1), [edit("value", "NEW", rowOf(S0), 1)]);
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["path=PID-9", "value=NEW"]);
    assert.strictEqual(rowOf(ed.text), row("PID-9", "NEW"));
  });

  test("control: main's pick drain (applyOne then takePending, no rebase) refuses that same edit", async () => {
    const ed = new FakeEditor(S0);
    const guard = new EditLoopGuard();
    ed.hold();
    assert.ok(guard.beginEdit());
    const running = (async (): Promise<void> => {
      let current: EditMessage | undefined = pick("path", "PID-9", rowOf(S0), 1);
      while (current) {
        await ed.apply(current);
        current = guard.takePending();
      }
      guard.endEdit();
    })();
    await drainEdits(guard, edit("value", "NEW", rowOf(S0), 1), ed.apply, undefined, undefined, ed.rebase);
    ed.release();
    await running;
    assert.deepStrictEqual(ed.refused, ["value=NEW"]);
  });

  test("a typed edit on the picked field is sent as posted, so it cannot write the old value over the pick", async () => {
    const ed = new FakeEditor(S0);
    await ed.drainWithQueued(pick("path", "PID-9", rowOf(S0), 1), [edit("path", "PID-5", rowOf(S0), 1)]);
    assert.deepStrictEqual(ed.applied, ["path=PID-9"]);
    assert.deepStrictEqual(ed.refused, ["path=PID-5"]);
    assert.strictEqual(rowOf(ed.text), row("PID-9", "OLD"));
  });

  test("a pick that meets a busy slot is not queued as a typed edit, and goes to onError", async () => {
    const ed = new FakeEditor(S0);
    const guard = new EditLoopGuard();
    assert.ok(guard.beginEdit());
    const errors: unknown[] = [];
    await drainEdits(guard, pick("path", "PID-9", rowOf(S0), 1), ed.apply, (err) => errors.push(err));
    assert.strictEqual(guard.pendingCount, 0);
    assert.strictEqual(errors.length, 1);
    assert.deepStrictEqual(ed.applied, []);
  });

  test("a pick is carried over an earlier typed write of another param of its row", async () => {
    const ed = new FakeEditor(S0);
    await ed.drain(edit("value", "A", rowOf(S0), 1));
    // The page still shows the row as projected, so the pick posts that row's old text.
    await ed.drain(pick("path", "PID-9", rowOf(S0), 1));
    assert.deepStrictEqual(ed.refused, []);
    assert.strictEqual(rowOf(ed.text), row("PID-9", "A"));
  });
});

suite("b20008 C2 #5943 -- a pick never writes over a write its page has not shown", () => {
  const S0 = source();

  test("a template pick over a typed write of its own param is refused, as on main", async () => {
    // pickPart with the picker open (ignoreFocusOut): the request carried the parts as they were, the
    // user typed a new template on the same page, and that write landed. The pick's value holds the
    // older parts, so carrying it would write them over the typed template with no error.
    const ed = new FakeEditor(S0);
    await ed.drain(edit("value", "{typed}", rowOf(S0), 1));
    await ed.drain(pick("value", "{older parts}+{PID-3}", rowOf(S0), 1));
    assert.deepStrictEqual(ed.applied, ["value={typed}"]);
    assert.deepStrictEqual(ed.refused, ["value={older parts}+{PID-3}"]);
    assert.strictEqual(rowOf(ed.text), row("PID-5", "{typed}"));
  });

  test("a pick over an earlier pick of its own param is refused", async () => {
    const ed = new FakeEditor(S0);
    await ed.drain(pick("path", "PID-9", rowOf(S0), 1));
    await ed.drain(pick("path", "PID-8", rowOf(S0), 1));
    assert.deepStrictEqual(ed.applied, ["path=PID-9"]);
    assert.deepStrictEqual(ed.refused, ["path=PID-8"]);
  });

  test("a page projected from a pre-pick buffer after the pick still cannot write over the pick", () => {
    const ed = new FakeEditor(S0);
    const S1 = source("PID-9");
    ed.rebaser.record(pick("path", "PID-9", rowOf(S0), 1), { before: S0, after: S1 });
    ed.rebaser.project(2, S1);
    ed.rebaser.project(3, S0); // a render that read the buffer before the pick finished last
    const onPicked = edit("path", "PID-5", rowOf(S0), 3);
    assert.strictEqual(ed.rebaser.rebase(onPicked, () => S1), onPicked, "the picked param is sent as posted");
    const other = ed.rebaser.rebase(edit("value", "NEW", rowOf(S0), 3), () => S1);
    assert.strictEqual(other.expectSrc, rowOf(S1), "another param of the row is still carried");
  });
});

suite("b20008 C2 #5943 item 43 -- project() never prunes a kept projection's buffer", () => {
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

  test("through the drain, that edit lands instead of being refused as stale", async () => {
    const ed = new FakeEditor(S0);
    await ed.drain(edit("value", "A", rowOf(S0), 1));
    const after1 = ed.text;
    await ed.drain(edit("value", "B", rowOf(S0), 1));
    ed.rebaser.project(2, ed.text);
    ed.rebaser.project(3, after1);
    await ed.drain(edit("path", "PID-7", rowOf(after1), 3));
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["value=A", "value=B", "path=PID-7"]);
  });

  test("a typed edit of the same param from that page is carried over the earlier typed write", () => {
    // What the user typed on the page they were looking at, over a typed value, as with any typed edit.
    const got = outOfOrder().rebase(edit("value", "C", rowOf(S1), 3), () => S2);
    assert.strictEqual(got.expectSrc, rowOf(S2));
  });

  test("control: a buffer from before every kept projection is still pruned", () => {
    const r = outOfOrder();
    r.project(4, S1); // keeps 3 and 4, both S1, so S0 goes
    const fromOne = edit("path", "PID-7", rowOf(S0), 1);
    assert.strictEqual(r.rebase(fromOne, () => S2), fromOne, "projection 1 is no longer kept");
    const r2 = outOfOrder();
    r2.project(4, S0); // S0 was pruned when 3 was projected, so a page of it is not in the chain
    const fromFour = edit("path", "PID-7", rowOf(S0), 4);
    assert.strictEqual(r2.rebase(fromFour, () => S2), fromFour);
  });
});

suite("b20008 C2 #5943 -- no false refusal on a retyped value, a reappearing buffer or a dropped pick page", () => {
  const S0 = source();

  test("a value retyped back is based on the latest buffer with that row text, not an older one", async () => {
    // Pick path (S0 -> S1), retype it back on the next page (S1 -> S0), then on a page of S0 a typed
    // value lands and a typed path edit is queued behind it. Based on the first S0, the pick would be
    // an unseen write of the path and the edit would be refused; based on the latest S0 it is carried.
    const ed = new FakeEditor(S0);
    await ed.drain(pick("path", "PID-9", rowOf(S0), 1));
    ed.rebaser.project(2, ed.text);
    await ed.drain(edit("path", "PID-5", rowOf(ed.text), 2));
    assert.strictEqual(ed.text, S0, "the buffer is S0 again");
    ed.rebaser.project(3, S0);
    await ed.drainWithQueued(edit("value", "X", rowOf(S0), 3), [edit("path", "PID-7", rowOf(S0), 3)]);
    assert.deepStrictEqual(ed.refused, []);
    assert.strictEqual(rowOf(ed.text), row("PID-7", "X"));
  });

  test("a projection whose buffer was outside the chain is used once a later chain holds that buffer", async () => {
    const ed = new FakeEditor(S0);
    await ed.drain(edit("value", "A", rowOf(S0), 1));
    ed.text = `${ed.text}\n# typed in a split view`; // outside the recorded writes
    const S9 = ed.text;
    ed.rebaser.project(2, S9); // not a chain buffer when it is projected
    await ed.drainWithQueued(edit("value", "B", rowOf(S9), 2), [edit("path", "PID-7", rowOf(S9), 2)]);
    assert.deepStrictEqual(ed.refused, []);
    assert.strictEqual(rowOf(ed.text), row("PID-7", "B"));
  });

  test("a projection whose buffer reappears after an undo is used again", async () => {
    const ed = new FakeEditor(S0);
    await ed.drain(edit("value", "A", rowOf(S0), 1));
    ed.text = S0; // an undo, which no rebase records
    ed.rebaser.project(2, S0);
    // A write from page 2 starts a new chain from S0, and page 1 (still kept, also S0) edits behind it.
    await ed.drainWithQueued(edit("path", "PID-7", rowOf(S0), 2), [edit("value", "C", rowOf(S0), 1)]);
    assert.deepStrictEqual(ed.refused, []);
    assert.strictEqual(rowOf(ed.text), row("PID-7", "C"));
  });

  test("two re-projections of the same buffer while the picker is open keep the queued edit carried", async () => {
    const ed = new FakeEditor(S0);
    ed.rebaser.project(2, S0);
    ed.rebaser.project(3, S0); // the pick's page, 1, is no longer kept
    await ed.drainWithQueued(pick("path", "PID-9", rowOf(S0), 1), [edit("value", "NEW", rowOf(S0), 3)]);
    assert.deepStrictEqual(ed.refused, []);
    assert.deepStrictEqual(ed.applied, ["path=PID-9", "value=NEW"]);
  });
});

suite("b20008 C2 #5943 -- the pick posts and readers carry the page's projection id", () => {
  const coords = { handler: "h", lineStart: LINE, lineEnd: LINE, name: "value", expectSrc: rowOf(source()) };

  test("readPickPartMessage keeps a safe-integer projection id and drops any other", () => {
    const msg = { command: "pickPart", ...coords, parts: [{ path: "PID-3" }], index: 0 };
    assert.strictEqual(readPickPartMessage({ ...msg, projection: 7 })?.projection, 7);
    for (const bad of [1.5, "7", Number.NaN, 2 ** 60]) {
      const read = readPickPartMessage({ ...msg, projection: bad });
      assert.ok(read !== undefined, "the pick is still read");
      assert.strictEqual(read.projection, undefined, `projection ${String(bad)} is dropped`);
    }
  });

  test("the provider's pickPath reader keeps only a safe-integer projection id", () => {
    const src = fs.readFileSync(VIEW_TS, "utf8");
    const at = src.indexOf('m?.command === "pickPath"');
    const body = src.slice(at, src.indexOf("pickThenApply(coords", at));
    assert.ok(
      body.includes('...(typeof m.projection === "number" && Number.isSafeInteger(m.projection)'),
      "pickPath copies the projection id only when it is a safe integer",
    );
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
    const posted = page.posted.find((m) => m.command === "pickPath");
    assert.ok(posted, "a pickPath was posted");
    assert.strictEqual(posted.projection, 7);
  });
});

suite("b20008 C2 #8295 item 60 -- a rebase failure is logged even when String() of it throws", () => {
  test("the log line is written with errorText's fallback", async () => {
    const r = new QueuedEditRebaser();
    const S0 = source();
    r.project(1, S0);
    r.record(edit("value", "A", rowOf(S0), 1), { before: S0, after: source("PID-5", "A") });
    const logged: string[] = [];
    const rebase = {
      rebaser: r,
      readSource: (): string => {
        throw Object.create(null) as unknown; // String() of a null-prototype object throws
      },
      log: (t: string): void => {
        logged.push(t);
      },
    };
    await drainEdits(new EditLoopGuard(), edit("path", "PID-7", rowOf(S0), 1), async () => undefined, undefined, undefined, rebase);
    assert.deepStrictEqual(logged, ["Steps edit rebase read failed: an unexpected error"]);
  });
});
