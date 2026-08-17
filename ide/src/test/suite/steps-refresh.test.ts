// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  EditLoopGuard,
  REDACTED_LIVE_VALUE,
  RerenderDebouncer,
  drainEdits,
  mergeLiveValues,
  shouldAttachLiveValues,
  type EditMessage,
  type LiveInlineValue,
  type RowViewModel,
} from "../../stepsModel";

// ---------------------------------------------------------------------------------------------------
// BACKLOG #234 / ADR 0076 Amendment C — the three invariants the deferred re-projection must preserve.
//
// Amendment C makes a save that lands while a `lens rewrite` holds the single edit slot DEFERRED rather
// than DISCARDED. `steps-edit.test.ts` already unit-tests the pieces (the guard's clear-on-read debt,
// `releaseEdit`, `RerenderDebouncer`) and their arithmetic (AC-C1..C4); `steps-mirror.test.ts` already
// scans the provider for the release-site and render-entry wiring (AC-C5).
//
// What none of those reach is the RACE ITSELF. Every existing composition test releases the slot and
// THEN advances the clock, so the one window where the update-loop guard is observable — the debounce
// firing WHILE the rewrite is still applying — is never entered. A guard that had stopped working would
// pass all of them. This file drives that window, and each suite carries a kept-in-tree falsification so
// a green here is evidence that the check can still see the defect it claims to exclude.
//
// Node-side only: no `vscode` import, so this runs on every `ide` CI leg (`npm run test:unit`), not only
// the Windows Extension Host leg.
// ---------------------------------------------------------------------------------------------------

const IDE_ROOT = path.join(__dirname, "..", "..", "..");
const STEPS_VIEW_TS = path.join(IDE_ROOT, "src", "stepsView.ts");
//: `render()`'s parse call moved behind `lensParseStdin` here (BACKLOG #232), so the "live buffer, never
//: a disk read" invariant now spans both files and both are scanned.
const CLI_TS = path.join(IDE_ROOT, "src", "cli.ts");

/** Mirrors `RERENDER_DEBOUNCE_MS` in `stepsView.ts`; only the relative ordering matters here. */
const DEBOUNCE_MS = 250;

const EDIT: EditMessage = {
  command: "edit",
  handler: "h",
  lineStart: 6,
  lineEnd: 6,
  name: "dst",
  value: "A",
};

/**
 * Manually-fired stand-ins for `setTimeout`/`clearTimeout`.
 *
 * Deliberately local to this file rather than shared with `steps-edit.test.ts`'s clock: these suites
 * must fire the debounce from INSIDE the race — while an async `lens rewrite` is parked mid-`await` —
 * which is a different job from advancing a clock after a synchronous sequence has finished.
 */
class ManualClock {
  private nextId = 1;
  private now = 0;
  private readonly timers = new Map<number, { fn: () => void; at: number }>();

  readonly set = (fn: () => void, ms: number): number => {
    const id = this.nextId++;
    this.timers.set(id, { fn, at: this.now + ms });
    return id;
  };

  readonly clear = (id: number): void => {
    this.timers.delete(id);
  };

  advance(ms: number): void {
    this.now += ms;
    for (const [id, t] of [...this.timers]) {
      if (t.at <= this.now) {
        this.timers.delete(id);
        t.fn();
      }
    }
  }

  get pending(): number {
    return this.timers.size;
  }
}

/** A promise the test resolves by hand, standing in for the in-flight `lens rewrite` + `WorkspaceEdit`. */
function deferred(): { readonly promise: Promise<void>; resolve(): void } {
  let release!: () => void;
  const promise = new Promise<void>((r) => {
    release = r;
  });
  return { promise, resolve: () => release() };
}

/** Let every queued microtask run, so a parked `await` has actually reached its await point. */
const settle = (): Promise<void> => new Promise<void>((r) => setImmediate(r));

interface RenderRecord {
  /** Whether the edit slot was still held when this re-projection ran — `true` IS the update loop. */
  readonly whileEditing: boolean;
}

interface Harness {
  readonly clock: ManualClock;
  readonly renders: RenderRecord[];
  readonly rerender: RerenderDebouncer<number>;
  onSave(): void;
}

/**
 * The provider's three #234 wires, assembled the way `stepsView.ts` assembles them:
 *
 *   * the ONE debounced re-projection channel both a save and a deferred refresh go through;
 *   * `render()`, whose first two statements are the two discharges (`rerender.cancel()` then
 *     `guard.takeSuppressedChange()`) before any projection work;
 *   * the `onDidSaveTextDocument` subscription body, which asks the guard and records a debt instead of
 *     re-projecting when the answer is no.
 *
 * `stepsView.ts` imports `vscode`, so it cannot be loaded node-side; `steps-mirror.test.ts` pins this
 * shape against the real file by source scan, and this harness is what makes the shape executable.
 */
function providerHarness(guard: EditLoopGuard, onRender?: () => void): Harness {
  const clock = new ManualClock();
  const renders: RenderRecord[] = [];

  function render(): void {
    rerender.cancel();
    guard.takeSuppressedChange();
    renders.push({ whileEditing: guard.isEditing });
    onRender?.();
  }

  const rerender = new RerenderDebouncer<number>(render, DEBOUNCE_MS, clock.set, clock.clear);

  return {
    clock,
    renders,
    rerender,
    onSave(): void {
      if (!guard.shouldReactToDocumentChange()) {
        guard.noteSuppressedChange();
        return;
      }
      rerender.schedule();
    },
  };
}

/** Park a `lens rewrite` in flight and hand back the drain plus the lever that finishes it. */
function startRewrite(
  guard: EditLoopGuard,
  h: Harness,
): { readonly drain: Promise<void>; finish(): void } {
  const rewrite = deferred();
  const drain = drainEdits(
    guard,
    EDIT,
    async () => {
      await rewrite.promise;
    },
    undefined,
    () => h.rerender.schedule(),
  );
  return { drain, finish: () => rewrite.resolve() };
}

// ---- INVARIANT 1: the update-loop guard still holds when a save races an in-flight rewrite ----------

suite("Steps #234 invariant 1 — a save racing an IN-FLIGHT lens rewrite never re-projects early", () => {
  test("zero re-projections while the slot is held; exactly one, after release", async () => {
    const guard = new EditLoopGuard();
    const h = providerHarness(guard);
    const rewrite = startRewrite(guard, h);
    await settle();
    assert.strictEqual(guard.isEditing, true, "the lens rewrite genuinely holds the edit slot");

    h.onSave(); // the user saves while our own WorkspaceEdit is still applying
    assert.strictEqual(
      h.rerender.armed,
      false,
      "the guard suppresses at the subscription — a raced save must not even ARM the channel",
    );

    // The whole debounce window passes INSIDE the in-flight window. This is the step every existing
    // composition test skips, and it is the only moment the guardrail is observable.
    h.clock.advance(10_000);

    assert.strictEqual(
      h.renders.length,
      0,
      "no re-projection may run while a lens rewrite is applying — that is the webview<->document " +
        `update loop ADR 0076 §5's guard exists to break; got ${JSON.stringify(h.renders)}`,
    );
    assert.strictEqual(
      guard.hasSuppressedChange,
      true,
      "…and the save is held as a debt rather than discarded (Amendment C, AC-C1)",
    );

    rewrite.finish();
    await rewrite.drain;

    assert.strictEqual(guard.isEditing, false, "the drain's finally released the slot");
    assert.strictEqual(h.rerender.armed, true, "releaseEdit armed the deferred refresh");
    h.clock.advance(DEBOUNCE_MS);

    assert.strictEqual(h.renders.length, 1, "the deferred save is honoured exactly once (AC-C2)");
    assert.strictEqual(
      h.renders[0].whileEditing,
      false,
      "…and it ran only once the slot was free, which is when a re-render is safe",
    );
    assert.strictEqual(h.clock.pending, 0, "no timer is left armed behind it");
  });

  /**
   * The guardrail REMOVED: a guard that answers "yes, react" while an edit is in flight. This is what
   * `shouldReactToDocumentChange()` returning `!this.inFlight` is the whole of, so overriding it to a
   * constant `true` is the minimal, honest break — nothing else about the guard changes.
   */
  class GuardWithoutTheLoopBreak extends EditLoopGuard {
    override shouldReactToDocumentChange(): boolean {
      return true;
    }
  }

  test("…and that is DISCRIMINATING: break the loop guard and the render fires mid-rewrite", async () => {
    // Kept in the tree as the falsification of the test above. Without it, a guard that had silently
    // stopped suppressing would leave every assertion above passing for the wrong reason: the renders
    // array is empty both when the guard holds and when nothing ever scheduled a render at all.
    const guard = new GuardWithoutTheLoopBreak();
    const h = providerHarness(guard);
    const rewrite = startRewrite(guard, h);
    await settle();
    assert.strictEqual(guard.isEditing, true, "same starting state as the test above");

    h.onSave();
    assert.strictEqual(h.rerender.armed, true, "the broken guard lets the raced save arm the channel");
    h.clock.advance(DEBOUNCE_MS);

    assert.strictEqual(
      h.renders.length,
      1,
      "the broken guard re-projects while the rewrite is still applying",
    );
    assert.strictEqual(
      h.renders[0].whileEditing,
      true,
      "…mid-rewrite, replacing the whole webview HTML under a half-applied edit — the update loop",
    );

    rewrite.finish();
    await rewrite.drain;
  });

  test("the ordinary path is untouched: a save with no edit in flight re-projects on the debounce", () => {
    // Non-vacuity for the suite: the harness's onSave DOES produce a render when the guard is idle, so
    // the empty-renders assertion above is a property of the guard, not of a dead harness.
    const guard = new EditLoopGuard();
    const h = providerHarness(guard);
    h.onSave();
    assert.strictEqual(h.rerender.armed, true);
    h.clock.advance(DEBOUNCE_MS);
    assert.strictEqual(h.renders.length, 1, "an ordinary save still re-projects exactly once");
    assert.strictEqual(h.renders[0].whileEditing, false);
  });
});

// ---- INVARIANT 2: relaxing the PROJECTION refresh must not relax LIVE-VALUE acquisition ------------
//
// Two different rules with two different reasons. The projection-refresh gate (ADR 0076 §5) is about
// re-shelling Python and replacing the webview HTML. The live-value gate (BACKLOG #225) is about
// CORRECTNESS: the trace reads the module from DISK while the rows are projected from the LIVE buffer,
// so mapping a disk trace onto a dirty buffer lands a marker on the wrong row.
//
// The deferred refresh is the one re-projection that is NOT triggered by a save — it fires at slot
// release, right after a structural WorkspaceEdit, which is precisely when the buffer is DIRTY. So it
// is the natural place for the two rules to get conflated.

suite("Steps #234 invariant 2 — a deferred refresh keeps live values save-gated (#225)", () => {
  /** DISK has the Send on source line 5 (0-based 4). The BUFFER has shifted it to 6 by an unsaved insert. */
  const DISK_TRACE: LiveInlineValue[] = [{ line: 4, after: REDACTED_LIVE_VALUE, kind: "value" }];

  function shiftedBufferRows(): RowViewModel[] {
    return [
      { index: 0, kind: "action", nesting: 0, lineStart: 5, lineEnd: 5, title: "Convert Case", params: [] },
      { index: 1, kind: "send", nesting: 0, lineStart: 6, lineEnd: 6, title: "Send", params: [] },
    ];
  }

  test("the deferred refresh runs against a DIRTY buffer and attaches no live values", async () => {
    const guard = new EditLoopGuard();
    const rows = shiftedBufferRows();
    // The provider's decision, as `stepsView.ts` makes it: keyed on the document's dirty state alone.
    const h = providerHarness(guard, () => {
      mergeLiveValues(rows, shouldAttachLiveValues(true) ? DISK_TRACE : []);
    });

    const rewrite = startRewrite(guard, h);
    await settle();
    h.onSave();
    rewrite.finish();
    await rewrite.drain;
    h.clock.advance(DEBOUNCE_MS);

    assert.strictEqual(h.renders.length, 1, "the deferred refresh ran (else this test asserts nothing)");
    assert.strictEqual(rows[0].liveValue, undefined, "no stale marker on the shifted Convert Case row");
    assert.strictEqual(rows[1].liveValue, undefined, "and none on the Send row either, while dirty");
  });

  test("…and that is DISCRIMINATING: gate on 'a save was owed' instead and the marker misplaces", () => {
    // The plausible wrong turn: a deferred refresh exists BECAUSE a save happened, so it is tempting to
    // treat the owed-refresh debt as evidence that disk == buffer. It is not — the save that was
    // suppressed is not the save that would have flushed OUR in-flight WorkspaceEdit to disk.
    const rows = shiftedBufferRows();
    const owedFromSave = true;
    const isDirty = true;
    mergeLiveValues(rows, owedFromSave || !isDirty ? DISK_TRACE : []);
    assert.strictEqual(
      rows[0].liveValue,
      REDACTED_LIVE_VALUE,
      "coupling the two rules lands the Send's disk value on the Convert Case row — the #225 defect",
    );
    assert.strictEqual(rows[1].liveValue, undefined, "…while the real Send row is left blank");
  });

  test("stepsView.ts acquires live values through exactly ONE isDirty-keyed gate", () => {
    const lines = fs.readFileSync(STEPS_VIEW_TS, "utf8").split(/\r?\n/);
    const scanned = `${STEPS_VIEW_TS} (${lines.length} lines)`;
    const gates = lines
      .map((line, i) => ({ line: line.trim(), n: i + 1 }))
      .filter(({ line }) => /shouldAttachLiveValues\s*\(/.test(line));
    const acquisitions = lines
      .map((line, i) => ({ line: line.trim(), n: i + 1 }))
      .filter(({ line }) => /this\s*\.\s*liveValuesFor\s*\(/.test(line));

    assert.strictEqual(
      gates.length,
      1,
      `scanned ${scanned}: expected exactly one live-value gate, found ${JSON.stringify(gates)}`,
    );
    assert.ok(
      /shouldAttachLiveValues\(document\.isDirty\)/.test(gates[0].line),
      `the live-value gate must be keyed on the document's dirty state (#225), never on how the ` +
        `projection was triggered; scanned ${scanned}, got ${JSON.stringify(gates[0])}`,
    );
    assert.strictEqual(
      acquisitions.length,
      1,
      `scanned ${scanned}: the traced dry-run must have exactly one call site, so no second, ` +
        `differently-gated acquisition can exist; found ${JSON.stringify(acquisitions)}`,
    );
  });
});

// ---- INVARIANT 3: no second execution path, no declarative artifact (CLAUDE.md §12 / BACKLOG #26) ---

suite("Steps #234 invariant 3 — refreshing more often adds no second state of record", () => {
  test("the owed-refresh debt carries no payload, so it can only cause a RE-DERIVATION", () => {
    // If the debt could carry rows, the deferred refresh would be able to restore a projection the
    // webview held rather than re-reading the buffer — a second state of record by the back door.
    const guard = new EditLoopGuard();
    assert.strictEqual(
      guard.noteSuppressedChange.length,
      0,
      "noteSuppressedChange takes no arguments: nothing about the suppressed change is retained",
    );
    guard.beginEdit();
    guard.noteSuppressedChange();
    const owed = guard.takeSuppressedChange();
    assert.strictEqual(typeof owed, "boolean", "the entire debt is one boolean");
    assert.strictEqual(owed, true);
  });

  test("the provider persists nothing: the .py buffer stays the only artifact", () => {
    // A `write`/Memento pattern this scan can actually SEE. Asserted against sample lines FIRST: a
    // pattern that matches nothing is indistinguishable from a clean file, and would pass forever.
    const PERSIST_RE =
      /\bfs\s*\.\s*(?:promises\s*\.\s*)?write\w*\s*\(|\bwriteFileSync\s*\(|\.(?:globalState|workspaceState)\b/;
    assert.ok(
      PERSIST_RE.test('      fs.writeFileSync(cachePath, JSON.stringify(rows));'),
      "the scan must match a file write, or it proves nothing",
    );
    assert.ok(
      PERSIST_RE.test('      void this.context.workspaceState.update("steps.rows", rows);'),
      "the scan must match a Memento write, or it proves nothing",
    );

    const lines = fs.readFileSync(STEPS_VIEW_TS, "utf8").split(/\r?\n/);
    const offenders = lines
      .map((line, i) => ({ line: line.trim(), n: i + 1 }))
      .filter(({ line }) => PERSIST_RE.test(line));
    assert.deepStrictEqual(
      offenders,
      [],
      `scanned ${STEPS_VIEW_TS} (${lines.length} lines): the Steps view must not persist a projection ` +
        `anywhere — every mutation goes back through \`lens rewrite\` into the .py via a WorkspaceEdit`,
    );
  });

  test("the projection is re-derived from the live buffer on every render, deferred or not", () => {
    // The other half of "no second state of record": there is exactly one projection input, and it is
    // the open document's text. A deferred refresh therefore cannot show anything the .py does not say.
    // Matched loosely on the argv so a later flag (a contract-version gate, say) does not fail this
    // test for the wrong reason: the property under test is that the LIVE BUFFER is what gets parsed,
    // not which flags `lens parse` is given. Loose is not toothless — the sample below proves it still
    // refuses the disk read, which is the exact premise Amendment C §C.4 had to correct.
    // THE PROPERTY SPANS TWO FILES, SO THE SCAN MUST TOO. This originally matched the piped call
    // INLINE in stepsView.ts. BACKLOG #232 then moved that call behind a named helper in cli.ts
    // (`lensParseStdin`, which also negotiates the contract version), and a scan of stepsView.ts alone
    // could no longer see through the indirection — so it failed while the property it names still
    // HELD. That is an instrument fault, not a regression, and loosening the pattern until it passed
    // would have thrown the invariant away to make the red go away. Instead each LINK is asserted:
    //   stepsView.ts:  source = document.getText()  ->  handed to lensParseStdin(source, …)
    //   cli.ts:        lensParseStdin  ->  runJsonWithStdin(["lens","parse","-",…], source, …)
    // A disk read anywhere in that chain still reds this test.
    const HANDS_BUFFER_TO_HELPER_RE = /lensParseStdin\(\s*source\s*[,)]/;
    const HELPER_PIPES_STDIN_RE =
      /runJsonWithStdin<LensParseResult>\(\s*\[[^\]]*"lens",\s*"parse",\s*"-"[^\]]*\],\s*source\s*,/;

    // Negative controls FIRST: a pattern that cannot refuse the disk read asserts nothing.
    assert.ok(
      !HELPER_PIPES_STDIN_RE.test(
        'parse = await runJson<LensParseResult>(["lens", "parse", document.uri.fsPath], ws);',
      ),
      "the helper pattern must NOT accept a parse of the on-disk path, or it asserts nothing",
    );
    assert.ok(
      !HANDS_BUFFER_TO_HELPER_RE.test("parse = await lensParseStdin(document.uri.fsPath, ws);"),
      "the call-site pattern must NOT accept handing the helper a PATH instead of the buffer",
    );
    assert.ok(
      HELPER_PIPES_STDIN_RE.test(
        'parse = await runJsonWithStdin<LensParseResult>(["lens", "parse", "-", "--contract", "2"], source, ws);',
      ),
      "…while still tolerating a later flag, so it fails on substance rather than on argv churn",
    );

    const src = fs.readFileSync(STEPS_VIEW_TS, "utf8");
    assert.ok(
      /const source = document\.getText\(\);/.test(src),
      `scanned ${STEPS_VIEW_TS}: render() must take its source from the live buffer`,
    );
    assert.ok(
      HANDS_BUFFER_TO_HELPER_RE.test(src) || HELPER_PIPES_STDIN_RE.test(src),
      `scanned ${STEPS_VIEW_TS}: render() must hand that same snapshot to \`lensParseStdin\` (or pipe ` +
        `it inline to \`lens parse -\`), never re-read the file from disk`,
    );

    // Follow the call through. If render() delegates, the helper is where the disk read would hide.
    if (!HELPER_PIPES_STDIN_RE.test(src)) {
      const cli = fs.readFileSync(CLI_TS, "utf8");
      assert.ok(
        HELPER_PIPES_STDIN_RE.test(cli),
        `scanned ${CLI_TS}: render() delegates its parse to \`lensParseStdin\`, so THAT is what must ` +
          `pipe the buffer to \`lens parse -\` over stdin — otherwise the projection input is a disk read`,
      );
    }
  });
});
