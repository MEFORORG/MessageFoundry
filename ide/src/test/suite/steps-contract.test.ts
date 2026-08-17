// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import {
  LENS_CONTRACT,
  type LensRow,
  buildRowViewModel,
  contextMenuEnablement,
  editableParamNames,
  isRowDeletable,
  isRowEditable,
  isRowMovable,
  isRowMutable,
  isUnknownArgumentError,
  looksLikeUnknownArgument,
  rowTitle,
} from "../../stepsModel";

// The CONTRACT_V2 row kinds (ADR 0076 Amendment A `note` / Amendment D `route`) as they reach the IDE,
// plus the contract negotiation that keeps an older extension and an older engine from meeting a kind
// neither can handle. The engine half of the same contract is asserted in tests/test_lens_grammar_v2.py.

const note = (over: Partial<LensRow> = {}): LensRow => ({
  kind: "note",
  line_start: 7,
  line_end: 7,
  nesting: 0,
  text: " why we do this",
  raw: "    # why we do this",
  pragma: false,
  ...over,
});

const route = (over: Partial<LensRow> = {}): LensRow => ({
  kind: "route",
  line_start: 9,
  line_end: 9,
  nesting: 0,
  handlers: ["oru_relay"],
  ...over,
});

suite("note rows reach the IDE as a titled, editable step", () => {
  test("a note is titled Comment, a pragma note is titled Pragma", () => {
    assert.strictEqual(rowTitle(note()), "Comment");
    assert.strictEqual(rowTitle(note({ pragma: true, text: " noqa: E501" })), "Pragma");
  });

  test("a note renders its verbatim line in the read-only code slot, never blank", () => {
    const vm = buildRowViewModel(note(), 0, ["", "", "", "", "", "", "    # why we do this"]);
    assert.strictEqual(vm.code, "    # why we do this");
    assert.strictEqual(vm.pragma, false);
  });

  test("a note is editable and deletable but NEVER movable (ADR 0076 A.6)", () => {
    assert.strictEqual(isRowEditable("note"), true);
    assert.strictEqual(isRowMutable(note()), true);
    assert.strictEqual(isRowDeletable(note()), true);
    assert.strictEqual(isRowMovable(note()), false);
  });

  test("a PRAGMA note is read-only in every op — the engine refuses all three", () => {
    const p = note({ pragma: true, text: " fmt: off" });
    assert.strictEqual(isRowMutable(p), false);
    assert.strictEqual(isRowDeletable(p), false);
    assert.strictEqual(isRowMovable(p), false);
    assert.deepStrictEqual(editableParamNames(p), []);
    assert.strictEqual(
      contextMenuEnablement({ kind: "note", pragma: true }, { canMoveUp: true, canMoveDown: true })
        .deleteRow,
      false,
      "the trash must be greyed, not left to fail as an error toast",
    );
  });

  test("a note exposes exactly its text as an editable param", () => {
    assert.deepStrictEqual(editableParamNames(note()), ["text"]);
  });
});

suite("route rows reach the IDE as a routing step, not a send", () => {
  test("a static route is titled Route; a routed-nowhere return is titled Unrouted, never Filter", () => {
    assert.strictEqual(rowTitle(route()), "Route");
    assert.strictEqual(rowTitle(route({ handlers: [], unrouted: true })), "Unrouted");
  });

  test("a route is editable, deletable and movable", () => {
    assert.strictEqual(isRowEditable("route"), true);
    assert.strictEqual(isRowMutable(route()), true);
    assert.strictEqual(isRowDeletable(route()), true);
    assert.strictEqual(isRowMovable(route()), true);
  });

  test("a route exposes its handler list — but a DYNAMIC return exposes nothing", () => {
    assert.deepStrictEqual(editableParamNames(route()), ["handlers"]);
    assert.deepStrictEqual(editableParamNames(route({ handlers: [], unrouted: true })), ["handlers"]);
    // `return [pick(msg)]`: empty handlers with NO `unrouted`. Editing it would flatten real code.
    assert.deepStrictEqual(editableParamNames(route({ handlers: [] })), []);
  });

  test("insert-after is suppressed on a route — a step after a routing return is dead code", () => {
    const menu = contextMenuEnablement({ kind: "route" }, { canMoveUp: true, canMoveDown: true });
    assert.strictEqual(menu.insertAfter, false);
    assert.strictEqual(menu.insertBefore, true);
    assert.strictEqual(menu.addDestination, false, "a route selects handlers, not outbound connections");
  });
});

suite("contract negotiation — skew is handled, not discovered", () => {
  test("the extension asks for the version it can RENDER", () => {
    assert.strictEqual(LENS_CONTRACT, 2);
  });

  test("an older engine's argument rejection is recognized, in each parser's wording", () => {
    for (const text of [
      "unrecognized arguments: --contract 2",
      "error: unrecognized argument --contract",
      "no such option: --contract",
      "unknown option '--contract'",
      "argument --contract: invalid choice: '2'",
    ]) {
      assert.strictEqual(looksLikeUnknownArgument(text), true, text);
      assert.strictEqual(isUnknownArgumentError(new Error(text)), true, text);
    }
  });

  test("a GENUINE refusal is NOT retried away as an argument problem", () => {
    // Each of these must fail loudly. If the predicate widened to match one, a real error would be
    // silently downgraded to a v1 projection and reported as success.
    for (const text of [
      "module.py: cannot parse (invalid syntax at line 12)",
      "unknown contract version 99 (supported: [1, 2])",
      "the row's source no longer matches the editor buffer (stale coordinates)",
      "row at lines 6-6 is a 'code' row",
      "workspace not trusted — MessageFoundry CLI disabled until you trust this workspace",
    ]) {
      assert.strictEqual(looksLikeUnknownArgument(text), false, text);
    }
  });
});

suite("an unknown row kind still degrades safely", () => {
  test("a kind this extension does not know is never draggable or deletable", () => {
    // Direction 1's backstop: the contract gate should mean this never happens, but if a future kind did
    // arrive, it must be inert rather than a half-wired control.
    const alien = { kind: "sparkle" as unknown as LensRow["kind"], line_start: 1, line_end: 1, nesting: 0 };
    assert.strictEqual(isRowMovable(alien as LensRow), false);
    assert.strictEqual(isRowDeletable(alien as LensRow), false);
    assert.deepStrictEqual(editableParamNames(alien as LensRow), []);
  });
});
