// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { StepsPanelProjection, type AnchorMessage, type StructuralAnchor } from "../../stepsPanel";
import {
  ADD_MENU_BY_ID,
  buildAddMenuRequest,
  buildPasteRequest,
  buildToolbarInsertRequest,
  type HandlerViewModel,
  type LensParseResult,
  type RowKind,
  type RowViewModel,
} from "../../stepsModel";

// BACKLOG #5844. The paste, insertToolbar and insertItem handlers built their insert anchor from the
// row's kind alone, dropping the fan-out flags isReturnRow reads. A request that derives its position
// then put a new step BEFORE a mid-body `sends.append(Send(...))` (which takes one after it) and AFTER
// the `return sends` footer (dead code after the return). The page posts no flags with a paste at all,
// so the provider now takes the row's kind and flags from the panel's own projection.

const STEPS_VIEW_TS = path.join(__dirname, "..", "..", "..", "src", "stepsView.ts");

const row = (over: Partial<RowViewModel> & Pick<RowViewModel, "kind" | "lineStart" | "lineEnd">) =>
  ({ index: 0, nesting: 0, title: "", params: [], ...over }) as RowViewModel;

const APPEND = row({ kind: "send", lineStart: 6, lineEnd: 6, appended: true, expectSrc: "    sends.append(Send(\"OB\", msg))" });
const FOOTER = row({ kind: "code", lineStart: 7, lineEnd: 7, scaffold: "return_collector", expectSrc: "    return sends" });
const RETURN = row({ kind: "send", lineStart: 9, lineEnd: 9, expectSrc: "    return Send(\"OB\", msg)" });

const handlers: HandlerViewModel[] = [{ handler: "h", defLine: 1, role: "handler", rows: [APPEND, FOOTER, RETURN] }];
const parse: LensParseResult = {
  module: "m.py",
  handlers: [{ handler: "h", module: "m.py", def_line: 1, rows: [], role: "handler" }],
};

/** A webview message naming `r`, as the page posts a paste: coordinates, kind and source, no flags. */
const pasteMsg = (r: RowViewModel) => ({
  handler: "h",
  lineStart: r.lineStart,
  lineEnd: r.lineEnd,
  kind: r.kind,
  expectSrc: r.expectSrc,
});

const CLIP = { source: "x = 1", nesting: 0, kind: "code" as const, lineCount: 1, label: "" };

/** anchorFor, asserting it accepted the message. */
function anchorAt(p: StepsPanelProjection, m: AnchorMessage, fallbackKind?: RowKind): StructuralAnchor {
  const anchor = p.anchorFor(m, fallbackKind);
  assert.ok(anchor !== undefined, "anchorFor refused a well-formed message");
  return anchor;
}

suite("BACKLOG #5844: Steps insert anchors carry the row's fan-out flags", () => {
  const panel = new StepsPanelProjection();
  panel.update(parse, handlers);

  test("a paste at a mid-body append send lands after it", () => {
    const anchor = anchorAt(panel, pasteMsg(APPEND), "send");
    assert.strictEqual(anchor.appended, true);
    assert.strictEqual(buildPasteRequest(anchor, CLIP).position, "after");
  });

  test("a paste at the return-collector footer lands before it", () => {
    const anchor = anchorAt(panel, pasteMsg(FOOTER), "code");
    assert.strictEqual(anchor.scaffold, "return_collector");
    assert.strictEqual(buildPasteRequest(anchor, CLIP).position, "before");
  });

  test("a paste at a terminal return still lands before it", () => {
    assert.strictEqual(buildPasteRequest(anchorAt(panel, pasteMsg(RETURN), "send"), CLIP).position, "before");
  });

  test("a derived toolbar insert and Add-menu insert follow the same flags", () => {
    const append = anchorAt(panel, pasteMsg(APPEND), "send");
    const footer = anchorAt(panel, pasteMsg(FOOTER), "code");
    assert.strictEqual(buildToolbarInsertRequest(append, "set_field").position, "after");
    assert.strictEqual(buildToolbarInsertRequest(footer, "set_field").position, "before");
    const item = ADD_MENU_BY_ID.set_field;
    assert.strictEqual((buildAddMenuRequest(item, append, {}) as { position?: string }).position, "after");
    assert.strictEqual((buildAddMenuRequest(item, footer, {}) as { position?: string }).position, "before");
  });

  test("the projection's kind and flags win over what the message claims", () => {
    const anchor = anchorAt(panel, { ...pasteMsg(FOOTER), kind: "action", scaffold: 7 }, "code");
    assert.strictEqual(anchor.kind, "code");
    assert.strictEqual(anchor.scaffold, "return_collector");
  });

  test("a row the projection does not hold falls back to the message's own fields", () => {
    const anchor = anchorAt(panel, 
      { handler: "h", lineStart: 40, lineEnd: 40, kind: "send", appended: true, expectSrc: "y" },
      "send",
    );
    assert.deepStrictEqual(anchor, {
      handler: "h",
      lineStart: 40,
      lineEnd: 40,
      expectSrc: "y",
      kind: "send",
      appended: true,
      scaffold: undefined,
    });
  });

  test("a message whose source differs from the projected row's does not take the row's flags", () => {
    const anchor = anchorAt(panel, { ...pasteMsg(APPEND), expectSrc: "something else" }, "send");
    assert.strictEqual(anchor.appended, false, "a stale message keeps its own (absent) flags");
    assert.strictEqual(anchor.expectSrc, "something else", "the engine's stale check still sees it");
  });

  test("an untrusted non-string kind or flag is never passed through", () => {
    const anchor = anchorAt(new StepsPanelProjection(), {
      handler: "h",
      lineStart: 1,
      lineEnd: 1,
      kind: 3,
      appended: "true",
    });
    assert.strictEqual(anchor.kind, "send", "the default fallback kind");
    assert.strictEqual(anchor.expectSrc, undefined);
    assert.strictEqual(anchor.appended, false);
  });

  test("a non-string expectSrc is refused, never dropped into an op with no stale check", () => {
    for (const expectSrc of [4, null, { x: 1 }]) {
      assert.strictEqual(panel.anchorFor({ ...pasteMsg(APPEND), expectSrc }), undefined);
    }
  });

  test("each handler drops a message anchorFor refused", () => {
    const src = fs.readFileSync(STEPS_VIEW_TS, "utf8");
    const drops = src.match(/const anchor = panelState\.anchorFor\(m as AnchorMessage\);\s+if \(anchor === undefined\) \{\s+return;/g);
    assert.strictEqual(drops?.length, 4, "paste, insertToolbar, insertItem and addDestination each drop it");
  });

  // stepsView.ts imports vscode, so the provider cannot be loaded node-side; pin its wiring by scan.
  test("paste, insertToolbar, insertItem and addDestination build their anchor through anchorFor", () => {
    const src = fs.readFileSync(STEPS_VIEW_TS, "utf8");
    for (const command of ["paste", "insertToolbar", "insertItem", "addDestination"]) {
      const at = src.indexOf(`m?.command === "${command}"`);
      assert.ok(at >= 0, `stepsView.ts has no ${command} handler`);
      const next = src.indexOf("m?.command ===", at + 1);
      const body = src.slice(at, next < 0 ? undefined : next);
      assert.ok(/panelState\.anchorFor\(/.test(body), `the ${command} handler must build its anchor via anchorFor`);
    }
  });
});
