// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { buildPasteRequest } from "../../stepsModel";
import { loadPage, withControls, type Page } from "./b622-g09-steps-page";

// BACKLOG #5839, the Paste remainder: a paste on a selected if/elif/else/for header was requested
// directly after the header line, which the engine's re-parse refuses. The page now resolves the
// anchor with resolveInsertAnchor and sends the body's first row with an explicit "before", and the
// provider passes that validated position through to buildPasteRequest.

const STEPS_VIEW_TS = path.join(__dirname, "..", "..", "..", "src", "stepsView.ts");
const CLIP = { source: "x = 1", nesting: 0, kind: "action" as const, lineCount: 1, label: "1 step" };

function key(page: Page, k: string): void {
  const KeyboardEvent = page.window.KeyboardEvent as new (type: string, init: object) => unknown;
  page.doc.dispatchEvent(
    new KeyboardEvent("keydown", { key: k, ctrlKey: true, bubbles: true, cancelable: true }),
  );
}

function pasteOn(lineStart: number): Record<string, unknown> | undefined {
  const page = loadPage(withControls());
  page.row(3).click();
  key(page, "c");
  page.row(lineStart).click();
  key(page, "v");
  return page.posted.find((m) => m.command === "paste");
}

suite("b622 #5839 — Paste on a control header lands as the block's first statement", () => {
  test("model: an explicit 'before' wins over the derived position", () => {
    const anchor = { handler: "h", lineStart: 3, lineEnd: 3, kind: "action" as const };
    assert.strictEqual(buildPasteRequest(anchor, CLIP).position, "after");
    assert.strictEqual(buildPasteRequest(anchor, CLIP, "before").position, "before");
    const send = { handler: "h", lineStart: 8, lineEnd: 8, kind: "send" as const };
    assert.strictEqual(buildPasteRequest(send, CLIP).position, "before");
    assert.strictEqual(buildPasteRequest(send, CLIP, "before").position, "before");
  });

  for (const [header, body, name] of [
    [2, 3, "if"],
    [4, 5, "else"],
    [6, 7, "for"],
  ] as const) {
    test(`webview: Ctrl+V on the ${name} header posts the body's first row, before`, () => {
      const paste = pasteOn(header);
      assert.ok(paste, "a paste was posted");
      assert.strictEqual(paste.lineStart, body);
      assert.strictEqual(paste.position, "before");
      assert.strictEqual(typeof paste.block, "string");
    });
  }

  // stepsView.ts imports vscode, so the provider cannot be loaded node-side; pin its wiring by scan.
  test("provider: the paste handler accepts only 'before' and forwards it to buildPasteRequest", () => {
    const src = fs.readFileSync(STEPS_VIEW_TS, "utf8");
    const at = src.indexOf('m?.command === "paste"');
    assert.ok(at >= 0, "stepsView.ts has a paste handler");
    // The paste branch is the last one, so bound it at the save subscription that follows the switch.
    const end = src.indexOf("vscode.workspace.onDidSaveTextDocument", at);
    assert.ok(end > at, "the save subscription follows the paste handler");
    const body = src.slice(at, end);
    const guard = /\(m\.position === undefined \|\| m\.position === "before"\)\s*\)/;
    const forwards = /buildPasteRequest\(\s*anchor,[^;]*?,\s*m\.position,\s*\)/;
    // Negative controls: the pre-fix guard and a call that drops the position do not match.
    assert.ok(!guard.test('(m.position === undefined || m.position === "before" || m.position === "after")\n)'));
    assert.ok(!forwards.test('buildPasteRequest(\n anchor,\n { source: m.block },\n),'));
    assert.ok(guard.test(body), "the paste guard admits an absent position or 'before', nothing else");
    assert.ok(!/m\.position === "after"/.test(body), "the paste guard does not admit 'after'");
    assert.ok(forwards.test(body), "the validated position reaches buildPasteRequest");
  });

  test("webview: Ctrl+V on a leaf row posts that row and no position, as before", () => {
    const paste = pasteOn(5);
    assert.ok(paste, "a paste was posted");
    assert.strictEqual(paste.lineStart, 5);
    assert.strictEqual("position" in paste, false);
  });
});
