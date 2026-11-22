// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { buildPasteRequest } from "../../stepsModel";
import { loadPage, withControls, type Page } from "./b622-g09-steps-page";

// BACKLOG #5839, the Paste remainder: a paste on a selected if/elif/else/for header was requested
// directly after the header line, which the engine's re-parse refuses. The page now resolves the
// anchor with resolveInsertAnchor and sends the body's first row with an explicit "before", and the
// provider passes that validated position through to buildPasteRequest.

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
  test("model: an explicit position wins over the derived one", () => {
    const anchor = { handler: "h", lineStart: 3, lineEnd: 3, kind: "action" as const };
    assert.strictEqual(buildPasteRequest(anchor, CLIP).position, "after");
    assert.strictEqual(buildPasteRequest(anchor, CLIP, "before").position, "before");
    const send = { handler: "h", lineStart: 8, lineEnd: 8, kind: "send" as const };
    assert.strictEqual(buildPasteRequest(send, CLIP).position, "before");
    assert.strictEqual(buildPasteRequest(send, CLIP, "after").position, "after");
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

  test("webview: Ctrl+V on a leaf row posts that row and no position, as before", () => {
    const paste = pasteOn(5);
    assert.ok(paste, "a paste was posted");
    assert.strictEqual(paste.lineStart, 5);
    assert.strictEqual("position" in paste, false);
  });
});
