// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { buildDropSlots, walkMove } from "../../stepsModel";
import { dropRows, loadPage, plain, twoHandlers } from "./b622-g09-steps-page";

// BACKLOG #5830 (the webview's stepsCtxRows gathered every section's rows) and #5840 (buildDropSlots
// seeded only the first function's suite): Move up and Move down were greyed for every step of the
// second and later Handler or Router in a module.

suite("b622 #5830/#5840 — Move up/down in every function of a multi-function module", () => {
  test("model: buildDropSlots enumerates the root suite of every function, in document order", () => {
    const suites = new Set(buildDropSlots(dropRows(twoHandlers())).map((s) => s.toSuite));
    assert.deepStrictEqual([...suites], ["1", "6"]);
  });

  test("model: walkMove moves a step of the SECOND handler, and never across a handler", () => {
    const rows = dropRows(twoHandlers());
    assert.deepStrictEqual(walkMove(rows, 8, "up"), {
      anchorLineStart: 7,
      anchorLineEnd: 7,
      toPosition: "before",
      toSuite: "6",
      landingDepth: 0,
    });
    assert.ok(walkMove(rows, 7, "down"), "the second handler's first step moves down");
    // The first handler's last movable step cannot walk down into the second handler, nor the second
    // handler's first step up into the first.
    assert.strictEqual(walkMove(rows, 3, "down"), null);
    assert.strictEqual(walkMove(rows, 7, "up"), null);
  });

  test("webview: the second handler's arrows are enabled, and its mirrors agree with the model", () => {
    const f = twoHandlers();
    const page = loadPage(f);
    assert.strictEqual(page.row(8).querySelector('button.rowop[data-op="moveUp"]').disabled, false);
    assert.strictEqual(page.row(7).querySelector('button.rowop[data-op="moveDown"]').disabled, false);
    const rows = dropRows(f);
    const webRows = page.hook.stepsCtxRows();
    for (const r of rows) {
      for (const dir of ["up", "down"] as const) {
        assert.deepStrictEqual(
          plain(page.hook.walkMove(webRows, r.lineStart, dir)),
          plain(walkMove(rows, r.lineStart, dir)),
          `walkMove('${dir}') at line ${r.lineStart}`,
        );
      }
    }
    assert.deepStrictEqual(plain(page.hook.buildDropSlots(webRows)), plain(buildDropSlots(rows)));
  });

  test("webview: the context menu's Move up is enabled on the second handler's step and posts moveTo", () => {
    const page = loadPage(twoHandlers());
    page.rightClick(page.row(8));
    const up = page.menuItem('.ctx-item[data-cmd="moveUp"]');
    assert.strictEqual(up.disabled, false);
    up.click();
    const move = page.posted.find((m) => m.command === "moveTo");
    assert.ok(move, "a moveTo was posted");
    assert.strictEqual(move.handler, "second");
    assert.strictEqual(move.toSuite, "6");
    assert.strictEqual(move.toLineStart, 7);
  });
});
