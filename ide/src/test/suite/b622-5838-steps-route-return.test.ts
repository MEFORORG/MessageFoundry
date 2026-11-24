// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import {
  ADD_MENU_BY_ID,
  buildAddMenuRequest,
  buildDropSlots,
  buildHandlerViewModels,
  buildPasteRequest,
  buildToolbarInsertRequest,
  isReturnRow,
  renderRowHtml,
  resolveDrop,
} from "../../stepsModel";
import { dropRows, routerAndHandler } from "./b622-g09-steps-page";

// BACKLOG #5838: isReturnRow did not count a Router's route row (its return statement) as a return,
// so the toolbar Add, paste, drag-and-drop and the arrow walk could place a statement after it.

suite("b622 #5838 — a Router route row counts as a return", () => {
  const route = { handler: "pick", lineStart: 3, lineEnd: 3, expectSrc: "x", kind: "route" as const };

  test("isReturnRow is true for a route row", () => {
    assert.strictEqual(isReturnRow({ kind: "route" }), true);
  });

  test("the toolbar Add, the Add menu and paste insert BEFORE a route row", () => {
    assert.strictEqual(buildToolbarInsertRequest(route, "set_field").position, "before");
    const req = buildAddMenuRequest(ADD_MENU_BY_ID["route"], route, { handlers: "H_ONE" });
    assert.strictEqual((req as { position?: string }).position, "before");
    const clip = { source: "x()", nesting: 0, kind: "action" as const, lineCount: 1, label: "1 step" };
    assert.strictEqual(buildPasteRequest(route, clip).position, "before");
  });

  test("a drop onto a route row clamps to before, and no slot lands after it", () => {
    const rows = dropRows(routerAndHandler());
    const target = rows.find((r) => r.lineStart === 3)!;
    const drag = rows.find((r) => r.lineStart === 2)!;
    assert.strictEqual(resolveDrop(drag, target, 0.9, rows)?.toPosition, "before");
    const slots = buildDropSlots(rows.filter((r) => r.handler === "pick"));
    assert.ok(!slots.some((s) => s.anchorLineStart === 3 && s.toPosition === "after"));
  });

  test("the route row renders data-is-return, so the webview treats it as a return", () => {
    const f = routerAndHandler();
    const vm = buildHandlerViewModels(f.parse, f.source)[0].rows[1];
    assert.strictEqual(vm.isReturn, true);
    assert.match(renderRowHtml(vm, "pick", undefined, "router"), /data-is-return="true"/);
  });
});
