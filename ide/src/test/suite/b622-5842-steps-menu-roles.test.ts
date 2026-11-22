// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { contextMenuEnablement } from "../../stepsModel";
import { loadPage, routerAndHandler, type DomNode } from "./b622-g09-steps-page";

// BACKLOG #5842: the shared row context menu greyed the Add items outside a row's role but never
// enabled them again, so once a Router row was right-clicked the Handler-only items stayed grey on
// every Handler row; and it offered Insert after on a Router route row.

suite("b622 #5842 — the context menu re-enables role-scoped items and greys Insert after on a route", () => {
  test("handler-only items are enabled again on a Handler row after a Router row was right-clicked", () => {
    const page = loadPage(routerAndHandler());
    const handlerOnly = (): DomNode[] =>
      Array.from(
        page.doc.querySelectorAll('#stepsCtxMenu .ctx-item[data-item-id][data-role-scope="handler"]'),
      );
    page.rightClick(page.row(6));
    const enabled = handlerOnly().filter((b) => !b.disabled).length;
    assert.ok(enabled > 0, "a Handler row enables handler-only items");
    page.rightClick(page.row(2));
    assert.ok(handlerOnly().every((b) => b.disabled), "a Router row greys every handler-only item");
    page.rightClick(page.row(6));
    assert.strictEqual(handlerOnly().filter((b) => !b.disabled).length, enabled);
  });

  test("Insert after is greyed on a Router route row, in the model and in the webview", () => {
    assert.strictEqual(
      contextMenuEnablement({ kind: "route" }, { canMoveUp: false, canMoveDown: false }).insertAfter,
      false,
    );
    const page = loadPage(routerAndHandler());
    page.rightClick(page.row(3));
    assert.strictEqual(page.menuItem('.ctx-parent[data-sub="after"]').disabled, true);
    page.rightClick(page.row(2));
    assert.strictEqual(page.menuItem('.ctx-parent[data-sub="after"]').disabled, false);
  });
});
