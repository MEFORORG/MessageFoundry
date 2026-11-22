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

  test("a Router row's Insert submenu can still open: a greyed item never hides its submenu", () => {
    const page = loadPage(routerAndHandler());
    page.rightClick(page.row(2));
    const sub = page.doc.querySelector('#stepsCtxMenu .ctx-sub:has(> .ctx-parent[data-sub="before"])');
    assert.strictEqual(sub.classList.contains("ctx-disabled"), false, "the before submenu is not suppressed");
    sub.dispatchEvent(new page.window.Event("mouseenter"));
    assert.strictEqual(sub.classList.contains("ctx-open"), true, "hovering opens it");
    const route = page.menuItem('.ctx-submenu[data-for="before"] .ctx-item[data-item-id="route"]');
    assert.strictEqual(route.disabled, false, "Route To is offered in a Router");
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
