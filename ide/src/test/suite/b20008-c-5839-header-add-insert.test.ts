// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { loadPage, withControls, type DomNode } from "./b622-g09-steps-page";

// BACKLOG #5839: Add and Insert after on a selected if, else or for header requested an insert directly
// after the header line, which the engine's re-parse refuses. Each case below drives the shipped page
// script through the DOM only, so it runs against the script before and after the fix: before it, the
// post names the header's own line and "after"; after it, the body's first row and "before".
// withControls(): if at line 2 (body line 3), else at line 4 (body line 5), for at line 6 (body line 7).

const HEADERS: readonly { name: string; header: number; body: number }[] = [
  { name: "if", header: 2, body: 3 },
  { name: "else", header: 4, body: 5 },
  { name: "for", header: 6, body: 7 },
];

function insertPosted(posted: DomNode[]): DomNode {
  const ins = posted.find((m) => m.command === "insertItem");
  assert.ok(ins, "an insertItem was posted");
  return ins;
}

suite("b20008 C #5839 -- Add and Insert after on an if, else or for header", () => {
  for (const { name, header, body } of HEADERS) {
    test(`toolbar Add on a selected ${name} header posts the body's first row, before`, () => {
      const page = loadPage(withControls());
      page.row(header).click();
      const sel = page.doc.getElementById("insertAction");
      const leaf = Array.from(sel.options as DomNode[]).find((o) => o.value !== "" && !o.dataset.anchor);
      assert.ok(leaf, "the toolbar offers a plain insert item");
      sel.value = leaf.value;
      sel.dispatchEvent(new page.window.Event("change"));
      page.doc.getElementById("addAction").click();
      const ins = insertPosted(page.posted);
      assert.deepStrictEqual([ins.lineStart, ins.position], [body, "before"]);
    });

    test(`context menu Insert after on a ${name} header posts the body's first row, before`, () => {
      const page = loadPage(withControls());
      page.rightClick(page.row(header));
      const item = page.menuItem('.ctx-submenu[data-for="after"] .ctx-item[data-item-id]:not([data-anchor])');
      assert.strictEqual(item.disabled, false);
      item.click();
      const ins = insertPosted(page.posted);
      assert.deepStrictEqual([ins.lineStart, ins.position], [body, "before"]);
    });
  }
});
