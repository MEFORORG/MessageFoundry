// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { resolveInsertAnchor } from "../../stepsModel";
import { dropRows, loadPage, withControls, type DomNode } from "./b622-g09-steps-page";

// BACKLOG #5839: an insert AFTER an if/elif/else/for header was requested directly after the header
// line, at the header's indent, which the engine's re-parse refuses (an IndentationError). The Steps
// view now sends it as an insert BEFORE the block's first body row: the statement right below the
// header, which is where the view draws it.

suite("b622 #5839 — insert after a control header lands as the block's first statement", () => {
  test("model: resolveInsertAnchor maps 'after a header' to 'before the body's first row'", () => {
    const rows = dropRows(withControls());
    for (const [header, body] of [
      [2, 3],
      [4, 5],
      [6, 7],
    ]) {
      const got = resolveInsertAnchor(rows, header, "after");
      assert.strictEqual(got?.anchor.lineStart, body, `after the header at line ${header}`);
      assert.strictEqual(got?.position, "before");
    }
    // A leaf, and a 'before' on a header, are unchanged.
    const leaf = resolveInsertAnchor(rows, 3, "after");
    assert.deepStrictEqual([leaf?.anchor.lineStart, leaf?.position], [3, "after"]);
    const head = resolveInsertAnchor(rows, 2, "before");
    assert.deepStrictEqual([head?.anchor.lineStart, head?.position], [2, "before"]);
    assert.strictEqual(resolveInsertAnchor(rows, 99, "after"), null);
  });

  test("webview: the resolveInsertAnchor mirror agrees with the model on every row and position", () => {
    const f = withControls();
    const page = loadPage(f);
    const web = page.hook.stepsCtxRows();
    const rows = dropRows(f);
    for (const r of rows) {
      for (const pos of ["before", "after"] as const) {
        const w = page.hook.resolveInsertAnchor(web, r.lineStart, pos);
        const m = resolveInsertAnchor(rows, r.lineStart, pos);
        assert.deepStrictEqual(
          w === null ? null : [w.anchor.lineStart, w.position],
          m === null ? null : [m.anchor.lineStart, m.position],
          `line ${r.lineStart}, ${pos}`,
        );
      }
    }
  });

  test("webview: the toolbar Add on a selected if header posts the body's first row, before", () => {
    const page = loadPage(withControls());
    page.row(2).click();
    const sel = page.doc.getElementById("insertAction");
    const leaf = Array.from(sel.options as DomNode[]).find((o) => o.value !== "" && !o.dataset.anchor);
    assert.ok(leaf, "the toolbar offers a plain insert item");
    sel.value = leaf.value;
    sel.dispatchEvent(new page.window.Event("change"));
    page.doc.getElementById("addAction").click();
    const ins = page.posted.find((m) => m.command === "insertItem");
    assert.ok(ins, "an insertItem was posted");
    assert.strictEqual(ins.lineStart, 3);
    assert.strictEqual(ins.position, "before");
    assert.strictEqual(ins.kind, "action");
  });

  test("webview: Insert after on a for header posts the body's first row, before", () => {
    const page = loadPage(withControls());
    page.rightClick(page.row(6));
    const item = page.menuItem('.ctx-submenu[data-for="after"] .ctx-item[data-item-id]:not([data-anchor])');
    assert.strictEqual(item.disabled, false);
    item.click();
    const ins = page.posted.find((m) => m.command === "insertItem");
    assert.ok(ins, "an insertItem was posted");
    assert.strictEqual(ins.lineStart, 7);
    assert.strictEqual(ins.position, "before");
  });

  test("a blank-only first body row is skipped as the anchor", () => {
    const rows = [
      { lineStart: 2, kind: "control" as const, control: "if", suite: "1", expectSrc: "    if x:" },
      { lineStart: 3, kind: "code" as const, suite: "2", expectSrc: "   " },
      { lineStart: 4, kind: "action" as const, suite: "2", expectSrc: "        f()" },
    ];
    assert.strictEqual(resolveInsertAnchor(rows, 2, "after")?.anchor.lineStart, 4);
  });

  test("Insert before an else header offers only Comment, which cannot split the if-chain", () => {
    const page = loadPage(withControls());
    const before = (id: string): DomNode =>
      page.menuItem(`.ctx-submenu[data-for="before"] .ctx-item[data-item-id="${id}"]`);
    page.rightClick(page.row(4));
    assert.strictEqual(page.menuItem('.ctx-parent[data-sub="before"]').disabled, false);
    assert.strictEqual(before("comment").disabled, false, "a Comment above else: is accepted");
    assert.strictEqual(before("set_field").disabled, true, "a statement above else: is not");
    page.rightClick(page.row(2));
    assert.strictEqual(before("set_field").disabled, false, "before an if header it is offered");
  });

  test("webview: an Else clause insert on an if header keeps the header as its anchor", () => {
    const page = loadPage(withControls());
    page.rightClick(page.row(2));
    const clause = page.menuItem('.ctx-submenu[data-for="after"] .ctx-item[data-anchor="if_chain"]');
    assert.ok(clause, "the menu carries an if-chain clause item");
    clause.click();
    assert.strictEqual(page.posted.find((m) => m.command === "insertItem")?.lineStart, 2);
  });
});
