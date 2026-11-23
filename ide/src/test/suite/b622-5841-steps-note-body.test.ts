// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { buildRowViewModel, renderRowHtml, type LensRow } from "../../stepsModel";
import { loadPage, type DomNode } from "./b622-g09-steps-page";

// BACKLOG #5841: renderRowHtml drew a source body only for a `code` row, so at lens contract 2 every
// Comment and Pragma card had a blank body and no editable text field. A one-line Comment edits in a
// text input, a multi-line Comment in a textarea that keeps its line count (the engine's set_note
// refuses a text whose line count changed), and a Pragma stays read-only: the engine refuses to edit
// one (ADR 0076 A.4), because it is functional code that changes what ruff and mypy do to the file.

suite("b622 #5841 — Comment and Pragma rows render their text", () => {
  const lines = ["def h(msg):", "    # check the MRN", "    # fmt: off"];
  const comment: LensRow = {
    kind: "note",
    text: " check the MRN",
    raw: "    # check the MRN",
    pragma: false,
    line_start: 2,
    line_end: 2,
    nesting: 0,
    suite: "1",
  };
  const pragma: LensRow = {
    ...comment,
    text: " fmt: off",
    raw: "    # fmt: off",
    pragma: true,
    line_start: 3,
    line_end: 3,
  };
  const multi: LensRow = { ...comment, text: " a\n b", raw: "    # a\n    # b", line_end: 3 };
  const multiLines = ["def h(msg):", "    # a", "    # b"];

  test("a single-line Comment renders an editable text field holding its text", () => {
    const html = renderRowHtml(buildRowViewModel(comment, 0, lines), "h");
    assert.match(html, /<input [^>]*class="edit"[^>]*data-name="text"[^>]*value=" check the MRN"/);
  });

  test("a Pragma renders its line read-only, with no editable field", () => {
    const html = renderRowHtml(buildRowViewModel(pragma, 1, lines), "h");
    assert.match(html, /<pre class="code"> {4}# fmt: off<\/pre>/);
    assert.doesNotMatch(html, /data-name="text"/);
  });

  test("a multi-line Comment renders an editable textarea holding its lines", () => {
    const html = renderRowHtml(buildRowViewModel(multi, 0, multiLines), "h");
    assert.match(
      html,
      /<textarea class="edit" [^>]*data-name="text"[^>]*rows="2" data-lines="2">\n a\n b<\/textarea>/,
    );
    assert.doesNotMatch(html, /<pre class="code">/);
  });

  test("a read-only projection (no handler name) shows the Comment text in a disabled field", () => {
    const html = renderRowHtml(buildRowViewModel(comment, 0, lines));
    assert.match(html, /readonly disabled value=" check the MRN"/);
    const ro = renderRowHtml(buildRowViewModel(multi, 0, multiLines));
    assert.match(ro, /<textarea readonly disabled rows="2">\n a\n b<\/textarea>/);
  });

  // The page side: the shipped stepsWebview.js run against the real renderer under jsdom.
  function notePage(): { area: DomNode; page: ReturnType<typeof loadPage> } {
    const first: LensRow = { ...multi, text: "\n b", raw: "    #\n    # b" };
    const page = loadPage({
      parse: { module: "m", handlers: [{ handler: "h", module: "m", def_line: 1, rows: [first] }] },
      source: "def h(msg):\n    #\n    # b",
    });
    const area = page.doc.querySelector('textarea.edit[data-name="text"]');
    assert.ok(area, "the multi-line Comment has an editable textarea");
    return { area, page };
  }

  test("webview: a leading empty Comment line survives the HTML parser", () => {
    const { area } = notePage();
    assert.strictEqual(area.value, "\n b");
    assert.strictEqual(area.defaultValue, "\n b");
  });

  test("webview: an edit that keeps the line count posts the new text", () => {
    const { area, page } = notePage();
    area.value = " first\n second";
    area.dispatchEvent(new page.window.Event("change"));
    const edit = page.posted.find((m) => m.command === "edit");
    assert.ok(edit, "an edit was posted");
    assert.deepStrictEqual(
      [edit.name, edit.value, edit.lineStart, edit.lineEnd],
      ["text", " first\n second", 2, 3],
    );
  });

  test("webview: an edit that changes the line count is put back unposted, with a toast", () => {
    const { area, page } = notePage();
    area.value = " one\n two\n three";
    area.dispatchEvent(new page.window.Event("change"));
    assert.strictEqual(page.posted.find((m) => m.command === "edit"), undefined);
    assert.strictEqual(area.value, "\n b");
    const toast = page.posted.find((m) => m.command === "cutInfo");
    assert.ok(toast && typeof toast.text === "string" && /2 lines/.test(toast.text));
  });
});
