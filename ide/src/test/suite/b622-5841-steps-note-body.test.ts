// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { buildRowViewModel, renderRowHtml, type LensRow } from "../../stepsModel";

// BACKLOG #5841: renderRowHtml drew a source body only for a `code` row, so at lens contract 2 every
// Comment and Pragma card had a blank body and no editable text field.

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

  test("a single-line Comment renders an editable text field holding its text", () => {
    const html = renderRowHtml(buildRowViewModel(comment, 0, lines), "h");
    assert.match(html, /<input [^>]*class="edit"[^>]*data-name="text"[^>]*value=" check the MRN"/);
  });

  test("a Pragma renders its line read-only, with no editable field", () => {
    const html = renderRowHtml(buildRowViewModel(pragma, 1, lines), "h");
    assert.match(html, /<pre class="code"> {4}# fmt: off<\/pre>/);
    assert.doesNotMatch(html, /data-name="text"/);
  });

  test("a multi-line Comment renders its lines read-only (one text box cannot hold them)", () => {
    const multi: LensRow = { ...comment, text: " a\n b", raw: "    # a\n    # b", line_end: 3 };
    const html = renderRowHtml(buildRowViewModel(multi, 0, ["def h(msg):", "    # a", "    # b"]), "h");
    assert.match(html, /<pre class="code"> {4}# a\n {4}# b<\/pre>/);
    assert.doesNotMatch(html, /data-name="text"/);
  });

  test("a read-only projection (no handler name) shows the Comment text in a disabled field", () => {
    const html = renderRowHtml(buildRowViewModel(comment, 0, lines));
    assert.match(html, /readonly disabled value=" check the MRN"/);
  });
});
