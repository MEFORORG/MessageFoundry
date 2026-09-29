// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import {
  type EditMessage,
  type LensRow,
  type RowViewModel,
  type TemplatePart,
  buildEditRequest,
  buildRowViewModel,
  classifyRewriteRefusal,
  isTemplateValue,
  paramModeOf,
  paramModeViews,
  paramWritableModes,
  readTemplateParts,
  templateValue,
} from "../../stepsModel";

// BACKLOG #237 step 2: the IDE model reads ADR 0076 Amendment E's per-argument modes. The engine half
// (the classifier, `param_parts`, `template_params` and the `{"parts"}` write) is asserted in
// tests/test_lens_param_modes.py and tests/test_lens_template_edit.py.
//
// The contract-2 rows below are VERBATIM `lens.parse_source(src, contract=2)` output, taken on branch
// b180/237-lens-edit-spec at 5d7a274ca, for a handler whose body is:
//
//     set_field(msg, "PID-5.1", "SMITH")                                      # line 8
//     set_field(msg, "PID-5.2", f"MRN {msg['PID-3.1']} / {msg['PID-5.1']}")   # line 9
//     set_field(msg, "PID-5.3", msg["PID-5.1"] + "x")                         # line 10
//     copy_field(msg, "PID-5.1", f"x{msg['PID-3']}")                          # line 11
//     append_to_field(msg, "PID-5.1", f"-{msg.field('PID-3', 2)}")            # line 12
//     msg.set("OBX-5", "V", occurrence=2)                                     # line 13
//     log_note(f"seen {msg['PID-3']}")                                        # line 14
//     row = db_lookup("DB", "select 1", {})                                   # line 15
//
// Only the `suite` key is dropped. Nothing else is edited, so a change to the wire format shows up here
// as a mismatch against a real engine payload rather than against a guess.

const STATIC_LITERAL: LensRow = {
  kind: "action",
  action: "set_field",
  params: { path: "PID-5.1", value: "SMITH" },
  literal_params: ["path", "value"],
  line_start: 8,
  line_end: 8,
  nesting: 0,
  param_modes: { path: "static", value: "static" },
  param_parts: {},
  template_params: ["value"],
};

const TEMPLATED_VALUE: LensRow = {
  kind: "action",
  action: "set_field",
  params: { path: "PID-5.2", value: "f\"MRN {msg['PID-3.1']} / {msg['PID-5.1']}\"" },
  literal_params: ["path"],
  line_start: 9,
  line_end: 9,
  nesting: 0,
  param_modes: { path: "static", value: "templated" },
  param_parts: {
    value: [{ text: "MRN " }, { path: "PID-3.1" }, { text: " / " }, { path: "PID-5.1" }],
  },
  template_params: ["value"],
};

const DYNAMIC_VALUE: LensRow = {
  kind: "action",
  action: "set_field",
  params: { path: "PID-5.3", value: 'msg["PID-5.1"] + "x"' },
  literal_params: ["path"],
  line_start: 10,
  line_end: 10,
  nesting: 0,
  param_modes: { path: "static", value: "dynamic" },
  param_parts: {},
  template_params: [],
};

const TEMPLATED_LOCATOR: LensRow = {
  kind: "action",
  action: "copy_field",
  params: { src: "PID-5.1", dst: "f\"x{msg['PID-3']}\"" },
  literal_params: ["src"],
  line_start: 11,
  line_end: 11,
  nesting: 0,
  param_modes: { src: "static", dst: "templated" },
  param_parts: { dst: [{ text: "x" }, { path: "PID-3" }] },
  template_params: [],
};

const TEMPLATED_NO_PARTS: LensRow = {
  kind: "action",
  action: "append_to_field",
  params: { path: "PID-5.1", suffix: "f\"-{msg.field('PID-3', 2)}\"" },
  literal_params: ["path"],
  line_start: 12,
  line_end: 12,
  nesting: 0,
  param_modes: { path: "static", suffix: "templated" },
  param_parts: { suffix: null },
  template_params: ["suffix"],
};

const NATIVE_DISPLAY: LensRow = {
  kind: "action",
  action: "set_field",
  params: { path: "OBX-5", value: "V", occurrence: 2 },
  literal_params: ["path", "value"],
  line_start: 13,
  line_end: 13,
  nesting: 0,
  param_modes: { path: "static", value: "static", occurrence: "static" },
  param_parts: {},
  template_params: ["value"],
};

const DIAGNOSTIC_TEMPLATE: LensRow = {
  kind: "diagnostic",
  call: "log_note",
  params: { template: "f\"seen {msg['PID-3']}\"" },
  literal_params: [],
  line_start: 14,
  line_end: 14,
  nesting: 0,
  param_modes: { template: "templated" },
  param_parts: { template: [{ text: "seen " }, { path: "PID-3" }] },
  template_params: [],
};

const LOOKUP: LensRow = {
  kind: "lookup",
  call: "db_lookup",
  params: { connection: "DB", statement: "select 1", params: "{}" },
  literal_params: ["connection", "statement"],
  line_start: 15,
  line_end: 15,
  nesting: 0,
  param_modes: { connection: "static", statement: "static", params: "dynamic" },
  param_parts: {},
  template_params: [],
  assign_to: "row",
};

const ENGINE_ROWS: LensRow[] = [
  STATIC_LITERAL,
  TEMPLATED_VALUE,
  DYNAMIC_VALUE,
  TEMPLATED_LOCATOR,
  TEMPLATED_NO_PARTS,
  NATIVE_DISPLAY,
  DIAGNOSTIC_TEMPLATE,
  LOOKUP,
];

/** The same row as an engine that predates Amendment E (or contract 1) would send it: no mode maps. */
function withoutModes(row: LensRow): LensRow {
  const copy: LensRow = { ...row };
  delete copy.param_modes;
  delete copy.param_parts;
  delete copy.template_params;
  return copy;
}

const vmOf = (row: LensRow): RowViewModel => buildRowViewModel(row, 0, []);

suite("Steps modes: the three modes read from the engine's maps (ADR 0076 E.4)", () => {
  test("a literal argument is static, and stays writable as a literal", () => {
    const views = paramModeViews(STATIC_LITERAL);
    assert.deepStrictEqual(views, {
      path: { mode: "static", writable: ["static"] },
      // A value param the engine lists in template_params can ALSO be written as a template.
      value: { mode: "static", writable: ["static", "templated"] },
    });
  });

  test("a templated value argument carries its parts and may switch either way", () => {
    const views = paramModeViews(TEMPLATED_VALUE);
    assert.deepStrictEqual(views?.value, {
      mode: "templated",
      parts: [{ text: "MRN " }, { path: "PID-3.1" }, { text: " / " }, { path: "PID-5.1" }],
      writable: ["static", "templated"],
    });
    assert.deepStrictEqual(views?.path, { mode: "static", writable: ["static"] });
  });

  test("a dynamic argument is read-only, whatever else the row says", () => {
    const views = paramModeViews(DYNAMIC_VALUE);
    assert.deepStrictEqual(views?.value, { mode: "dynamic", writable: [] });
    // A contradictory row (a dynamic name in both engine lists) still reads as read-only: the mode wins.
    const contradictory: LensRow = {
      ...DYNAMIC_VALUE,
      literal_params: ["path", "value"],
      template_params: ["value"],
    };
    assert.deepStrictEqual(paramModeViews(contradictory)?.value, { mode: "dynamic", writable: [] });
  });

  test("a templated argument outside template_params shows its parts but offers no write", () => {
    // copy_field's dst is a locator, so the engine refuses a template there and issues no permission.
    assert.deepStrictEqual(paramModeViews(TEMPLATED_LOCATOR)?.dst, {
      mode: "templated",
      parts: [{ text: "x" }, { path: "PID-3" }],
      writable: [],
    });
    // A log_note template is logged unredacted, so it is never a template write either (E.6, section 9).
    assert.deepStrictEqual(paramModeViews(DIAGNOSTIC_TEMPLATE)?.template, {
      mode: "templated",
      parts: [{ text: "seen " }, { path: "PID-3" }],
      writable: [],
    });
  });

  test("a templated argument with no parts form carries parts null and stays writable", () => {
    // msg.field("PID-3", 2) has no parts form. The engine still accepts a fresh template or a literal.
    assert.deepStrictEqual(paramModeViews(TEMPLATED_NO_PARTS)?.suffix, {
      mode: "templated",
      parts: null,
      writable: ["static", "templated"],
    });
  });

  test("a static display keyword is shown but never writable (E.10)", () => {
    // `occurrence=` is static by shape and absent from literal_params by design.
    assert.deepStrictEqual(paramModeViews(NATIVE_DISPLAY)?.occurrence, {
      mode: "static",
      writable: [],
    });
  });

  test("a lookup's dynamic params argument is read-only; its literals keep their edit", () => {
    assert.deepStrictEqual(paramModeViews(LOOKUP), {
      connection: { mode: "static", writable: ["static"] },
      statement: { mode: "static", writable: ["static"] },
      params: { mode: "dynamic", writable: [] },
    });
  });

  test("the view-model carries the modes, and the selector helpers read them", () => {
    const vm = vmOf(TEMPLATED_VALUE);
    assert.ok(vm.paramModes);
    assert.strictEqual(paramModeOf(vm, "value"), "templated");
    assert.deepStrictEqual(paramWritableModes(vm, "value"), ["static", "templated"]);
    assert.deepStrictEqual(paramWritableModes(vm, "path"), ["static"]);
    assert.strictEqual(paramModeOf(vmOf(DYNAMIC_VALUE), "value"), "dynamic");
    assert.deepStrictEqual(paramWritableModes(vmOf(DYNAMIC_VALUE), "value"), []);
  });

  test("rows without typed arguments carry no modes", () => {
    const send: LensRow = { kind: "send", outbounds: ["OUT"], line_start: 16, line_end: 16, nesting: 0 };
    const code: LensRow = { kind: "code", line_start: 17, line_end: 17, nesting: 0 };
    assert.strictEqual(paramModeViews(send), undefined);
    assert.strictEqual(paramModeViews(code), undefined);
    assert.strictEqual(vmOf(send).paramModes, undefined);
  });
});

suite("Steps modes: modes widen nothing that was editable before (ADR 0076 E.10)", () => {
  test("editableParams is exactly literal_params on every engine row, with modes or without", () => {
    // Pinned per row rather than compared with editableParamNames, which would compare it with itself.
    const expected: Record<number, string[]> = {
      8: ["path", "value"],
      9: ["path"],
      10: ["path"],
      11: ["src"],
      12: ["path"],
      13: ["path", "value"],
      14: [],
      15: ["connection", "statement"],
    };
    for (const row of ENGINE_ROWS) {
      const where = `row at line ${row.line_start}`;
      assert.deepStrictEqual(vmOf(row).editableParams, expected[row.line_start], where);
      assert.deepStrictEqual(vmOf(withoutModes(row)).editableParams, expected[row.line_start], where);
    }
  });

  test("static-and-writable-as-static agrees with literal_params in both directions (AC-M2)", () => {
    for (const row of ENGINE_ROWS) {
      const views = paramModeViews(row) ?? {};
      const literal = new Set(row.literal_params ?? []);
      for (const [name, view] of Object.entries(views)) {
        const where = `${name} at line ${row.line_start}`;
        if (view.mode === "static") {
          // Over static arguments, "writable as a literal" is exactly literal_params, both directions.
          assert.strictEqual(view.writable.includes("static"), literal.has(name), where);
        }
        if (literal.has(name)) {
          assert.strictEqual(view.mode, "static", `${where} is literal but not static`);
        }
      }
    }
  });

  test("no argument outside template_params is ever offered a template write", () => {
    for (const row of ENGINE_ROWS) {
      const templateOk = new Set(row.template_params ?? []);
      for (const [name, view] of Object.entries(paramModeViews(row) ?? {})) {
        const where = `${name} at line ${row.line_start}`;
        assert.strictEqual(view.writable.includes("templated"), templateOk.has(name), where);
      }
    }
  });
});

suite("Steps modes: an absent map falls back to the literal split (ADR 0076 E.8)", () => {
  test("a row with no param_modes has no modes, and is never read as all-dynamic", () => {
    for (const row of ENGINE_ROWS) {
      const old = withoutModes(row);
      assert.strictEqual(paramModeViews(old), undefined);
      const vm = vmOf(old);
      assert.strictEqual(vm.paramModes, undefined);
      for (const name of Object.keys(old.params ?? {})) {
        assert.strictEqual(paramModeOf(vm, name), undefined, `${name} got a mode from nothing`);
        const expected = (old.literal_params ?? []).includes(name) ? ["static"] : [];
        assert.deepStrictEqual(paramWritableModes(vm, name), expected, `${name} at ${old.line_start}`);
      }
    }
  });

  test("a hand-built row with neither map keeps the old all-editable reading", () => {
    const bare: LensRow = {
      kind: "action",
      action: "copy_field",
      params: { src: "PID-5.1", dst: "NK1-2.1" },
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    const vm = vmOf(bare);
    assert.deepStrictEqual(paramWritableModes(vm, "src"), ["static"]);
    assert.deepStrictEqual(paramWritableModes(vm, "dst"), ["static"]);
  });

  test("modes without template_params or param_parts (an engine between the two) offer no template", () => {
    // The shape engine main emits after PR 1170 and before the template edit spec: modes only.
    const partial: LensRow = { ...TEMPLATED_VALUE };
    delete partial.param_parts;
    delete partial.template_params;
    const views = paramModeViews(partial);
    assert.deepStrictEqual(views?.value, { mode: "templated", writable: [] });
    assert.deepStrictEqual(views?.path, { mode: "static", writable: ["static"] });
  });

  test("modes without literal_params grant no literal write (the all-editable reading is pre-modes)", () => {
    const row: LensRow = { ...NATIVE_DISPLAY };
    delete row.literal_params;
    const views = paramModeViews(row);
    assert.deepStrictEqual(views?.occurrence, { mode: "static", writable: [] });
    assert.deepStrictEqual(views?.path, { mode: "static", writable: [] });
    // template_params still grants its own writes, the literal switch included.
    assert.deepStrictEqual(views?.value, { mode: "static", writable: ["static", "templated"] });
  });

  test("an unknown mode string or a missing key falls back for that argument alone", () => {
    const skewed: LensRow = {
      ...TEMPLATED_VALUE,
      param_modes: { value: "computed" }, // a mode a newer engine might add; `path` is missing
    };
    const vm = vmOf(skewed);
    assert.deepStrictEqual(vm.paramModes, {});
    assert.strictEqual(paramModeOf(vm, "value"), undefined);
    assert.deepStrictEqual(paramWritableModes(vm, "value"), []); // not a literal, so read-only as before
    assert.deepStrictEqual(paramWritableModes(vm, "path"), ["static"]);
  });

  test("a malformed param_modes value is treated as absent", () => {
    for (const bad of [null, ["static"], "static"]) {
      const row = { ...TEMPLATED_VALUE, param_modes: bad } as unknown as LensRow;
      assert.strictEqual(paramModeViews(row), undefined, JSON.stringify(bad));
    }
  });

  // The committed fixtures under fixtures/lens/ are NOT used for the fallback: measured on this base, they
  // carry no action, lookup or diagnostic row at all, so a fold over them passes over an empty set. The
  // engine rows above, stripped by withoutModes, are the fallback's corpus instead.
});

suite("Steps modes: parts on the wire and into a set_params payload", () => {
  test("engine parts round-trip unchanged into the rewrite payload", () => {
    const parts = paramModeViews(TEMPLATED_VALUE)?.value.parts;
    assert.ok(parts);
    const msg: EditMessage = {
      command: "edit",
      handler: "H",
      lineStart: TEMPLATED_VALUE.line_start,
      lineEnd: TEMPLATED_VALUE.line_end,
      name: "value",
      value: templateValue(parts),
      expectSrc: "    set_field(...)",
    };
    const req = buildEditRequest(msg);
    assert.deepStrictEqual(req, {
      handler: "H",
      line_start: 9,
      line_end: 9,
      op: "set_params",
      params: {
        value: { parts: [{ text: "MRN " }, { path: "PID-3.1" }, { text: " / " }, { path: "PID-5.1" }] },
      },
      expect_src: "    set_field(...)",
    });
    // The payload the CLI receives is JSON, and it parses back to the same parts.
    const wire = JSON.parse(JSON.stringify(req)) as { params: { value: { parts: unknown } } };
    assert.deepStrictEqual(readTemplateParts(wire.params.value.parts), parts);
  });

  test("a malformed posted template reaches the engine unchanged, so the engine refuses it", () => {
    // Repairing it here (dropping the second key) would write a template the user never built.
    const posted = {
      parts: [{ text: "a", path: "PID-3" } as unknown as TemplatePart],
    };
    const req = buildEditRequest({
      command: "edit",
      handler: "H",
      lineStart: 9,
      lineEnd: 9,
      name: "value",
      value: posted,
    });
    assert.deepStrictEqual(req.params.value, { parts: [{ text: "a", path: "PID-3" }] });
    assert.strictEqual(isTemplateValue(posted), false);
    assert.strictEqual(req.expect_src, undefined);
  });

  test("the model's parts are copies, so editing them never edits the projected row", () => {
    const parts = paramModeViews(TEMPLATED_VALUE)?.value.parts;
    assert.ok(parts);
    parts.push({ path: "PID-8" });
    const again = paramModeViews(TEMPLATED_VALUE)?.value.parts;
    assert.strictEqual(again?.length, 4);
    const edited = templateValue(parts);
    edited.parts.pop();
    assert.strictEqual(parts.length, 5);
  });

  test("templateValue copies the list but never repairs a part", () => {
    const bad = [{ text: "a", path: "PID-3" } as unknown as TemplatePart];
    assert.deepStrictEqual(templateValue(bad), { parts: [{ text: "a", path: "PID-3" }] });
  });

  test("a param named like an Object member is an own key, never an inherited one", () => {
    // Built from JSON, as the wire delivers it: an object literal's `__proto__` key sets the prototype.
    const row: LensRow = {
      ...STATIC_LITERAL,
      params: JSON.parse('{"__proto__": "X", "constructor": "Y"}') as Record<string, unknown>,
      literal_params: [],
      param_modes: JSON.parse('{"__proto__": "static", "constructor": "computed"}') as Record<string, string>,
      template_params: [],
    };
    const vm = vmOf(row);
    assert.deepStrictEqual(Object.keys(vm.paramModes ?? {}), ["__proto__"]);
    assert.strictEqual(paramModeOf(vm, "__proto__"), "static");
    assert.strictEqual(paramModeOf(vm, "constructor"), undefined);
    assert.strictEqual(paramModeOf(vm, "toString"), undefined);
    assert.deepStrictEqual(paramWritableModes(vm, "constructor"), []);
    assert.deepStrictEqual(paramWritableModes(vm, "toString"), []);
  });

  test("switching a templated argument to static sends a plain scalar, as before", () => {
    const req = buildEditRequest({
      command: "edit",
      handler: "H",
      lineStart: 9,
      lineEnd: 9,
      name: "value",
      value: "plain",
    });
    assert.deepStrictEqual(req.params, { value: "plain" });
  });

  test("readTemplateParts accepts exactly the wire shape and nothing looser", () => {
    assert.deepStrictEqual(readTemplateParts([]), []);
    assert.deepStrictEqual(readTemplateParts([{ text: "" }, { path: "PID-3" }]), [
      { text: "" },
      { path: "PID-3" },
    ]);
    for (const bad of [
      null,
      undefined,
      "PID-3",
      { path: "PID-3" },
      [{ text: "a", path: "PID-3" }],
      [{ value: "a" }],
      [{ path: 3 }],
      [null],
      [["path", "PID-3"]],
    ]) {
      assert.strictEqual(readTemplateParts(bad), null, JSON.stringify(bad));
    }
  });

  test("malformed engine parts read as no parts form, never as a crash", () => {
    const row: LensRow = { ...TEMPLATED_VALUE, param_parts: { value: [{ text: 1 }] } };
    assert.strictEqual(paramModeViews(row)?.value.parts, null);
    // Parts sent for a non-templated argument are ignored: only a templated argument has parts.
    const stray: LensRow = { ...STATIC_LITERAL, param_parts: { value: [{ path: "PID-3" }] } };
    assert.strictEqual(paramModeViews(stray)?.value.parts, undefined);
  });

  test("isTemplateValue accepts only {parts: [...]} with well-formed parts", () => {
    assert.strictEqual(isTemplateValue({ parts: [{ path: "PID-3" }] }), true);
    assert.strictEqual(isTemplateValue({ parts: [] }), true);
    assert.strictEqual(isTemplateValue({ parts: [{ path: "PID-3" }], x: 1 }), false);
    assert.strictEqual(isTemplateValue({ expr: "msg['PID-3']" }), false);
    assert.strictEqual(isTemplateValue({ parts: "PID-3" }), false);
    assert.strictEqual(isTemplateValue("PID-3"), false);
    assert.strictEqual(isTemplateValue(null), false);
    assert.strictEqual(isTemplateValue([{ path: "PID-3" }]), false);
  });
});

suite("Steps modes: the engine's set_params refusals are classified by kind", () => {
  // The messages below are the engine's own refusal text (messagefoundry/lens.py on the same base).
  const cases: Array<[string, string | undefined]> = [
    [
      "parameter 'value' is in dynamic mode (an expression the lens cannot write back faithfully) - it " +
        "is read-only here; edit it as text (ADR 0076 E.6.4)",
      "dynamic",
    ],
    [
      "parameter 'value': the expression would write a dynamic-mode argument, which is read-only - only " +
        "a literal or a template may be written here (ADR 0076 E.6.4)",
      "dynamic",
    ],
    [
      "parameter 'dst' takes a literal only: only a value parameter takes a template (set_field or " +
        "add_repetition value, append_to_field suffix, replace_literal new); a path, segment id, index or " +
        "setting chosen by message content is refused",
      "literal-only",
    ],
    [
      "parameter 'value': write a template as {'parts': [...]}, not as an expression, so the engine " +
        "renders it and checks it reads back",
      "template-shape",
    ],
    ["parameter 'value': 'parts' must be a list of part objects", "template-shape"],
    [
      "parameter 'value': part 0 must be an object with exactly one key, 'text' or 'path'",
      "template-shape",
    ],
    ["parameter 'value': part 0 must be {'text': <string>} or {'path': <string>}", "template-shape"],
    [
      "parameter 'value': part 1 path '' must be non-empty, with no quote, backslash, brace or " +
        "non-printable character",
      "template-shape",
    ],
    [
      "parameter 'value': a template needs at least one 'path' part - plain text is static mode, so send " +
        "it as a literal value instead",
      "template-shape",
    ],
    [
      "this edit would make line 9 97 columns wide, past the 88-column limit - shorten the template, or " +
        "edit it as text",
      "column-limit",
    ],
    ["parameter 'value': an object value must be {'parts': [...]} or {'expr': <source>}", "template-shape"],
    [
      "parameter 'value': part 0 carries a character that cannot be encoded as UTF-8",
      "template-shape",
    ],
    [
      "parameter 'value': the template did not render to a bounded interpolation that reads back to the " +
        "same parts - refused (no change made)",
      "template-shape",
    ],
    // A refused path is quoted verbatim, so a path spelling another family's needle stays template-shape.
    [
      "parameter 'value': part 0 path 'a\"is in dynamic mode' must be non-empty, with no quote, " +
        "backslash, brace or non-printable character",
      "template-shape",
    ],
    // Not mode refusals: a note's over-long comment, a route row's list refusal, a stale coordinate.
    ["the edited comment would be 95 columns — over the 88-column limit; shorten it", undefined],
    ["a route row's 'handlers' must be a list of handler-name strings", undefined],
    // A user-chosen handler name quoted in an unrelated error must not spell a mode refusal.
    ["no recognized row at lines 3-3 in handler 'exactly one key'", undefined],
    ["unknown or absent parameter(s) ['is in dynamic mode'] for this call", undefined],
    [
      "the row's source no longer matches the editor buffer (stale coordinates) - re-project the Steps " +
        "view and retry",
      undefined,
    ],
  ];

  for (const [message, kind] of cases) {
    test(`${kind ?? "not a mode refusal"}: ${message.slice(0, 60)}`, () => {
      assert.strictEqual(classifyRewriteRefusal(message), kind);
    });
  }

  test("no error, no kind", () => {
    assert.strictEqual(classifyRewriteRefusal(undefined), undefined);
    assert.strictEqual(classifyRewriteRefusal(""), undefined);
  });
});
