import * as assert from "assert";

import {
  ADD_MENU_BY_ID,
  ADD_MENU_CATALOG,
  STRUCTURAL_OPS,
  addMenuGroups,
  buildAddMenuRequest,
  buildRowViewModel,
  editableParamNames,
  isRowDeletable,
  isRowMovable,
  type AddMenuGroup,
  type LensRow,
} from "../../stepsModel";

const anchor = (kind: LensRow["kind"] = "action") => ({
  handler: "h",
  lineStart: 6,
  lineEnd: 6,
  expectSrc: "    set_field(msg, \"PID-3.1\", \"X\")",
  kind,
});
const base = { handler: "h", line_start: 6, line_end: 6, expect_src: "    set_field(msg, \"PID-3.1\", \"X\")" };

suite("Steps Add menu — grouped catalog (ADR 0106)", () => {
  test("the catalog spans the four ADR 0106 groups", () => {
    const groups = [...new Set(ADD_MENU_CATALOG.map((i) => i.group))];
    const expected: AddMenuGroup[] = ["Transform", "Translate & lookup", "Structure & flow", "Diagnostics"];
    assert.deepStrictEqual(groups, expected);
  });

  test("addMenuGroups() returns the four groups in order, each non-empty", () => {
    const g = addMenuGroups();
    assert.deepStrictEqual(
      g.map((x) => x.group),
      ["Transform", "Translate & lookup", "Structure & flow", "Diagnostics"],
    );
    assert.ok(g.every((x) => x.items.length > 0));
  });

  test("every item op is a supported lens op", () => {
    const ops = new Set(["insert_row", "template", "insert_clause", "insert_comment", "insert_code_lookup"]);
    for (const item of ADD_MENU_CATALOG) {
      assert.ok(ops.has(item.op), `${item.id} has an unknown op ${item.op}`);
    }
  });

  test("ADD_MENU_BY_ID is the by-id allowlist (keys == ids, no dups)", () => {
    const ids = ADD_MENU_CATALOG.map((i) => i.id);
    assert.strictEqual(new Set(ids).size, ids.length, "item ids must be unique");
    assert.deepStrictEqual(Object.keys(ADD_MENU_BY_ID).sort(), [...ids].sort());
  });

  test("STRUCTURAL_OPS covers every ADR 0106 insert op (each forces re-projection)", () => {
    for (const op of ["template", "insert_clause", "insert_comment", "insert_code_lookup"]) {
      assert.ok(STRUCTURAL_OPS.has(op), `${op} must be structural`);
    }
  });

  test("only Send uses the outbound-destination picker; db/fhir connections are free text", () => {
    // db_lookup / fhir_lookup connections live in [egress].allowed_db / allowed_http, not the outbound
    // graph, so a 'destination' picker would offer the wrong set (review finding).
    for (const id of ["db_lookup", "fhir_lookup"]) {
      const conn = ADD_MENU_BY_ID[id].prompts.find((p) => p.field === "connection");
      assert.strictEqual(conn?.kind, "text", `${id} connection must be free text`);
    }
    const destUsers = ADD_MENU_CATALOG.filter((i) => i.prompts.some((p) => p.kind === "destination"));
    assert.deepStrictEqual(
      destUsers.map((i) => i.id),
      ["send"],
    );
  });
});

suite("Steps Add menu — buildAddMenuRequest maps to the lens edit dict", () => {
  test("inline-fill insert_row seeds default params (no prompt)", () => {
    assert.deepStrictEqual(buildAddMenuRequest(ADD_MENU_BY_ID.set_field, anchor(), {}), {
      ...base,
      op: "insert_row",
      position: "after",
      action: "set_field",
      params: { path: "", value: "" },
    });
  });

  test("numeric params render as {expr} (not string literals)", () => {
    assert.deepStrictEqual(
      buildAddMenuRequest(ADD_MENU_BY_ID.substring_field, anchor(), { path: "PID-3.1", start: "0", end: "6" }),
      {
        ...base,
        op: "insert_row",
        position: "after",
        action: "substring_field",
        params: { path: "PID-3.1", start: { expr: "0" }, end: { expr: "6" } },
      },
    );
  });

  test("db_lookup gathers a var → assign_to and keeps its seed params dict", () => {
    assert.deepStrictEqual(
      buildAddMenuRequest(ADD_MENU_BY_ID.db_lookup, anchor(), { var: "row", connection: "MPI", statement: "select 1" }),
      {
        ...base,
        op: "insert_row",
        position: "after",
        action: "db_lookup",
        params: { params: { expr: "{}" }, connection: "MPI", statement: "select 1" },
        assign_to: "row",
      },
    );
  });

  test("code_lookup maps to insert_code_lookup", () => {
    assert.deepStrictEqual(
      buildAddMenuRequest(ADD_MENU_BY_ID.code_lookup, anchor(), { code_set: "gender", path: "PID-8" }),
      { ...base, op: "insert_code_lookup", position: "after", code_set: "gender", path: "PID-8" },
    );
  });

  test("if maps to a template op with the structured test", () => {
    assert.deepStrictEqual(
      buildAddMenuRequest(ADD_MENU_BY_ID.if, anchor(), { field: "PID-3.1", operator: "equals", value: "A" }),
      { ...base, op: "template", position: "after", template: "if", field: "PID-3.1", operator: "equals", value: "A" },
    );
  });

  test("else maps to an insert_clause op with no test", () => {
    assert.deepStrictEqual(buildAddMenuRequest(ADD_MENU_BY_ID.else, anchor(), {}), {
      ...base,
      op: "insert_clause",
      clause: "else",
    });
  });

  test("comment maps to insert_comment", () => {
    assert.deepStrictEqual(buildAddMenuRequest(ADD_MENU_BY_ID.comment, anchor(), { text: "note" }), {
      ...base,
      op: "insert_comment",
      position: "after",
      text: "note",
    });
  });

  test("a send anchor derives position 'before' (a new step precedes the return)", () => {
    const req = buildAddMenuRequest(ADD_MENU_BY_ID.log_note, anchor("send"), {});
    assert.strictEqual((req as { position: string }).position, "before");
  });
});

suite("Steps Add menu — new row kinds render + edit correctly", () => {
  const vm = (row: LensRow) => buildRowViewModel(row, 0, []);

  test("a diagnostic row titles + exposes only its literal (log_note template)", () => {
    const row: LensRow = {
      kind: "diagnostic",
      call: "log_note",
      params: { template: "MRN {}", arg1: 'msg.field("PID-3.1")' },
      literal_params: ["template"],
      line_start: 1,
      line_end: 1,
      nesting: 0,
    };
    assert.strictEqual(vm(row).title, "Log Note");
    assert.deepStrictEqual(editableParamNames(row), ["template"]); // operand is read-only
    assert.strictEqual(isRowMovable(row), true);
    assert.strictEqual(isRowDeletable(row), true);
  });

  test("a filtered send reads as 'Filter'", () => {
    const row: LensRow = { kind: "send", outbounds: [], filtered: true, line_start: 1, line_end: 1, nesting: 0 };
    assert.strictEqual(vm(row).title, "Filter");
  });

  test("a raise control is movable but NOT deletable (the engine refuses it)", () => {
    const row: LensRow = { kind: "control", control: "raise", line_start: 1, line_end: 1, nesting: 0 };
    assert.strictEqual(isRowMovable(row), true);
    assert.strictEqual(isRowDeletable(row), false);
  });
});
