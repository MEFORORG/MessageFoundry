import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  buildEditRequest,
  buildHandlerViewModels,
  renderRowHtml,
  resolveWidget,
  type EditMessage,
  type LensRow,
  type OpSchema,
} from "../../stepsModel";

// BACKLOG #235 — the Steps-view param INPUT widgets are driven by the engine's `lens schema` output
// (op -> editable params with their kind), not a hand-rolled IDE table. These are the pure, vscode-free
// renderer + edit-mapping tests (the CI ide job has no Python, so they consume a CANNED op-schema
// fixture — a faithful dump of `messagefoundry lens schema` — never shelling the CLI). Covers: an int
// param -> a type=number input, an enum param -> a <select>, the number round-trip (a number reaches the
// engine as a JSON number, not a re-typed string), the text fallback for an op absent from the schema +
// byte-identity when no schema is supplied, and a light op-name parity drift guard.

// A dedicated fixtures subdir — NOT fixtures/lens/, which steps.test.ts enumerates wholesale as `lens
// parse` results (a differently-shaped op-schema there would break that iteration). This is a canned dump
// of `messagefoundry lens schema` (the CI ide job has no Python, so the renderer tests never shell it).
const FIXTURE_DIR = path.join(__dirname, "..", "..", "..", "src", "test", "fixtures", "lens-schema");

function loadOpSchema(): OpSchema {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, "op-schema.json"), "utf8")) as OpSchema;
}

// The vocabulary verb names (actions.__all__ + diagnostics.__all__) — the source of truth the fixture's
// op names must stay a subset of. A light drift guard; it does NOT model the structural Add-menu catalog.
const VOCABULARY = new Set<string>([
  "copy_field",
  "set_field",
  "append_to_field",
  "trim_field",
  "substring_field",
  "pad_field",
  "replace_literal",
  "convert_case",
  "arith_field",
  "format_date",
  "date_diff_field",
  "split_field",
  "code_lookup",
  "copy_segment",
  "delete_segment",
  "log_note",
  "checkpoint",
]);

/** Fold one contract row into its rendered view-model (a synthetic source with enough lines). */
function rowVm(row: LensRow) {
  const source = Array.from({ length: row.line_end + 1 }, (_, i) => `line_${i + 1}`).join("\n");
  return buildHandlerViewModels(
    { module: "m", handlers: [{ handler: "h", module: "m", def_line: 1, rows: [row] }] },
    source,
  )[0].rows[0];
}

const CONVERT_CASE_ROW: LensRow = {
  kind: "action",
  action: "convert_case",
  params: { path: "PID-8", mode: "upper" },
  literal_params: ["path", "mode"],
  line_start: 2,
  line_end: 2,
  nesting: 0,
};

const SUBSTRING_ROW: LensRow = {
  kind: "action",
  action: "substring_field",
  params: { path: "PID-5", start: 0, end: 3 },
  literal_params: ["path", "start", "end"],
  line_start: 2,
  line_end: 2,
  nesting: 0,
};

const DB_LOOKUP_ROW: LensRow = {
  kind: "lookup",
  call: "db_lookup",
  params: { connection: "pkms", statement: "SELECT 1", params: "{}" },
  literal_params: ["connection", "statement"],
  line_start: 2,
  line_end: 2,
  nesting: 0,
};

suite("Steps param schema — schema-driven input widgets (#235)", () => {
  test("an enum param renders a <select> with the current value selected", () => {
    // An INLINE schema (not the fixture) so this proves the RENDERER reacts to an `enum` kind regardless
    // of whether the live engine currently emits one for `mode` (that hinges on the actions.py Literal
    // enrichment, reported as an open question) — and so regenerating the faithful fixture never breaks it.
    const schema: OpSchema = {
      convert_case: [
        { name: "path", kind: "str", required: true, keyword_only: false },
        {
          name: "mode",
          kind: "enum",
          choices: ["upper", "lower", "title"],
          required: true,
          keyword_only: false,
        },
      ],
    };
    const html = renderRowHtml(rowVm(CONVERT_CASE_ROW), "h", schema);
    assert.ok(html.includes("<select"), "the enum param renders a <select>");
    assert.ok(html.includes('class="edit"'), "the <select> is an editable widget");
    assert.ok(
      html.includes('value="upper" selected'),
      "the current value is the selected option",
    );
    assert.ok(html.includes('<option value="lower"'), "every choice is an option");

    // FALSIFY: with NO schema the same row renders a plain text input, so the <select> assertion fails.
    const noSchema = renderRowHtml(rowVm(CONVERT_CASE_ROW), "h");
    assert.ok(!noSchema.includes("<select"), "no schema -> no dropdown (falsification guard)");
    assert.ok(noSchema.includes('type="text"'), "no schema -> the mode param is a text input");
  });

  test("an enum whose current value is outside the choices still displays that value", () => {
    // A hand-authored literal the vocabulary no longer lists must still SHOW as the selected option, not
    // silently display the FIRST choice while the underlying argument is unchanged (a <select> with no
    // selected <option> renders its first option). The out-of-set option round-trips like any other.
    const schema: OpSchema = {
      convert_case: [
        { name: "path", kind: "str", required: true, keyword_only: false },
        {
          name: "mode",
          kind: "enum",
          choices: ["upper", "lower", "title"],
          required: true,
          keyword_only: false,
        },
      ],
    };
    const outOfSet: LensRow = {
      kind: "action",
      action: "convert_case",
      params: { path: "PID-8", mode: "camel" }, // `camel` is not among the schema's choices
      literal_params: ["path", "mode"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    const html = renderRowHtml(rowVm(outOfSet), "h", schema);
    assert.ok(
      html.includes('<option value="camel" selected>camel</option>'),
      "the out-of-set value is shown as the selected option",
    );
    assert.ok(
      !html.includes('value="upper" selected'),
      "no in-set choice is selected when the current value is out-of-set",
    );
  });

  test("an int param renders a type=number input", () => {
    const schema = loadOpSchema();
    const html = renderRowHtml(rowVm(SUBSTRING_ROW), "h", schema);
    assert.ok(html.includes('type="number"'), "the int `start`/`end` params render number fields");
    assert.ok(html.includes('class="edit"'), "the number input is editable");
    assert.ok(html.includes('data-name="start"'), "the number widget keeps its edit coordinates");

    // FALSIFY: with NO schema `start`/`end` render as text inputs, so the number assertion fails.
    const noSchema = renderRowHtml(rowVm(SUBSTRING_ROW), "h");
    assert.ok(!noSchema.includes('type="number"'), "no schema -> text inputs (falsification guard)");
  });

  test("a number-kind field round-trips to the engine as a JSON number", () => {
    // The webview posts a JS number for a number widget; buildEditRequest must carry it through so
    // JSON.stringify emits a bare `6` (an int literal), never `"6"` (a re-typed string literal — the
    // latent _render_literal corruption on the editable substring start/end + pad width).
    const msg: EditMessage = {
      command: "edit",
      handler: "h",
      lineStart: 2,
      lineEnd: 2,
      name: "start",
      value: 6,
    };
    const req = buildEditRequest(msg);
    assert.strictEqual(req.params.start, 6, "the value stays a number");
    assert.strictEqual(typeof req.params.start, "number", "typeof is number, not string");
    assert.ok(JSON.stringify(req).includes('"start":6'), "serializes as a bare number");
    assert.ok(!JSON.stringify(req).includes('"start":"6"'), "NOT as a quoted string");
  });

  test("an op absent from the schema falls back to a text input", () => {
    const schema = loadOpSchema();
    assert.ok(schema.db_lookup === undefined, "precondition: db_lookup is not in the vocabulary schema");
    const html = renderRowHtml(rowVm(DB_LOOKUP_ROW), "h", schema);
    assert.ok(html.includes('data-name="connection"'), "the connection param is editable");
    assert.ok(html.includes('type="text"'), "an unmapped op keeps the current text input");
    assert.ok(!html.includes("<select"), "an unmapped op never invents a dropdown");
    assert.ok(!html.includes('type="number"'), "an unmapped op never invents a number field");

    // FALSIFY protection for the existing steps-edit assertions: a 2-arg (no-schema) call is unchanged —
    // it emits only text inputs (never a select/number), so the byte-shape the other suite pins holds.
    const twoArg = renderRowHtml(rowVm(SUBSTRING_ROW), "h");
    assert.ok(twoArg.includes('type="text"') && !twoArg.includes('type="number"'));
    assert.ok(!twoArg.includes("<select"));
  });

  test("parity: every fixture op is a real verb and every param resolves to a defined widget", () => {
    const schema = loadOpSchema();
    const allowed = new Set(["text", "number", "enum"]);
    for (const [op, params] of Object.entries(schema)) {
      assert.ok(VOCABULARY.has(op), `${op} is a real actions/diagnostics verb`);
      for (const p of params) {
        const widget = resolveWidget(op, p.name, schema);
        assert.ok(allowed.has(widget.kind), `${op}.${p.name} resolves to a defined widget`);
      }
    }

    // FALSIFY: a bogus op in the schema is caught by the real-verb assertion.
    const tampered: OpSchema = { ...schema, foo: [{ name: "x", kind: "str", required: true, keyword_only: false }] };
    assert.ok(!VOCABULARY.has("foo"), "a bogus op is not a real verb (falsification guard)");
    assert.ok(Object.keys(tampered).includes("foo"));
  });
});
