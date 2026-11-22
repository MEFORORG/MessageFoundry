// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import { codeSetEditorUpsertArgs } from "../../configEditorModel";

// BACKLOG #5834. The code-set custom editor saved with `codeset upsert` and no `--name`, which the CLI
// reads as a create (`create = --name is None`), so every save of the opened file was refused as a
// collision with that same file.
suite("configEditorModel: code-set custom editor upsert argv (BACKLOG #5834)", () => {
  const detail = { name: "epic_diets", format: "csv", columns: ["key", "value"], rows: [["A", "B"]] };

  test("a save of the opened file passes --name <stem>, so the CLI treats it as an edit", () => {
    const out = codeSetEditorUpsertArgs("samples/config", "epic_diets", { readonly: false, unloaded: false }, detail);
    assert.ok("args" in out, JSON.stringify(out));
    const i = out.args.indexOf("--name");
    assert.ok(i !== -1, `no --name in ${out.args.join(" ")}`);
    assert.strictEqual(out.args[i + 1], "epic_diets");
    assert.deepStrictEqual(out.args.slice(0, 4), ["codeset", "upsert", "--config", "samples/config"]);
    assert.strictEqual(out.args[out.args.indexOf("--data") + 1], JSON.stringify(detail));
  });

  test("a read-only (.toml) code set is refused before any write", () => {
    const out = codeSetEditorUpsertArgs("samples/config", "epic_diets", { readonly: true, unloaded: false }, detail);
    assert.ok("error" in out);
    assert.match(out.error, /read-only/);
  });

  test("a posted name other than the file's stem is refused, not written as another code set", () => {
    const out = codeSetEditorUpsertArgs("samples/config", "other_table", { readonly: false, unloaded: false }, detail);
    assert.ok("error" in out);
    assert.match(out.error, /other_table/);
    assert.match(out.error, /nothing was written/);
  });

  test("a file whose content never loaded into the grid is refused, not replaced by the empty grid", () => {
    const out = codeSetEditorUpsertArgs("samples/config", "epic_diets", { readonly: false, unloaded: true }, detail);
    assert.ok("error" in out);
    assert.match(out.error, /did not load/);
    assert.match(out.error, /nothing was written/);
  });
});
