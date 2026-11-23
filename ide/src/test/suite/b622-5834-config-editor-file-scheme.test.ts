// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import {
  configNoticeHtml,
  isConfigDirCodeSetFile,
  isConfigDirConnectionsFile,
  isConfigDirDocument,
} from "../../configEditorModel";

// configEditors.ts imports vscode, so its wiring is pinned by reading its source.
const EDITORS = fs
  .readFileSync(path.join(__dirname, "..", "..", "..", "src", "configEditors.ts"), "utf8")
  .replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");

// BACKLOG #5834. The exact-file guard compared only fsPath. A git: revision tab of the config dir's own
// file has that same fsPath, so a save or remove from it would have written the working copy.
suite("configEditorModel: only a file: document is the config-dir file (BACKLOG #5834)", () => {
  const conn = "/ws/samples/config/connections.toml";
  const csv = "/ws/samples/config/codesets/diets.csv";

  test("the working copy itself (file:) passes the guard", () => {
    assert.strictEqual(
      isConfigDirDocument({ scheme: "file", fsPath: conn }, "/ws", "samples/config", isConfigDirConnectionsFile),
      true,
    );
    assert.strictEqual(
      isConfigDirDocument({ scheme: "file", fsPath: csv }, "/ws", "samples/config", isConfigDirCodeSetFile),
      true,
    );
  });

  for (const scheme of ["git", "untitled", "vscode-userdata", "FILE"]) {
    test(`a ${scheme}: document with the config-dir file's path is refused`, () => {
      assert.strictEqual(
        isConfigDirDocument({ scheme, fsPath: conn }, "/ws", "samples/config", isConfigDirConnectionsFile),
        false,
      );
      assert.strictEqual(
        isConfigDirDocument({ scheme, fsPath: csv }, "/ws", "samples/config", isConfigDirCodeSetFile),
        false,
      );
    });
  }

  test("a file: document that is not the config-dir file is still refused", () => {
    assert.strictEqual(
      isConfigDirDocument(
        { scheme: "file", fsPath: "/ws/other/connections.toml" },
        "/ws",
        "samples/config",
        isConfigDirConnectionsFile,
      ),
      false,
    );
  });

  // The pre-fix spellings, so each scan below is shown to fire on the code it guards against.
  const BARE_PATH = /isConfigDir(?:Connections|CodeSet)File\(document\.uri\.fsPath/;
  const CONN_GUARD = /isConfigDirDocument\(document\.uri, ws, target\.configDir, isConfigDirConnectionsFile\)/g;
  const CODESET_GUARD = /isConfigDirDocument\(document\.uri, ws, dir, isConfigDirCodeSetFile\)/g;

  test("control: the bare-path scan fires on the pre-fix guard lines", () => {
    assert.match("if (!isConfigDirConnectionsFile(document.uri.fsPath, ws, target.configDir)) {", BARE_PATH);
    assert.match("if (!isConfigDirCodeSetFile(document.uri.fsPath, ws, dir)) {", BARE_PATH);
    assert.doesNotMatch("if (!isConfigDirDocument(document.uri, ws, dir, isConfigDirCodeSetFile)) {", BARE_PATH);
  });

  test("wiring: every save and remove guard checks the scheme, none the bare path", () => {
    assert.strictEqual((EDITORS.match(CONN_GUARD) ?? []).length, 2, "connections save + remove");
    assert.strictEqual((EDITORS.match(CODESET_GUARD) ?? []).length, 2, "code-set save + remove");
    assert.doesNotMatch(EDITORS, BARE_PATH);
  });

  test("wiring: the open guard passes only a file: document through to the form", () => {
    const guard = EDITORS.slice(
      EDITORS.indexOf("function reopenAsTextIfNotConfigDirFile"),
      EDITORS.indexOf("function wrongTargetError"),
    );
    assert.ok(guard.length > 0, "open guard not found");
    // Every pass-through (return false) sits inside the file: branch.
    const fileBranch = guard.indexOf('if (scheme === "file") {');
    assert.ok(fileBranch !== -1, "no file: branch in the open guard");
    const passes = [...guard.matchAll(/return false/g)].map((m) => m.index ?? -1);
    assert.ok(passes.length > 0 && passes.every((i) => i > fileBranch && i < guard.indexOf("const inPlace")));
    // A revision is painted in place with its own text and is not reopened out of a diff.
    assert.match(guard, /const inPlace = scheme !== "file" && scheme !== "untitled";/);
    const inPlace = guard.slice(guard.indexOf("if (inPlace) {"), guard.indexOf("} else {"));
    assert.ok(inPlace.length > 0 && !/openWith/.test(inPlace));
    assert.match(guard, /panel\.webview\.html = configNoticeHtml\(notice, inPlace \? document\.getText\(\) : undefined\)/);
  });

  test("the non-file page escapes the revision's text and allows no script", () => {
    const html = configNoticeHtml("a <b> notice", "<script>x()</script> & \"q\"");
    assert.ok(!html.includes("<script>") && !html.includes("<b>"));
    assert.ok(html.includes("a &lt;b&gt; notice"));
    assert.ok(html.includes("&lt;script&gt;x()&lt;/script&gt; &amp; &quot;q&quot;"));
    assert.match(html, /default-src 'none'/);
    assert.doesNotMatch(html, /script-src/);
  });
});
