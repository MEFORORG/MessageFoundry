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

  test("wiring: every save and remove guard checks the scheme, none the bare path", () => {
    assert.strictEqual(
      (EDITORS.match(/isConfigDirDocument\(document\.uri, ws, target\.configDir, isConfigDirConnectionsFile\)/g) ?? [])
        .length,
      2,
      "connections save + remove",
    );
    assert.strictEqual(
      (EDITORS.match(/isConfigDirDocument\(document\.uri, ws, dir, isConfigDirCodeSetFile\)/g) ?? []).length,
      2,
      "code-set save + remove",
    );
    assert.doesNotMatch(EDITORS, /isConfigDir(?:Connections|CodeSet)File\(document\.uri\.fsPath/);
  });

  test("wiring: the open guard shows a non-file document as text before any form", () => {
    const guard = EDITORS.slice(EDITORS.indexOf("function reopenAsTextIfNotConfigDirFile"));
    const scheme = guard.indexOf('const nonFile = document.uri.scheme !== "file";');
    assert.ok(scheme !== -1, "no scheme check in the open guard");
    assert.ok(scheme < guard.indexOf("if (!nonFile)"), "the pass-through must be gated on the scheme");
    assert.ok(guard.indexOf("if (!nonFile)") < guard.indexOf("return false"), "pass-through only for file:");
    // The non-file branch shows the revision's own text and does not reopen it out of a diff.
    const branch = guard.slice(guard.indexOf("if (nonFile) {"), guard.indexOf("} else {"));
    assert.match(branch, /text = document\.getText\(\)/);
    assert.doesNotMatch(branch, /openWith/);
    assert.match(guard, /panel\.webview\.html = configNoticeHtml\(notice, text\)/);
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
