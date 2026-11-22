// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import { isConfigDirCodeSetFile, isConfigDirConnectionsFile, isConfigDirDocument } from "../../configEditorModel";

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
});
