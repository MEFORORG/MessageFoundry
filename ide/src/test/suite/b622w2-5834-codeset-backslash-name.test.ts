// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import { codeSetNameFromPath, isConfigDirCodeSetFile } from "../../configEditorModel";

// BACKLOG #5834, added item 1. On posix `a\b.csv` is one file name, so it passed the exact-path check,
// but codeSetNameFromPath splits on `\` as well as `/` and named it `b`, so the editor showed and
// saved code set `b`, a different file. Such a name now falls back to the text editor.
suite("configEditorModel: a code-set file name holding a backslash is refused (BACKLOG #5834)", () => {
  test("posix: codesets/a\\b.csv is not a code-set file the editor opens", () => {
    // The mismatch the refusal exists for.
    assert.strictEqual(codeSetNameFromPath("/ws/config/codesets/a\\b.csv"), "b");
    assert.strictEqual(isConfigDirCodeSetFile("/ws/config/codesets/a\\b.csv", "/ws", "config", "linux"), false);
    assert.strictEqual(isConfigDirCodeSetFile("/ws/config/codesets/a\\b.toml", "/ws", "config", "darwin"), false);
  });

  test("control: a plain name, and one holding other punctuation, still open", () => {
    assert.strictEqual(isConfigDirCodeSetFile("/ws/config/codesets/a_b.csv", "/ws", "config", "linux"), true);
    assert.strictEqual(isConfigDirCodeSetFile("/ws/config/codesets/a b-c.csv", "/ws", "config", "linux"), true);
    assert.strictEqual(isConfigDirCodeSetFile("C:\\ws\\config\\codesets\\a_b.csv", "C:\\ws", "config", "win32"), true);
  });
});
