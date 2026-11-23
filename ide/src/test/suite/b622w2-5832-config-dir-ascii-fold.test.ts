// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import { isConfigDirCodeSetFile, isConfigDirConnectionsFile } from "../../configEditorModel";

// BACKLOG #5832, added item 1. The containment check folded case with toLowerCase(), which maps
// U+212A KELVIN SIGN onto ASCII "k". NTFS upcases "k" to "K" and leaves U+212A as itself, so the two
// spell different directories there, yet the check took one for the other.
const KELVIN = "\u212A";

suite("configEditorModel: case folding is ASCII-only (BACKLOG #5832)", () => {
  test("a directory spelled with U+212A is not the config dir spelled with k, on win32", () => {
    assert.strictEqual(
      isConfigDirConnectionsFile(`C:\\ws\\${KELVIN}its\\connections.toml`, "C:\\ws", "kits", "win32"),
      false,
    );
    assert.strictEqual(
      isConfigDirCodeSetFile(`C:\\ws\\${KELVIN}its\\codesets\\diets.csv`, "C:\\ws", "kits", "win32"),
      false,
    );
    // And the other way round: the config dir is the U+212A spelling, the file is under "kits".
    assert.strictEqual(
      isConfigDirConnectionsFile("C:\\ws\\kits\\connections.toml", "C:\\ws", `${KELVIN}its`, "win32"),
      false,
    );
  });

  test("U+212A is not folded onto k on darwin either", () => {
    assert.strictEqual(isConfigDirConnectionsFile("/ws/kits/connections.toml", "/ws", `${KELVIN}its`, "darwin"), false);
    assert.strictEqual(isConfigDirCodeSetFile(`/ws/${KELVIN}its/codesets/a.csv`, "/ws", "kits", "darwin"), false);
  });

  test("control: an ASCII case difference still folds on win32 and darwin", () => {
    assert.strictEqual(isConfigDirConnectionsFile("C:\\WS\\KITS\\Connections.TOML", "C:\\ws", "kits", "win32"), true);
    assert.strictEqual(isConfigDirCodeSetFile("/WS/Kits/CodeSets/Diets.CSV", "/ws", "kits", "darwin"), true);
  });
});
