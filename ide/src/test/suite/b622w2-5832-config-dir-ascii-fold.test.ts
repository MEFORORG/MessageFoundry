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

  // APFS may well treat the two spellings as one directory. Reading them as different there is not a
  // fixed false match but a safe fallback: the file opens in the text editor rather than the form.
  test("darwin: a U+212A spelling falls back to outside, the same one rule as win32", () => {
    assert.strictEqual(isConfigDirConnectionsFile("/ws/kits/connections.toml", "/ws", `${KELVIN}its`, "darwin"), false);
    assert.strictEqual(isConfigDirCodeSetFile(`/ws/${KELVIN}its/codesets/a.csv`, "/ws", "kits", "darwin"), false);
  });

  test("a non-ASCII case difference NTFS would fold is outside too, by design", () => {
    // E-acute against e-acute: the same directory on NTFS, but no ASCII-only fold can say so, and
    // erring this way only loses the form editor for that spelling.
    assert.strictEqual(isConfigDirConnectionsFile("C:\\ws\\Caf\u00C9\\connections.toml", "C:\\ws", "caf\u00E9", "win32"), false);
    assert.strictEqual(isConfigDirConnectionsFile("C:\\ws\\caf\u00E9\\connections.toml", "C:\\ws", "caf\u00E9", "win32"), true);
  });

  test("control: an ASCII case difference still folds on win32 and darwin", () => {
    assert.strictEqual(isConfigDirConnectionsFile("C:\\WS\\KITS\\Connections.TOML", "C:\\ws", "kits", "win32"), true);
    assert.strictEqual(isConfigDirCodeSetFile("/WS/Kits/CodeSets/Diets.CSV", "/ws", "kits", "darwin"), true);
  });

  test("UNC paths: the same share is inside, another share or server is not", () => {
    const dir = "\\\\srv\\share\\cfg";
    assert.strictEqual(isConfigDirConnectionsFile("\\\\srv\\share\\cfg\\connections.toml", "C:\\ws", dir, "win32"), true);
    assert.strictEqual(isConfigDirConnectionsFile("\\\\SRV\\Share\\CFG\\connections.toml", "C:\\ws", dir, "win32"), true);
    assert.strictEqual(isConfigDirConnectionsFile("\\\\srv\\other\\cfg\\connections.toml", "C:\\ws", dir, "win32"), false);
    assert.strictEqual(isConfigDirConnectionsFile("\\\\host\\share\\cfg\\connections.toml", "C:\\ws", dir, "win32"), false);
    assert.strictEqual(isConfigDirConnectionsFile("C:\\share\\cfg\\connections.toml", "C:\\ws", dir, "win32"), false);
    // A UNC share root as the config dir.
    assert.strictEqual(isConfigDirConnectionsFile("\\\\srv\\share\\connections.toml", "C:\\ws", "\\\\srv\\share\\", "win32"), true);
  });
});
