// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import { isConfigDirCodeSetFile, isConfigDirConnectionsFile } from "../../configEditorModel";

// BACKLOG #5832. The guard in front of the custom editors decides whether connections.toml or a
// codesets file opens in the form or falls back to text. It joined the config dir onto the workspace
// without resolving dot segments, so `./samples/config` and `.` never matched, and it lower-cased both
// sides on every platform, so a wrong-cased path counted as the config dir's file on a case-sensitive
// filesystem.
const conns = isConfigDirConnectionsFile;
const codeset = isConfigDirCodeSetFile;

suite("configEditorModel: the config dir is resolved before comparing (BACKLOG #5832)", () => {
  test("a ./-prefixed relative config dir matches its own files", () => {
    assert.strictEqual(conns("/ws/samples/config/connections.toml", "/ws", "./samples/config", "linux"), true);
    assert.strictEqual(conns("/ws/other/connections.toml", "/ws", "./samples/config", "linux"), false);
  });

  test("a config dir of '.' is the workspace itself", () => {
    assert.strictEqual(conns("/ws/connections.toml", "/ws", ".", "linux"), true);
    assert.strictEqual(codeset("/ws/codesets/diets.csv", "/ws", ".", "linux"), true);
    assert.strictEqual(conns("/elsewhere/connections.toml", "/ws", ".", "linux"), false);
  });

  test("dot segments inside the config dir or the file path are resolved", () => {
    assert.strictEqual(conns("/ws/samples/config/connections.toml", "/ws", "samples/x/../config", "linux"), true);
    assert.strictEqual(conns("/ws/samples/config/../other/connections.toml", "/ws", "samples/config", "linux"), false);
  });

  test("a root config dir", () => {
    assert.strictEqual(conns("/connections.toml", "/ws", "/", "linux"), true);
    assert.strictEqual(conns("C:\\connections.toml", "C:\\ws", "C:\\", "win32"), true);
    assert.strictEqual(conns("D:\\connections.toml", "C:\\ws", "C:\\", "win32"), false);
  });

  test("a wrong-cased path is not the config dir's file on a case-sensitive filesystem", () => {
    assert.strictEqual(conns("/ws/Samples/Config/connections.toml", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(conns("/ws/samples/config/connections.toml", "/ws", "samples/config", "linux"), true);
  });

  test("case is folded where the platform filesystem is case-insensitive by default", () => {
    assert.strictEqual(conns("C:\\WS\\Samples\\Config\\connections.toml", "C:\\ws", "samples\\config", "win32"), true);
    assert.strictEqual(conns("/srv/WS/Config/connections.toml", "/srv/ws", "config", "darwin"), true);
  });

  test("a sibling that shares a name prefix, or a dir named like '..x', is judged by segment", () => {
    assert.strictEqual(conns("/ws/samples/config-backup/connections.toml", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(conns("/ws/..x/connections.toml", "/ws", "..x", "linux"), true);
  });

  test("a file on another Windows drive is not the config dir's file", () => {
    assert.strictEqual(conns("D:\\ws\\config\\connections.toml", "C:\\ws", "config", "win32"), false);
  });
});

// The custom editors read and write the exact file the CLI edits, so the guard asks for that file, not
// for any file under the config dir. With a config dir of "." every nested connections.toml in the
// workspace is under it, and each would otherwise be shown and saved as the workspace root's file.
suite("configEditorModel: the custom editors open only the file the CLI edits", () => {
  test("connections.toml: the config dir's own, not a nested or wrong-cased one", () => {
    assert.strictEqual(conns("/ws/samples/config/connections.toml", "/ws", ".", "linux"), false);
    assert.strictEqual(conns("/ws/Connections.toml", "/ws", ".", "linux"), false);
    assert.strictEqual(conns("C:\\ws\\Connections.TOML", "C:\\ws", ".", "win32"), true);
  });

  test("a code set: <configDir>/codesets/<stem>.csv or .toml, not one nested deeper", () => {
    assert.strictEqual(codeset("/ws/samples/config/codesets/diets.csv", "/ws", "samples/config", "linux"), true);
    assert.strictEqual(codeset("/ws/samples/config/codesets/legacy.toml", "/ws", "samples/config", "linux"), true);
    assert.strictEqual(codeset("/ws/samples/config/old/codesets/diets.csv", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(codeset("/ws/samples/results_relay/codesets/t.csv", "/ws", ".", "linux"), false);
    assert.strictEqual(codeset("/ws/samples/config/CodeSets/diets.csv", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(codeset("/ws/samples/config/codesets/Diets.CSV", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(codeset("C:\\ws\\cfg\\CodeSets\\diets.CSV", "C:\\ws", "cfg", "win32"), true);
  });
});
