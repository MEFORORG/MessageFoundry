// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import { isConfigDirCodeSetFile, isConfigDirConnectionsFile, isUnderConfigDir } from "../../configEditorModel";

// BACKLOG #5832. isUnderConfigDir decides whether connections.toml or a codesets file opens in the
// form or falls back to text. It joined the config dir onto the workspace without resolving dot
// segments, so `./samples/config` and `.` never matched, and it lower-cased both sides on every
// platform, so a wrong-cased path counted as inside the config dir on a case-sensitive filesystem.
suite("configEditorModel: isUnderConfigDir resolves the config dir (BACKLOG #5832)", () => {
  test("a ./-prefixed relative config dir matches its own files", () => {
    assert.strictEqual(isUnderConfigDir("/ws/samples/config/connections.toml", "/ws", "./samples/config", "linux"), true);
    assert.strictEqual(isUnderConfigDir("/ws/other/connections.toml", "/ws", "./samples/config", "linux"), false);
  });

  test("a config dir of '.' is the workspace itself", () => {
    assert.strictEqual(isUnderConfigDir("/ws/connections.toml", "/ws", ".", "linux"), true);
    assert.strictEqual(isUnderConfigDir("/ws/codesets/diets.csv", "/ws", ".", "linux"), true);
    assert.strictEqual(isUnderConfigDir("/elsewhere/connections.toml", "/ws", ".", "linux"), false);
  });

  test("dot segments inside the config dir or the file path are resolved", () => {
    assert.strictEqual(isUnderConfigDir("/ws/samples/config/connections.toml", "/ws", "samples/x/../config", "linux"), true);
    assert.strictEqual(isUnderConfigDir("/ws/samples/config/../other/connections.toml", "/ws", "samples/config", "linux"), false);
  });

  test("a root config dir contains every absolute path", () => {
    assert.strictEqual(isUnderConfigDir("/ws/connections.toml", "/ws", "/", "linux"), true);
    assert.strictEqual(isUnderConfigDir("C:\\ws\\connections.toml", "C:\\ws", "C:\\", "win32"), true);
    assert.strictEqual(isUnderConfigDir("D:\\ws\\connections.toml", "C:\\ws", "C:\\", "win32"), false);
  });

  test("a wrong-cased path is outside the config dir on a case-sensitive filesystem", () => {
    assert.strictEqual(isUnderConfigDir("/ws/Samples/Config/connections.toml", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(isUnderConfigDir("/ws/samples/config/connections.toml", "/ws", "samples/config", "linux"), true);
  });

  test("case is folded where the platform filesystem is case-insensitive by default", () => {
    assert.strictEqual(isUnderConfigDir("C:\\WS\\Samples\\Config\\connections.toml", "C:\\ws", "samples\\config", "win32"), true);
    assert.strictEqual(isUnderConfigDir("/srv/WS/Config/connections.toml", "/srv/ws", "config", "darwin"), true);
  });

  test("a sibling that shares a name prefix, or a dir named like '..x', is judged by segment", () => {
    assert.strictEqual(isUnderConfigDir("/ws/samples/config-backup/connections.toml", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(isUnderConfigDir("/ws/samples/config/..x/connections.toml", "/ws", "samples/config", "linux"), true);
  });

  test("a file on another Windows drive is outside the config dir", () => {
    assert.strictEqual(isUnderConfigDir("D:\\ws\\config\\connections.toml", "C:\\ws", "config", "win32"), false);
  });
});

// The custom editors read and write the exact file the CLI edits, so the guard in front of them asks
// for that file, not for any file under the config dir. With a config dir of "." every nested
// connections.toml in the workspace is under it, and each would otherwise be shown and saved as the
// workspace root's file.
suite("configEditorModel: the custom editors open only the file the CLI edits", () => {
  test("connections.toml: the config dir's own, not a nested or wrong-cased one", () => {
    assert.strictEqual(isConfigDirConnectionsFile("/ws/connections.toml", "/ws", ".", "linux"), true);
    assert.strictEqual(isConfigDirConnectionsFile("/ws/samples/config/connections.toml", "/ws", ".", "linux"), false);
    assert.strictEqual(isConfigDirConnectionsFile("/ws/samples/config/connections.toml", "/ws", "./samples/config", "linux"), true);
    assert.strictEqual(isConfigDirConnectionsFile("/ws/Connections.toml", "/ws", ".", "linux"), false);
    assert.strictEqual(isConfigDirConnectionsFile("C:\\ws\\Connections.TOML", "C:\\ws", ".", "win32"), true);
    assert.strictEqual(isConfigDirConnectionsFile("/ws/other/connections.toml", "/ws", "samples/config", "linux"), false);
  });

  test("a code set: <configDir>/codesets/<stem>.csv or .toml, not one nested deeper", () => {
    assert.strictEqual(isConfigDirCodeSetFile("/ws/samples/config/codesets/diets.csv", "/ws", "samples/config", "linux"), true);
    assert.strictEqual(isConfigDirCodeSetFile("/ws/samples/config/codesets/legacy.toml", "/ws", "samples/config", "linux"), true);
    assert.strictEqual(isConfigDirCodeSetFile("/ws/samples/config/old/codesets/diets.csv", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(isConfigDirCodeSetFile("/ws/samples/results_relay/codesets/t.csv", "/ws", ".", "linux"), false);
    assert.strictEqual(isConfigDirCodeSetFile("/ws/samples/config/CodeSets/diets.csv", "/ws", "samples/config", "linux"), false);
    assert.strictEqual(isConfigDirCodeSetFile("C:\\ws\\cfg\\CodeSets\\diets.csv", "C:\\ws", "cfg", "win32"), true);
  });
});
