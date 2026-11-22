// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 622 (BACKLOG #5847): createValidator passed a diagnostic's `file` straight to Uri.file, so a
// relative one would anchor at the filesystem root; it joined an absolute configDir onto the workspace
// for the no-file fallback; and it put every diagnostic on line 0. `diagnosticLocation` fixes all three.
import * as assert from "assert";

import { diagnosticLocation } from "../../validateDiagnostics";

const diag = (file: string | null, message = "boom") => ({ message, file, severity: "error" });

suite("b622 #5847 validate diagnostic location", () => {
  test("an absolute configDir is the fallback as it stands", () => {
    assert.strictEqual(diagnosticLocation(diag(null), "D:\\ws", "D:\\cfg", true).file, "D:\\cfg");
    assert.strictEqual(diagnosticLocation(diag(null), "/ws", "/etc/cfg", false).file, "/etc/cfg");
  });

  test("a relative configDir and a relative file resolve against the workspace", () => {
    assert.strictEqual(diagnosticLocation(diag(null), "/ws", "config", false).file, "/ws/config");
    assert.strictEqual(diagnosticLocation(diag("config/a.py"), "/ws", "config", false).file, "/ws/config/a.py");
    assert.strictEqual(
      diagnosticLocation(diag("config\\a.py"), "D:\\ws", "config", true).file,
      "D:\\ws\\config\\a.py",
    );
  });

  test("an absolute file is kept", () => {
    assert.strictEqual(diagnosticLocation(diag("/ws/config/a.py"), "/other", "config", false).file, "/ws/config/a.py");
  });

  test("the engine's own 'at line N' places the diagnostic on that line, 0-based", () => {
    const m = "error loading config module syn.py: SyntaxError at line 7 (its message is withheld)";
    assert.strictEqual(diagnosticLocation(diag("/ws/config/syn.py", m), "/ws", "config", false).line, 6);
  });

  test("a line in a helper the file imported is not this file's line", () => {
    const m = "error loading config module a.py: NameError in _helpers.py at line 4";
    assert.strictEqual(diagnosticLocation(diag("/ws/config/a.py", m), "/ws", "config", false).line, 0);
    const upper = "error loading config module a.py: NameError in _Helper.PY at line 4 (withheld)";
    assert.strictEqual(diagnosticLocation(diag("D:\\ws\\config\\a.py", upper), "D:\\ws", "config", true).line, 0);
  });

  test("a helper-preload refusal quoting the helper's own line is not this file's line", () => {
    const m =
      "error loading config module a.py: config helper _helpers.py failed to load " +
      "(SyntaxError at line 4; its message is withheld), and a.py imports it outside an ImportError guard";
    assert.strictEqual(diagnosticLocation(diag("/ws/config/a.py", m), "/ws", "config", false).line, 0);
  });

  test("a message naming another module is not this file's line; on Windows the name ignores case", () => {
    const other = "error loading config module b.py: SyntaxError at line 3 (withheld)";
    assert.strictEqual(diagnosticLocation(diag("/ws/config/a.py", other), "/ws", "config", false).line, 0);
    const upper = "error loading config module A.PY: SyntaxError at line 3 (withheld)";
    assert.strictEqual(diagnosticLocation(diag("d:\\ws\\config\\a.py", upper), "d:\\ws", "config", true).line, 2);
  });

  test("a non-ASCII exception type name still places the line", () => {
    const m = "error loading config module a.py: ÉchecConfig at line 12 (withheld)";
    assert.strictEqual(diagnosticLocation(diag("/ws/config/a.py", m), "/ws", "config", false).line, 11);
  });

  test("an empty file falls back to the config directory, like a missing one", () => {
    assert.strictEqual(diagnosticLocation(diag(""), "/ws", "config", false).file, "/ws/config");
  });

  test("no line in the message, or no file, stays on the first line", () => {
    assert.strictEqual(diagnosticLocation(diag("/ws/config/a.py"), "/ws", "config", false).line, 0);
    assert.strictEqual(diagnosticLocation(diag(null, "x at line 9"), "/ws", "config", false).line, 0);
  });
});
