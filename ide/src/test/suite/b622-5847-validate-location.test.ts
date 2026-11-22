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
  });

  test("no line in the message, or no file, stays on the first line", () => {
    assert.strictEqual(diagnosticLocation(diag("/ws/config/a.py"), "/ws", "config", false).line, 0);
    assert.strictEqual(diagnosticLocation(diag(null, "x at line 9"), "/ws", "config", false).line, 0);
  });
});
