// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 622 (BACKLOG #5835): live debug matched a trace's `file` to the editor's `fsPath` with a plain
// `path.resolve` equality. On Windows `Uri.fsPath` lower-cases the drive letter while Python keeps the
// case it was given, and a relative trace path is relative to the workspace the CLI ran in, not to the
// extension host's cwd, so every inline and Steps live value would drop. `invocationsForFile` now
// matches on `fileKey`; `live-debug.test.js` is outside test:unit, so the helper is pinned here.
import * as assert from "assert";

import { fileKey, resolveAgainst } from "../../pathIdentity";

/** Whether `a` and `b` name the same file, as invocationsForFile decides it. */
function sameFilePath(a: string, b: string, base: string, win32: boolean): boolean {
  return fileKey(base, a, win32) === fileKey(base, b, win32);
}

suite("b622 #5835 trace path identity", () => {
  test("Windows: a drive-letter or segment case difference still names the same file", () => {
    assert.ok(sameFilePath("D:\\ws\\config\\A.py", "d:\\ws\\config\\A.py", "d:\\ws", true));
    assert.ok(sameFilePath("D:\\WS\\Config\\a.py", "d:\\ws\\config\\A.py", "d:\\ws", true));
    assert.ok(sameFilePath("D:/ws/config/A.py", "d:\\ws\\config\\A.py", "d:\\ws", true));
  });

  test("Windows: a relative trace path resolves against the workspace, not the process cwd", () => {
    assert.ok(sameFilePath("config\\A.py", "d:\\ws\\config\\A.py", "D:\\ws", true));
    assert.ok(!sameFilePath("config\\A.py", "d:\\other\\config\\A.py", "D:\\ws", true));
  });

  test("Windows: a different file is still different", () => {
    assert.ok(!sameFilePath("D:\\ws\\config\\A.py", "d:\\ws\\config\\B.py", "d:\\ws", true));
  });

  test("POSIX: case is significant, and a relative path resolves against the base", () => {
    assert.ok(!sameFilePath("/ws/config/A.py", "/ws/config/a.py", "/ws", false));
    assert.ok(sameFilePath("config/A.py", "/ws/config/A.py", "/ws", false));
    assert.ok(sameFilePath("./config/../config/A.py", "/ws/config/A.py", "/ws", false));
  });

  test("resolveAgainst keeps an absolute path and anchors a relative one at the base", () => {
    assert.strictEqual(resolveAgainst("/ws", "/abs/x.py", false), "/abs/x.py");
    assert.strictEqual(resolveAgainst("/ws", "cfg/x.py", false), "/ws/cfg/x.py");
    assert.strictEqual(resolveAgainst("D:\\ws", "cfg\\x.py", true), "D:\\ws\\cfg\\x.py");
  });
});
