// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Workspace containment and path identity fold ASCII case only on Windows (BACKLOG #5404, #5832).
//
// path.win32.relative and toLowerCase() fold U+212A KELVIN SIGN onto "k", a name NTFS keeps apart
// from "k", so a sibling directory spelled with it read as inside the workspace. Every refusal here is
// paired with an ASCII-case control that must still read as within, so the fix only tightens.
import * as assert from "assert";
import * as path from "node:path";
import { foldAsciiCase, isPathWithin } from "../../pathFold";
import { trustPinsFor } from "../../engineTrustModel";
import { committedRelativePath, containedPathSetting, resolveInsideWorkspace } from "../../workspaceContainment";

const KELVIN = "\u212A";

suite("isPathWithin folds ASCII case only on win32 (BACKLOG #5832)", () => {
  test("a directory named with KELVIN SIGN for k is not the workspace", () => {
    assert.strictEqual(isPathWithin("C:\\ws\\kit", `C:\\ws\\${KELVIN}it\\x.py`, true), false);
    assert.strictEqual(isPathWithin("C:\\ws\\kit", `C:\\ws\\${KELVIN}it`, true), false);
  });

  test("ASCII case control: a wrong-cased path inside the workspace is still within", () => {
    assert.strictEqual(isPathWithin("C:\\WS\\Kit", "c:\\ws\\KIT\\sub\\x.py", true), true);
    assert.strictEqual(isPathWithin("C:\\ws\\kit", "C:/ws/kit", true), true);
    assert.strictEqual(isPathWithin("C:\\", "C:\\anything", true), true);
  });

  test("UNC: the share is compared ASCII-folded, and KELVIN SIGN in it is another share", () => {
    assert.strictEqual(isPathWithin("\\\\Server\\Kits\\ws", "\\\\server\\KITS\\ws\\a", true), true);
    assert.strictEqual(isPathWithin("\\\\server\\kits\\ws", `\\\\server\\${KELVIN}its\\ws\\a`, true), false);
    assert.strictEqual(isPathWithin("\\\\server\\kits\\ws", "\\\\other\\kits\\ws\\a", true), false);
    assert.strictEqual(isPathWithin("C:\\ws", "\\\\server\\share\\ws", true), false);
  });

  test("climbs, siblings and another drive stay outside", () => {
    assert.strictEqual(isPathWithin("C:\\ws", "C:\\ws\\..\\other", true), false);
    assert.strictEqual(isPathWithin("C:\\ws", "C:\\wsx", true), false);
    assert.strictEqual(isPathWithin("C:\\ws", "D:\\ws", true), false);
    assert.strictEqual(isPathWithin("C:\\ws", "C:\\ws\\..foo", true), true);
  });

  test("POSIX compares exactly", () => {
    assert.strictEqual(isPathWithin("/ws", "/ws/a", false), true);
    assert.strictEqual(isPathWithin("/ws", "/WS/a", false), false);
    assert.strictEqual(isPathWithin("/ws", "/ws/../x", false), false);
  });

  test("foldAsciiCase leaves non-ASCII letters alone", () => {
    assert.strictEqual(foldAsciiCase(`AbC${KELVIN}\u00C9`), `abc${KELVIN}\u00C9`);
  });
});

suite("the sibling sites use the ASCII-only fold (BACKLOG #5832)", () => {
  test("a second caFile differing only by KELVIN SIGN is refused, an ASCII case twin is not", () => {
    const url = "https://prod:8765";
    const kelvin = trustPinsFor(
      [
        { url, caFile: "C:\\pki\\kit.pem" },
        { url, caFile: `C:\\pki\\${KELVIN}it.pem` },
      ],
      path.win32,
    );
    assert.strictEqual(kelvin.filter((p) => p.kind === "refused").length, 1);
    const ascii = trustPinsFor(
      [
        { url, caFile: "C:\\PKI\\Kit.pem" },
        { url, caFile: "c:\\pki\\kit.pem" },
      ],
      path.win32,
    );
    assert.strictEqual(ascii.filter((p) => p.kind === "refused").length, 0);
  });
});

// The public containment API reads the host's own path module, so its Windows reading is pinned
// only on a Windows runner; the helper suite above pins the rule on every runner.
(process.platform === "win32" ? suite : suite.skip)(
  "containment on a Windows host refuses a KELVIN SIGN sibling (BACKLOG #5404)",
  () => {
    test("a workspace value naming the KELVIN SIGN sibling is dropped; an ASCII case twin is kept", () => {
      const ws = "C:\\ws\\kit";
      const escape = containedPathSetting(
        { globalValue: undefined, workspaceValue: `C:\\ws\\${KELVIN}it\\config` },
        ws,
        "samples/config",
      );
      assert.strictEqual(escape.source === "workspace", false, `contained: ${JSON.stringify(escape)}`);
      assert.strictEqual(escape.dropped, "workspace");
      const control = containedPathSetting({ workspaceValue: "C:\\WS\\KIT\\config" }, ws, "samples/config");
      assert.strictEqual(control.source, "workspace");
      assert.strictEqual(control.dropped, false);
    });

    test("committedRelativePath refuses the KELVIN SIGN sibling; an ASCII case twin is relative", () => {
      assert.strictEqual(committedRelativePath("C:\\ws\\kit", `C:\\ws\\${KELVIN}it\\hook.py`), undefined);
      assert.strictEqual(committedRelativePath("C:\\ws\\kit", "C:\\WS\\KIT\\scripts\\hook.py"), "scripts/hook.py");
    });

    test("resolveInsideWorkspace refuses the KELVIN SIGN sibling by spelling", () => {
      assert.strictEqual(resolveInsideWorkspace("C:\\ws\\kit", `C:\\ws\\${KELVIN}it\\config`), undefined);
    });
  },
);
