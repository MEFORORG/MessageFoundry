// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Workspace containment, the hooks-folder match, the caFile pin match and the Security Settings
// editor's target fold ASCII case only on Windows (BACKLOG #5404, #5832). pathIdentity.fileKey keeps
// VS Code's toLowerCase() fold.
//
// path.win32.relative and toLowerCase() fold U+212A KELVIN SIGN onto "k", a name NTFS keeps apart
// from "k", so a sibling directory spelled with it read as inside the workspace. Most refusals here
// are paired with an ASCII-case control that must still read as within. The ASCII fold is not a pure
// tightening: a path that differs from the workspace only by a non-ASCII case NTFS folds (e-acute
// against E-acute) also reads as spelled outside, so a check skipped for an outside value would be
// skipped there. The link-check suites below pin that it still runs. An earlier header said every
// refusal was paired with a control and the fix only tightened; neither held.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { foldAsciiCase, isPathWithin, nonAsciiCaseVariant } from "../../pathFold";
import { trustPinsFor } from "../../engineTrustModel";
import { securityConfigTarget, type LinkFs } from "../../securityEditorModel";
import {
  committedRelativePath,
  containedPathSetting,
  escapesByLink,
  resolveInsideWorkspace,
} from "../../workspaceContainment";

const KELVIN = "\u212A";
const E_ACUTE = "\u00E9";
const E_ACUTE_UPPER = "\u00C9";

/** `s` with ASCII a-z upper-cased, every other character unchanged. */
function upperAscii(s: string): string {
  return s.replace(/[a-z]+/g, (m) => m.toUpperCase());
}

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

suite("nonAsciiCaseVariant names the folder a file system must be asked about (BACKLOG #5832)", () => {
  test("a non-ASCII case difference in the workspace's spelling gives the head at its depth", () => {
    assert.deepStrictEqual(nonAsciiCaseVariant(`C:\\ws\\${E_ACUTE}`, `C:\\WS\\${E_ACUTE_UPPER}\\cfg\\x`, true), {
      head: `C:\\WS\\${E_ACUTE_UPPER}`,
      rest: ["cfg", "x"],
    });
    assert.deepStrictEqual(nonAsciiCaseVariant("C:\\ws\\kit", `C:\\ws\\${KELVIN}it`, true), {
      head: `C:\\ws\\${KELVIN}it`,
      rest: [],
    });
  });

  test("none for a path within by the ASCII fold, one outside under every fold, or on POSIX", () => {
    assert.strictEqual(nonAsciiCaseVariant("C:\\ws\\kit", "C:\\WS\\KIT\\cfg", true), undefined);
    assert.strictEqual(nonAsciiCaseVariant("C:\\ws\\kit", "C:\\ws\\other\\cfg", true), undefined);
    assert.strictEqual(nonAsciiCaseVariant("C:\\ws\\kit", `D:\\ws\\${KELVIN}it`, true), undefined);
    assert.strictEqual(nonAsciiCaseVariant(`/ws/${E_ACUTE}`, `/ws/${E_ACUTE_UPPER}/cfg`, false), undefined);
  });
});

suite("the caFile pin match uses the ASCII-only fold (BACKLOG #5832)", () => {
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

// The public containment API and the Security Settings editor read the host's own path module, so
// their Windows reading is pinned only on a Windows runner: none takes a path flavour, and adding
// one would widen their surface. The helper suites above pin the rule on every runner.
const windowsSuite = process.platform === "win32" ? suite : suite.skip;

windowsSuite("containment on a Windows host refuses a KELVIN SIGN sibling (BACKLOG #5404)", () => {
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

  test("resolveInsideWorkspace refuses the KELVIN SIGN sibling by spelling; an ASCII case twin resolves", () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "mf-b622-resolve-"));
    try {
      const ws = path.join(base, "kit");
      fs.mkdirSync(ws);
      assert.strictEqual(resolveInsideWorkspace(ws, path.join(base, `${KELVIN}it`, "config")), undefined);
      const twin = path.join(upperAscii(ws), "config");
      assert.strictEqual(resolveInsideWorkspace(ws, twin), twin);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
});

windowsSuite("escapesByLink still checks a value that names the workspace by a non-ASCII case (BACKLOG #5832)", () => {
  let base: string;
  let outside: string;

  setup(function () {
    base = fs.mkdtempSync(path.join(os.tmpdir(), "mf-b622-variant-"));
    outside = path.join(base, "outside");
    fs.mkdirSync(outside);
  });

  teardown(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  test("a junction under an E-acute spelling of the workspace is refused, as under its own", function () {
    const ws = path.join(base, `ws-${E_ACUTE}`);
    fs.mkdirSync(ws);
    if (!fs.existsSync(path.join(base, `ws-${E_ACUTE_UPPER}`))) {
      this.skip(); // this folder keeps E-acute and e-acute apart, so there is no variant to test
    }
    fs.symlinkSync(outside, path.join(ws, "cfg"), "junction");
    fs.mkdirSync(path.join(ws, "plain"));
    const variant = path.join(base, `ws-${E_ACUTE_UPPER}`);
    assert.strictEqual(escapesByLink(ws, path.join(variant, "cfg")), true);
    assert.strictEqual(escapesByLink(ws, path.join(variant, "cfg", "new.toml")), true);
    // Controls: the workspace's own spelling, and its ASCII case twin, refuse the same junction;
    // a plain folder under the variant spelling is not refused.
    assert.strictEqual(escapesByLink(ws, path.join(ws, "cfg")), true);
    assert.strictEqual(escapesByLink(ws, path.join(upperAscii(ws), "cfg")), true);
    assert.strictEqual(escapesByLink(ws, path.join(variant, "plain")), false);
    assert.strictEqual(escapesByLink(ws, path.join(variant, "plain", "new.toml")), false);
  });

  test("where the native realpath fails with EISDIR, the variant is still placed, by file id", function () {
    const ws = path.join(base, `ws-${E_ACUTE}`);
    fs.mkdirSync(ws);
    if (!fs.existsSync(path.join(base, `ws-${E_ACUTE_UPPER}`))) {
      this.skip();
    }
    fs.symlinkSync(outside, path.join(ws, "cfg"), "junction");
    // The JS fallback realpath() takes keeps the spelling's case, so the real paths differ.
    const native = fs.realpathSync.native;
    fs.realpathSync.native = ((): never => {
      throw Object.assign(new Error("EISDIR"), { code: "EISDIR" });
    }) as unknown as typeof fs.realpathSync.native;
    fs.mkdirSync(path.join(ws, "plain"));
    try {
      assert.strictEqual(escapesByLink(ws, path.join(base, `ws-${E_ACUTE_UPPER}`, "cfg")), true);
      // Control: under the same mock a plain folder is placed and passes, so the refusal above is
      // the junction's, not an unreadable path's.
      assert.strictEqual(escapesByLink(ws, path.join(base, `ws-${E_ACUTE_UPPER}`, "plain")), false);
    } finally {
      fs.realpathSync.native = native;
    }
  });

  test("a KELVIN SIGN sibling is another folder, the operator's own, and is not checked", function () {
    const ws = path.join(base, "kit");
    const sibling = path.join(base, `${KELVIN}it`);
    fs.mkdirSync(ws);
    if (fs.existsSync(sibling)) {
      this.skip(); // this file system folds KELVIN SIGN onto k
    }
    fs.mkdirSync(sibling);
    fs.symlinkSync(outside, path.join(sibling, "cfg"), "junction");
    assert.strictEqual(escapesByLink(ws, path.join(sibling, "cfg")), false);
    // A `..` in the operator's own path to another folder is not refused either.
    assert.strictEqual(escapesByLink(ws, `${sibling}\\a\\..\\cfg`), false);
    // Control: the same junction inside the workspace is refused.
    fs.symlinkSync(outside, path.join(ws, "cfg"), "junction");
    assert.strictEqual(escapesByLink(ws, path.join(ws, "cfg")), true);
  });
});

windowsSuite("the Security Settings target folds ASCII case only (BACKLOG #5404, #5832)", () => {
  const trusted = { trusted: true };

  /** A LinkFs over spelled paths: `links` lstat as links, `realpaths` maps a path's real path, and
   *  every other path is a plain entry whose real path is itself. */
  function fakeFs(links: readonly string[], realpaths: Readonly<Record<string, string>> = {}): LinkFs {
    return {
      lstat: (p: string) => ({ isSymbolicLink: () => links.includes(p) }),
      realpath: (p: string): string => realpaths[p] ?? p,
      fileId: (p: string): string => foldAsciiCase(realpaths[p] ?? p),
    };
  }

  test("a workspace value naming the KELVIN SIGN sibling is refused; an ASCII case twin is accepted", () => {
    const ws = "C:\\ws\\kit";
    const kelvin = securityConfigTarget(ws, `C:\\ws\\${KELVIN}it\\messagefoundry.toml`, { ...trusted, fromWorkspace: true }, fakeFs([]));
    assert.strictEqual(kelvin.ok, false, JSON.stringify(kelvin));
    assert.ok(!kelvin.ok && kelvin.problem.includes("letter case must match"), JSON.stringify(kelvin));
    const twin = securityConfigTarget(ws, "C:\\WS\\KIT\\messagefoundry.toml", { ...trusted, fromWorkspace: true }, fakeFs([]));
    assert.deepStrictEqual(twin, { ok: true, path: "C:\\ws\\kit\\messagefoundry.toml" });
  });

  test("a user value naming the KELVIN SIGN sibling is accepted as written, being another folder", () => {
    const value = `C:\\ws\\${KELVIN}it\\messagefoundry.toml`;
    const got = securityConfigTarget("C:\\ws\\kit", value, { ...trusted, fromWorkspace: false }, fakeFs([]));
    assert.deepStrictEqual(got, { ok: true, path: value });
  });

  test("a user value whose real path keeps its case is refused without a file id, placed with one", () => {
    const ws = `C:\\ws\\${E_ACUTE}`;
    const value = `C:\\ws\\${E_ACUTE_UPPER}\\cfg\\messagefoundry.toml`;
    const keeps: LinkFs = { lstat: () => ({ isSymbolicLink: () => false }), realpath: (p: string) => p };
    const blind = securityConfigTarget(ws, value, { ...trusted, fromWorkspace: false }, keeps);
    assert.strictEqual(blind.ok, false, JSON.stringify(blind));
    const linked: LinkFs = {
      lstat: (p: string) => ({ isSymbolicLink: () => p === `${ws}\\cfg` }),
      realpath: (p: string) => p,
      fileId: (p: string) => p.toLowerCase(),
    };
    const placed = securityConfigTarget(ws, value, { ...trusted, fromWorkspace: false }, linked);
    assert.ok(!placed.ok && placed.problem.includes("passes through a link"), JSON.stringify(placed));
  });

  test("a user value naming the workspace by an E-acute case still gets the link check", () => {
    const ws = `C:\\ws\\${E_ACUTE}`;
    const head = `C:\\ws\\${E_ACUTE_UPPER}`;
    const value = `${head}\\cfg\\messagefoundry.toml`;
    const fsx = (links: string[]): LinkFs => fakeFs(links, { [head]: ws });
    const linked = securityConfigTarget(ws, value, { ...trusted, fromWorkspace: false }, fsx([`${ws}\\cfg`]));
    assert.strictEqual(linked.ok, false, JSON.stringify(linked));
    assert.ok(!linked.ok && linked.problem.includes("passes through a link"), JSON.stringify(linked));
    // Control: with no link the same value is accepted, spelled from the workspace folder.
    const plain = securityConfigTarget(ws, value, { ...trusted, fromWorkspace: false }, fsx([]));
    assert.deepStrictEqual(plain, { ok: true, path: `${ws}\\cfg\\messagefoundry.toml` });
  });

  test("the real-path compare folds the workspace folder's own segments ASCII case only", () => {
    // A junction lstat does not report as a link, whose real path names the KELVIN SIGN sibling.
    const ws = "C:\\ws\\kit";
    const fsx = fakeFs([], { "C:\\ws\\kit\\cfg": `C:\\ws\\${KELVIN}it\\cfg` });
    const got = securityConfigTarget(ws, "cfg", { ...trusted, fromWorkspace: true }, fsx);
    assert.strictEqual(got.ok, false, JSON.stringify(got));
    const control = securityConfigTarget(ws, "cfg", { ...trusted, fromWorkspace: true }, fakeFs([], { "C:\\ws\\kit\\cfg": "C:\\WS\\KIT\\CFG" }));
    assert.deepStrictEqual(control, { ok: true, path: "C:\\ws\\kit\\cfg" });
  });

  test("a folder below the workspace spelled with another non-ASCII case than on disk is accepted", () => {
    // NTFS opens it as the folder on disk, which is inside the workspace; it is not a link.
    const ws = "C:\\ws\\kit";
    const fsx = fakeFs([], { [`${ws}\\${E_ACUTE}val`]: `${ws}\\${E_ACUTE_UPPER}val` });
    const got = securityConfigTarget(ws, `${E_ACUTE}val`, { ...trusted, fromWorkspace: true }, fsx);
    assert.deepStrictEqual(got, { ok: true, path: `${ws}\\${E_ACUTE}val` });
  });

  test("a user value whose case-variant head is a dangling link is refused, as escapesByLink refuses it", () => {
    const ws = `C:\\ws\\${E_ACUTE}`;
    const head = `C:\\ws\\${E_ACUTE_UPPER}`;
    const fsx: LinkFs = {
      lstat: (p: string) => {
        if (p === head) {
          return { isSymbolicLink: () => true };
        }
        throw Object.assign(new Error("absent"), { code: "ENOENT" });
      },
      realpath: (p: string): string => {
        if (p === head) {
          throw Object.assign(new Error("dangling"), { code: "ENOENT" });
        }
        return p;
      },
    };
    const got = securityConfigTarget(ws, `${head}\\cfg.toml`, { ...trusted, fromWorkspace: false }, fsx);
    assert.strictEqual(got.ok, false, JSON.stringify(got));
  });
});
