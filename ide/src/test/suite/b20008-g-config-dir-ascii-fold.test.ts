// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5832, added item 1, for the three callers PR 3166 and PR 3170 left: the config-dir
// watcher (configRefresh), the editor toolbar's config-file test (editorToolbar) and the validate
// diagnostic's own-file test (validateDiagnostics). Each folded case with toLowerCase(), directly or
// through path.win32.relative, and toLowerCase() maps U+212A KELVIN SIGN onto ASCII "k". NTFS keeps
// the two apart, so on Windows a different directory or file read as the config dir's own.
//
// configRefresh and editorToolbar take the host's path rules, so their U+212A cases bite only on a
// Windows runner; on posix the two spellings differ under the exact compare, before and after. On
// Windows the fixed code asks the file system about a U+212A spelling, and ROOT names no folder, so
// the spelling-only cases below read as outside without one; the "on disk" suite pins the case where
// both folders exist. editorToolbar.ts imports vscode, so it is loaded against a stub here (as promote-target-gate does),
// which keeps this case in the node-side unit suite rather than the Extension Host's editor-toolbar.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { watchableConfigDir } from "../../configRefresh";
import { diagnosticLocation } from "../../validateDiagnostics";

const KELVIN = "\u212A";
const WIN = process.platform === "win32";
// A host-native absolute root, so each path below is absolute under the host's own path rules.
const ROOT = WIN ? "C:\\ws" : "/ws";

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

function insideExtensionHost(): boolean {
  try {
    const api = realLoad.call(loader, "vscode", module, false) as { version?: unknown; env?: { appName?: unknown } };
    return typeof api?.version === "string" && typeof api?.env?.appName === "string";
  } catch {
    return false;
  }
}

type Toolbar = typeof import("../../editorToolbar");
let toolbar: Toolbar | undefined;

if (!insideExtensionHost()) {
  // Every extension module is loaded fresh against the stub and the cache put back afterwards, so a
  // sibling suite's copies are unaffected. Loading only declares classes; nothing calls vscode.
  const outDir = path.resolve(__dirname, "..", "..");
  const testDir = path.join(outDir, "test") + path.sep;
  const isExtensionModule = (f: string): boolean => f.startsWith(outDir + path.sep) && !f.startsWith(testDir);
  const saved = new Map(
    Object.keys(require.cache)
      .filter(isExtensionModule)
      .map((f) => [f, require.cache[f]]),
  );
  for (const f of saved.keys()) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? {} : realLoad.call(this, request, parent, isMain);
  };
  try {
    toolbar = require("../../editorToolbar") as Toolbar;
  } finally {
    loader._load = realLoad;
    for (const f of Object.keys(require.cache).filter(isExtensionModule)) {
      delete require.cache[f];
    }
    for (const [f, entry] of saved) {
      require.cache[f] = entry;
    }
  }
}

const stubSuite = toolbar === undefined ? suite.skip : suite;

suite("configRefresh: the watched config dir folds ASCII case only (BACKLOG #5832)", () => {
  const ws = path.join(ROOT, "kits");

  test("a config dir spelled with U+212A is not the workspace spelled with k", () => {
    assert.strictEqual(watchableConfigDir(ws, path.join(ROOT, `${KELVIN}its`, "cfg")), undefined);
    // Relative, climbing out and back in under the U+212A spelling.
    assert.strictEqual(watchableConfigDir(ws, path.join("..", `${KELVIN}its`)), undefined);
  });

  test("control: an ASCII case difference still reads as inside on Windows, and as outside elsewhere", () => {
    const upper = path.join(ROOT, "KITS", "cfg");
    assert.strictEqual(watchableConfigDir(ws, upper), WIN ? upper : undefined);
    assert.strictEqual(watchableConfigDir(ws, "cfg"), path.join(ws, "cfg"));
    assert.strictEqual(watchableConfigDir(ws, "."), ws);
    assert.strictEqual(watchableConfigDir(ws, path.join(ROOT, "kits-other")), undefined);
  });
});

stubSuite("editorToolbar.isConfigFile folds ASCII case only (BACKLOG #5832)", () => {
  test("a module under a directory spelled with U+212A is not under the config dir spelled with k", () => {
    const t = toolbar as Toolbar;
    assert.strictEqual(t.isConfigFile(path.join(ROOT, `${KELVIN}its`, "a.py"), ROOT, "kits"), false);
    assert.strictEqual(t.isConfigFile(path.join(ROOT, "kits", "a.py"), ROOT, `${KELVIN}its`), false);
  });

  test("control: the config dir's own module is a config file; an ASCII case difference only on Windows", () => {
    const t = toolbar as Toolbar;
    assert.strictEqual(t.isConfigFile(path.join(ROOT, "kits", "sub", "a.py"), ROOT, "kits"), true);
    assert.strictEqual(t.isConfigFile(path.join(ROOT, "KITS", "a.py"), ROOT, "kits"), WIN);
    assert.strictEqual(t.isConfigFile(path.join(ROOT, "kits"), ROOT, "kits"), false); // the dir itself
    assert.strictEqual(t.isConfigFile(path.join(ROOT, "kits-other", "a.py"), ROOT, "kits"), false);
  });
});

// On disk, on Windows only: a case difference outside A-Z is settled by the file system, so the fix
// does not lose a folder NTFS folds (e-acute against E-acute), while a U+212A spelling, which NTFS
// keeps apart from "k", stays outside even where both folders exist.
const diskSuite = WIN && toolbar !== undefined ? suite : suite.skip;

diskSuite("on disk: a non-ASCII case NTFS folds is inside, U+212A is not (BACKLOG #5832)", () => {
  const LOWER = "caf\u00E9";
  const UPPER = "CAF\u00C9";
  let root: string;
  // What this volume does, so a temp directory that folds otherwise skips rather than goes red.
  let foldsAcute = false;
  let keepsKelvinApart = false;
  setup(() => {
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008g-")));
    fs.mkdirSync(path.join(root, LOWER, "cfg"), { recursive: true });
    foldsAcute = fs.existsSync(path.join(root, UPPER));
    fs.mkdirSync(path.join(root, "kits"));
    try {
      fs.mkdirSync(path.join(root, `${KELVIN}its`));
      keepsKelvinApart = true;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") {
        throw e;
      }
      keepsKelvinApart = false; // this volume folds U+212A onto k, so the two are one folder here
    }
  });
  teardown(() => fs.rmSync(root, { recursive: true, force: true }));

  test("E-acute spelling of the config dir is the same folder; the toolbar and the watcher keep it", function () {
    if (!foldsAcute) {
      this.skip(); // a case-sensitive or non-folding temp volume: no folded spelling to read
    }
    const t = toolbar as Toolbar;
    const dir = path.join(root, LOWER);
    assert.strictEqual(t.isConfigFile(path.join(root, UPPER, "a.py"), dir, "."), true);
    const upper = path.join(root, UPPER, "cfg");
    assert.strictEqual(watchableConfigDir(dir, upper), upper);
    assert.strictEqual(watchableConfigDir(dir, path.join(root, UPPER)), dir);
    // A case variant of a config dir that does not exist cannot be read, so it reads as outside.
    const missing = path.join(root, "na\u00EFve");
    assert.strictEqual(t.isConfigFile(path.join(root, "NA\u00CFVE", "a.py"), missing, "."), false);
    assert.strictEqual(watchableConfigDir(missing, path.join(root, "NA\u00CFVE", "cfg")), undefined);
  });

  test("where the native real path fails with EISDIR, the JS one and the file id still settle it", function () {
    if (!foldsAcute) {
      this.skip();
    }
    const t = toolbar as Toolbar;
    const native = fs.realpathSync.native;
    fs.realpathSync.native = ((): never => {
      throw Object.assign(new Error("EISDIR: illegal operation on a directory"), { code: "EISDIR" });
    }) as unknown as typeof native;
    try {
      assert.strictEqual(t.isConfigFile(path.join(root, UPPER, "a.py"), path.join(root, LOWER), "."), true);
    } finally {
      fs.realpathSync.native = native;
    }
  });

  test("a U+212A folder beside the k one is another folder, by the file system too", function () {
    if (!keepsKelvinApart) {
      this.skip();
    }
    const t = toolbar as Toolbar;
    assert.strictEqual(t.isConfigFile(path.join(root, `${KELVIN}its`, "a.py"), path.join(root, "kits"), "."), false);
    assert.strictEqual(watchableConfigDir(path.join(root, "kits"), path.join(root, `${KELVIN}its`)), undefined);
  });

  test("a volume that reports file id 0 for both folders does not make them one", function () {
    if (!keepsKelvinApart) {
      this.skip();
    }
    const t = toolbar as Toolbar;
    // The module object itself: the `import * as fs` binding is read-only, and pathFold reads through it.
    const nodeFs = require("node:fs") as { statSync: unknown };
    const stat = nodeFs.statSync;
    nodeFs.statSync = (): { dev: bigint; ino: bigint } => ({ dev: 0n, ino: 0n });
    try {
      assert.strictEqual(t.isConfigFile(path.join(root, `${KELVIN}its`, "a.py"), path.join(root, "kits"), "."), false);
    } finally {
      nodeFs.statSync = stat;
    }
  });
});

suite("validateDiagnostics: the own-file name test folds ASCII case only (BACKLOG #5832)", () => {
  const diag = (file: string, message: string) => ({ message, file, severity: "error" });

  test("on Windows, a module named with U+212A is not this file named with k", () => {
    const m = `error loading config module ${KELVIN}its.py: SyntaxError at line 7 (withheld)`;
    assert.strictEqual(diagnosticLocation(diag("C:\\ws\\config\\kits.py", m), "C:\\ws", "config", true).line, 0);
  });

  test("control: an ASCII case difference still places the line on Windows, not on posix", () => {
    const m = "error loading config module KITS.py: SyntaxError at line 7 (withheld)";
    assert.strictEqual(diagnosticLocation(diag("C:\\ws\\config\\kits.py", m), "C:\\ws", "config", true).line, 6);
    assert.strictEqual(diagnosticLocation(diag("/ws/config/kits.py", m), "/ws", "config", false).line, 0);
  });
});
