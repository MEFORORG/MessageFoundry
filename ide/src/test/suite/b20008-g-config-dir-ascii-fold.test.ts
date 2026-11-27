// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5832, added item 1, for the three callers PR 3166 and PR 3170 left: the config-dir
// watcher (configRefresh), the editor toolbar's config-file test (editorToolbar) and the validate
// diagnostic's own-file test (validateDiagnostics). Each folded case with toLowerCase(), directly or
// through path.win32.relative, and toLowerCase() maps U+212A KELVIN SIGN onto ASCII "k". NTFS keeps
// the two apart, so on Windows a different directory or file read as the config dir's own.
//
// configRefresh and editorToolbar take the host's path rules, so their U+212A cases bite only on a
// Windows runner; on posix the two spellings differ under the exact compare, before and after.
// editorToolbar.ts imports vscode, so it is loaded against a stub here (as promote-target-gate does),
// which keeps this case in the node-side unit suite rather than the Extension Host's editor-toolbar.
import * as assert from "assert";
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
