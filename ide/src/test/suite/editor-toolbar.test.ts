import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { findElements, isConfigFile } from "../../editorToolbar";

// An absolute workspace root for the active platform, so isConfigFile's path.resolve is a no-op prefix
// (resolve would otherwise inject the cwd drive on win32 and skew path.relative).
const WS = process.platform === "win32" ? "C:\\work\\ws" : "/work/ws";
const CFG = "samples/config";

suite("isConfigFile", () => {
  test("a .py module under the config dir is a config file", () => {
    assert.strictEqual(isConfigFile(path.join(WS, "samples", "config", "IB_ACME_ADT.py"), WS, CFG), true);
  });
  test("a nested .py under the config dir counts", () => {
    assert.strictEqual(isConfigFile(path.join(WS, "samples", "config", "sub", "h.py"), WS, CFG), true);
  });
  test("a .py outside the config dir is not", () => {
    assert.strictEqual(isConfigFile(path.join(WS, "src", "thing.py"), WS, CFG), false);
  });
  test("a sibling dir sharing a name prefix does not match", () => {
    assert.strictEqual(isConfigFile(path.join(WS, "samples", "config-other", "x.py"), WS, CFG), false);
  });
  test("a non-.py file under the config dir is not", () => {
    assert.strictEqual(isConfigFile(path.join(WS, "samples", "config", "data.toml"), WS, CFG), false);
  });
  test("no workspace → false", () => {
    assert.strictEqual(isConfigFile(path.join(WS, "samples", "config", "x.py"), undefined, CFG), false);
  });
});

suite("findElements", () => {
  test("matches routers, handlers, and inbound/outbound connections — and only those", () => {
    const text = [
      "import messagefoundry", // 0
      "from x import inbound", // 1 — import, not matched
      "", // 2
      "IB_ACME_ADT = inbound(MLLP())", // 3 — inbound
      "OB_FOO = outbound(File())", // 4 — outbound
      "", // 5
      '@router("IB_ACME_ADT")', // 6 — router
      "def route(msg): ...", // 7
      '@handler("h")', // 8 — handler
      "def handle(msg): ...", // 9
      "result = process_inbound(msg)", // 10 — substring, not matched
      "@router_helper", // 11 — prefix, not matched
    ].join("\n");
    assert.deepStrictEqual(findElements(text), [
      { line: 3, kind: "inbound" },
      { line: 4, kind: "outbound" },
      { line: 6, kind: "router" },
      { line: 8, kind: "handler" },
    ]);
  });
});

interface Pkg {
  contributes: {
    submenus?: Array<{ id: string; label: string; icon?: unknown }>;
    menus: Record<string, Array<{ command?: string; submenu?: string; when?: string }>>;
  };
}

function pkg(): Pkg {
  const pkgPath = path.join(__dirname, "..", "..", "..", "package.json");
  return JSON.parse(fs.readFileSync(pkgPath, "utf8")) as Pkg;
}

suite("editor toolbar contributions", () => {
  test("editor/title hosts the MessageFoundry submenu, gated on isConfigFile", () => {
    const entry = (pkg().contributes.menus["editor/title"] ?? []).find(
      (e) => e.submenu === "messagefoundry.editorMenu",
    );
    assert.ok(entry, "editor/title must reference the messagefoundry.editorMenu submenu");
    assert.ok(
      entry?.when?.includes("messagefoundry.isConfigFile"),
      "the submenu button must be gated on messagefoundry.isConfigFile",
    );
  });

  test("the submenu is declared with a branded icon", () => {
    const sub = (pkg().contributes.submenus ?? []).find((s) => s.id === "messagefoundry.editorMenu");
    assert.ok(sub, "the messagefoundry.editorMenu submenu must be declared");
    assert.ok(sub?.icon, "the submenu needs an icon to render as a title-bar button");
  });

  test("the submenu lists the build actions", () => {
    const items = pkg().contributes.menus["messagefoundry.editorMenu"] ?? [];
    for (const cmd of [
      "messagefoundry.validate",
      "messagefoundry.openTestBench",
      "messagefoundry.promote",
    ]) {
      assert.ok(
        items.find((e) => e.command === cmd),
        `the submenu is missing ${cmd}`,
      );
    }
  });
});
