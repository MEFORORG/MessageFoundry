// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { findElements, hasHandler, hasRouter, hasStepsElement, isConfigFile } from "../../editorToolbar";

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

suite("hasHandler / hasRouter", () => {
  test("each answers only about its own decorator", () => {
    assert.strictEqual(hasHandler('@handler("h")\ndef handle(msg): ...'), true);
    assert.strictEqual(hasHandler('@router("IB")\ndef route(msg): ...'), false);
    assert.strictEqual(hasRouter('@router("IB")\ndef route(msg): ...'), true);
    assert.strictEqual(hasRouter('@handler("h")\ndef handle(msg): ...'), false);
    assert.strictEqual(hasHandler("OB = outbound(File())"), false);
    assert.strictEqual(hasHandler(""), false);
  });
});

suite("hasStepsElement", () => {
  // This assertion INVERTED with BACKLOG #232: a router-only file could not open as Steps before ADR 0076
  // Amendment D widened the grammar with the `route` row kind, and can now. The pre-#232 test asserted
  // `hasHandler(router) === false` AS the Steps gate; `hasHandler` still answers that narrower question
  // (above), but the gate itself is `hasStepsElement`.
  test("true for a file with a @handler, a @router, or both — the Steps affordance gate", () => {
    assert.strictEqual(hasStepsElement('@handler("h")\ndef handle(msg): ...'), true);
    assert.strictEqual(hasStepsElement('@router("IB")\ndef route(msg): ...'), true);
    assert.strictEqual(
      hasStepsElement('@router("IB")\ndef route(msg): ...\n@handler("h")\ndef handle(msg): ...'),
      true,
    );
  });

  test("false for a file with neither — a connection-only or empty module", () => {
    assert.strictEqual(hasStepsElement("OB = outbound(File())"), false);
    assert.strictEqual(hasStepsElement(""), false);
  });
});

interface Pkg {
  contributes: {
    commands?: Array<{ command: string; title?: string; icon?: unknown }>;
    submenus?: Array<{ id: string; label: string; icon?: unknown }>;
    menus: Record<string, Array<{ command?: string; submenu?: string; when?: string; group?: string }>>;
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

// The "View as Steps" affordance must appear only where a file/row can actually open as Steps —
// Handlers and, since ADR 0076 Amendment D (BACKLOG #232), Routers. In the editor it is gated on the
// activeFileHasSteps context key; in the tree it is an inline action on Handler rows
// (contextValue meforElementHandler).
suite("View as Steps gating", () => {
  test("openSteps is a distinct icon from Group Components (no shared glyph)", () => {
    const cmds = pkg().contributes.commands ?? [];
    const steps = cmds.find((c) => c.command === "messagefoundry.openSteps");
    const group = cmds.find((c) => c.command === "messagefoundry.groupConnections");
    assert.strictEqual(steps?.icon, "media/list-ordered-amber.svg");
    assert.strictEqual(group?.icon, "media/list-tree-amber.svg");
    assert.notStrictEqual(steps?.icon, group?.icon);
  });

  test("the editor-title button and submenu item are gated on activeFileHasSteps", () => {
    const menus = pkg().contributes.menus;
    const titleBtn = (menus["editor/title"] ?? []).find((e) => e.command === "messagefoundry.openSteps");
    assert.ok(
      titleBtn?.when?.includes("messagefoundry.activeFileHasSteps"),
      "the editor-title View as Steps button must be gated on activeFileHasSteps",
    );
    const menuItem = (menus["messagefoundry.editorMenu"] ?? []).find(
      (e) => e.command === "messagefoundry.openSteps",
    );
    assert.ok(
      menuItem?.when?.includes("messagefoundry.activeFileHasSteps"),
      "the submenu View as Steps item must be gated on activeFileHasSteps",
    );
  });

  test("the tree inline Steps action targets Handler rows only, with the list-ordered icon", () => {
    const cmds = pkg().contributes.commands ?? [];
    const cmd = cmds.find((c) => c.command === "messagefoundry.openStepsFromNode");
    assert.ok(cmd, "openStepsFromNode command must be declared");
    assert.strictEqual(cmd?.icon, "media/list-ordered-amber.svg");

    const inline = (pkg().contributes.menus["view/item/context"] ?? []).find(
      (e) => e.command === "messagefoundry.openStepsFromNode" && e.group?.startsWith("inline"),
    );
    assert.ok(inline, "openStepsFromNode must have an inline view/item/context rule");
    assert.ok(
      inline?.when?.includes("meforElementHandler"),
      "the inline Steps action must be gated on the Handler contextValue (meforElementHandler)",
    );
  });

  test("openStepsFromNode is hidden from the command palette", () => {
    const hidden = (pkg().contributes.menus["commandPalette"] ?? []).find(
      (e) => e.command === "messagefoundry.openStepsFromNode",
    );
    assert.strictEqual(hidden?.when, "false", "openStepsFromNode must be hidden from the palette");
  });
});
