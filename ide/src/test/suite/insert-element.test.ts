import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

import { buildPicks, detectContext, filterSnippetsForContext } from "../../insertElement";

suite("buildPicks", () => {
  test("groups by the 'Category · text' description, with separators, and attaches the body", () => {
    const picks = buildPicks({
      A: { prefix: "mefa", body: ["x = 1"], description: "Field · Do A" },
      B: { prefix: "mefb", body: 'return Send("o", msg)', description: "Send · Do B" },
      S: { prefix: "mefs", body: ["inbound(...)"], description: "Scaffold thing" }, // no " · "
    });

    const separators = picks
      .filter((p) => p.kind === vscode.QuickPickItemKind.Separator)
      .map((p) => p.label);
    assert.deepStrictEqual(separators, ["Field", "Send", "Scaffold"]);

    const a = picks.find((p) => p.label === "Do A");
    assert.ok(a, "Field item present");
    assert.strictEqual(a?.body, "x = 1");
    assert.strictEqual(a?.detail, "prefix: mefa");

    const b = picks.find((p) => p.label === "Do B");
    assert.strictEqual(b?.body, 'return Send("o", msg)');

    // a description without the delimiter falls under Scaffold with the whole text as the label
    const s = picks.find((p) => p.label === "Scaffold thing");
    assert.ok(s && s.body === "inbound(...)");
  });
});

interface Pkg {
  contributes: {
    commands: Array<{ command: string }>;
    keybindings?: Array<{ command: string; key: string }>;
    menus: Record<string, Array<{ command?: string }>>;
  };
}
interface SnippetDef {
  prefix?: string;
  body: string | string[];
  description?: string;
}

function pkg(): Pkg {
  const p = path.join(__dirname, "..", "..", "..", "package.json");
  return JSON.parse(fs.readFileSync(p, "utf8")) as Pkg;
}
function snippets(): Record<string, SnippetDef> {
  const p = path.join(__dirname, "..", "..", "..", "snippets", "messagefoundry.code-snippets");
  return JSON.parse(fs.readFileSync(p, "utf8")) as Record<string, SnippetDef>;
}

suite("insert-element contributions", () => {
  test("the messagefoundry.insertElement command is contributed", () => {
    assert.ok(
      pkg().contributes.commands.find((c) => c.command === "messagefoundry.insertElement"),
      "package.json must contribute messagefoundry.insertElement",
    );
  });

  test("messagefoundry.insertElement is keybindable", () => {
    assert.ok(
      pkg().contributes.keybindings?.find((k) => k.command === "messagefoundry.insertElement"),
      "package.json must contribute a keybinding for messagefoundry.insertElement",
    );
  });

  test("messagefoundry.insertElement is on the editor MessageFoundry submenu", () => {
    const items = pkg().contributes.menus["messagefoundry.editorMenu"] ?? [];
    assert.ok(
      items.find((e) => e.command === "messagefoundry.insertElement"),
      "the editorMenu submenu is missing messagefoundry.insertElement",
    );
  });

  test("the snippets file parses and carries the body-level transform idioms", () => {
    const prefixes = new Set(Object.values(snippets()).map((s) => s.prefix));
    for (const p of [
      "meforget",
      "meforset",
      "meforcopy",
      "meforforrep",
      "meforcodelookup",
      "mefordblookup",
      "mefordate",
      "meforsend",
      "meforsplit",
      // Palette expansion (BACKLOG #48 Lane L1): Format/Transform/Decision/Date/Lookup/Send/Raw/
      // Field/Router idioms mapping Corepoint's Action-List palette.
      "meforupper",
      "meforlower",
      "meforstrip",
      "meforsubstr",
      "meforpad",
      "meforregex",
      "meforcalc",
      "meformatch",
      "meforstamp",
      "meforlos",
      "meforingesttime",
      "meforfhirlookup",
      "meforclear",
      "meforjson",
      "meforrawtext",
      "meforfanout",
      "meforroutetype",
      "meforroutemulti",
    ]) {
      assert.ok(prefixes.has(p), `snippets file is missing prefix ${p}`);
    }
  });

  test("every snippet has a description (the quick-pick label/category source)", () => {
    for (const [name, def] of Object.entries(snippets())) {
      assert.ok(def.description, `snippet ${name} needs a description`);
    }
  });
});

suite("detectContext", () => {
  test("null above any element (e.g. import lines) — the show-everything fallback", () => {
    const text = ["import messagefoundry", "", "IB = inbound(MLLP())"].join("\n");
    assert.strictEqual(detectContext(text, 0), null);
  });

  test("router inside a @router def's body", () => {
    const text = ['@router("r")', "def route(msg):", "\treturn []"].join("\n");
    assert.strictEqual(detectContext(text, 2), "router");
  });

  test("handler inside a @handler def's body", () => {
    const text = ['@handler("h")', "def handle(msg):", "\treturn Send('o', msg)"].join("\n");
    assert.strictEqual(detectContext(text, 2), "handler");
  });

  test("resets to null after leaving a router/handler for a later connection line", () => {
    const text = [
      '@router("r")',
      "def route(msg):",
      "\treturn []",
      "",
      "OB = outbound(File())",
    ].join("\n");
    assert.strictEqual(detectContext(text, 4), null);
  });
});

suite("filterSnippetsForContext", () => {
  const catalog = {
    A: { prefix: "a", body: "a", description: "Field · A" }, // context-agnostic
    B: { prefix: "b", body: "b", description: "Send · B", context: "handler" as const },
    C: { prefix: "c", body: "c", description: "Router · C", context: "router" as const },
  };

  test("null context keeps every snippet (the fallback)", () => {
    assert.deepStrictEqual(Object.keys(filterSnippetsForContext(catalog, null)), ["A", "B", "C"]);
  });

  test("router context keeps context-agnostic + router-tagged, drops handler-tagged", () => {
    assert.deepStrictEqual(Object.keys(filterSnippetsForContext(catalog, "router")), ["A", "C"]);
  });

  test("handler context keeps context-agnostic + handler-tagged, drops router-tagged", () => {
    assert.deepStrictEqual(Object.keys(filterSnippetsForContext(catalog, "handler")), ["A", "B"]);
  });
});
