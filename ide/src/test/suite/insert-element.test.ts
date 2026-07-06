import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

import { buildPicks } from "../../insertElement";

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
  contributes: { commands: Array<{ command: string }> };
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
