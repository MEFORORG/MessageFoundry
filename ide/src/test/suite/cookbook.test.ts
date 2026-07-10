import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

// Deliberately imports the pure catalog module, NOT ../../cookbook (which pulls in `vscode` for the
// webview panel) — this suite runs unchanged under plain Node/Mocha, no Extension Host required.
import { RECIPES, searchBlob } from "../../cookbookRecipes";

interface Pkg {
  contributes: {
    commands: Array<{ command: string }>;
    walkthroughs?: Array<{
      id: string;
      steps: Array<{ id: string; description: string; media?: { markdown?: string } }>;
    }>;
  };
}

function pkg(): Pkg {
  const p = path.join(__dirname, "..", "..", "..", "package.json");
  return JSON.parse(fs.readFileSync(p, "utf8")) as Pkg;
}

// The static-snippet catalog is pure (no `vscode` import) — this suite runs unchanged under plain
// Node/Mocha (no Extension Host needed) if the GUI test harness can't launch in this sandbox.
suite("cookbook recipe catalog", () => {
  test("carries 8-12 recipes (BACKLOG #104 — a gallery, not a sprawling library)", () => {
    assert.ok(RECIPES.length >= 8 && RECIPES.length <= 12, `got ${RECIPES.length} recipes`);
  });

  test("every recipe has a unique id and every field populated", () => {
    const seen = new Set<string>();
    for (const r of RECIPES) {
      assert.ok(r.id, "recipe missing id");
      assert.ok(!seen.has(r.id), `duplicate recipe id ${r.id}`);
      seen.add(r.id);
      assert.ok(r.title, `${r.id} missing title`);
      assert.ok(r.category, `${r.id} missing category`);
      assert.ok(r.summary, `${r.id} missing summary`);
      assert.ok(r.tags.length > 0, `${r.id} needs at least one tag`);
      assert.ok(r.code.trim().length > 0, `${r.id} missing code`);
    }
  });

  test("every recipe's code is a Router or Handler body (the two code-first building blocks)", () => {
    for (const r of RECIPES) {
      assert.ok(
        /@router\(|@handler\(/.test(r.code),
        `${r.id} should scaffold a @router or @handler`,
      );
    }
  });

  test("no recipe carries a stray '$' that isn't a snippet tabstop", () => {
    // new vscode.SnippetString(code) parses $1 / ${1:x} as tabstops; any other literal '$' would be
    // misread as the start of one. Every deliberate tabstop here is the ${n:...} form.
    for (const r of RECIPES) {
      const strays = r.code.match(/\$(?!\{\d+:)/g);
      assert.strictEqual(strays, null, `${r.id} has a non-tabstop '$': ${JSON.stringify(strays)}`);
    }
  });

  test("no recipe spells the forbidden space-form 'action-list(s)' phrase (leak-gate)", () => {
    for (const r of RECIPES) {
      assert.ok(
        !/\baction\s+lists?\b/i.test(`${r.title} ${r.summary} ${r.code}`),
        `${r.id} must not spell the space form of "action-list(s)"`,
      );
    }
  });

  test("searchBlob matches on title/summary/category/tags and is used to find real recipes", () => {
    const find = (q: string): string[] =>
      RECIPES.filter((r) => searchBlob(r).includes(q.toLowerCase())).map((r) => r.id);
    assert.ok(find("split").includes("split-batch-by-obr"));
    assert.ok(find("code_set").includes("codeset-crosswalk") || find("crosswalk").includes("codeset-crosswalk"));
    assert.ok(find("db_lookup").includes("enrich-db-lookup"));
    assert.ok(find("fan-out").includes("fan-out-multiple-outbounds"));
    assert.deepStrictEqual(find("no-such-recipe-should-match-nothing"), []);
  });
});

suite("cookbook + walkthrough contributions", () => {
  test("the messagefoundry.openCookbook command is contributed", () => {
    assert.ok(
      pkg().contributes.commands.find((c) => c.command === "messagefoundry.openCookbook"),
      "package.json must contribute messagefoundry.openCookbook",
    );
  });

  test("a getting-started walkthrough is contributed, ending at the Cookbook", () => {
    const walkthroughs = pkg().contributes.walkthroughs ?? [];
    assert.ok(walkthroughs.length > 0, "package.json must contribute at least one walkthrough");
    const flow = walkthroughs[0];
    const stepIds = flow.steps.map((s) => s.id);
    for (const expected of ["newConnection", "newRoute", "insertElement", "testBench", "cookbook"]) {
      assert.ok(stepIds.includes(expected), `walkthrough is missing the ${expected} step`);
    }
  });

  test("every walkthrough step links a real command and a markdown file that exists on disk", () => {
    const walkthroughs = pkg().contributes.walkthroughs ?? [];
    const extRoot = path.join(__dirname, "..", "..", "..");
    for (const flow of walkthroughs) {
      for (const step of flow.steps) {
        assert.ok(
          /\]\(command:messagefoundry\.\w+\)/.test(step.description),
          `step ${step.id} should link a messagefoundry command`,
        );
        const md = step.media?.markdown;
        assert.ok(md, `step ${step.id} needs a markdown media file`);
        if (md) {
          assert.ok(
            fs.existsSync(path.join(extRoot, md)),
            `step ${step.id}'s media file ${md} does not exist`,
          );
        }
      }
    }
  });
});
