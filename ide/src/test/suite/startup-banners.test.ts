// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { alertEditorScript } from "../../alertEditorWebview";
import { codeSetEditorScript } from "../../codeSetEditorWebview";
import { connectionEditorScript } from "../../connectionEditorWebview";
import { homeScript } from "../../homeWebview";
import { FIELDS, securityEditorScript } from "../../securityEditorWebview";
import { sourceControlScript } from "../../sourceControlWebview";
import { testBenchScript } from "../../testBenchWebview";
import {
  CSP_BANNER_ID,
  SCRIPT_BANNER_ID,
  SCRIPT_STARTED_MARK,
  STARTUP_BANNERS,
} from "../../webviewMessaging";
import { wiringMapScript } from "../../wiringMapWebview";

// ASVS 3.1.1 / 3.7.5 (BACKLOG #1116, #1124): a webview that warns for itself.
//
// Two things are pinned here. The BEHAVIOUR of the two banners is measured in a real DOM, and the
// WIRING is derived from the source, so a panel added later without the banners fails this file
// rather than shipping an inert shell that says nothing.
//
// jsdom does not enforce Content-Security-Policy. That is what makes it the right instrument for
// the canary: with scripts on, it IS an engine that ignores the policy, and the warning must show.
// It cannot play an engine that enforces the policy, so that half is pinned statically below: the
// canary carries no nonce, and no panel policy would let an un-nonced inline script run.
//
// Node-side only, like webview-guard.test.ts: no `vscode` import, so this runs on the unit leg.

interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib (webview-guard.test.ts says why).
  [key: string]: any;
}
interface JsdomWindow {
  document: DomNode;
  close(): void;
  [key: string]: unknown;
}
interface JsdomModule {
  JSDOM: new (html: string, options?: Record<string, unknown>) => { window: JsdomWindow };
  VirtualConsole: new () => { on(event: string, handler: (e: unknown) => void): void };
}
const { JSDOM, VirtualConsole } = require("jsdom") as JsdomModule;

const IDE_ROOT = path.join(__dirname, "..", "..", "..");
const SRC = path.join(IDE_ROOT, "src");

const openWindows: JsdomWindow[] = [];

/** A panel shell: the banners, then `panelScript` as the panel's own script when one is given. */
function shell(
  options: { runScripts: boolean; panelScript?: string },
): { hidden(id: string): boolean; errors: unknown[] } {
  const errors: unknown[] = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e: unknown) => errors.push(e));
  const script =
    options.panelScript === undefined ? "" : `<script>${options.panelScript}</script>`;
  const dom = new JSDOM(`<!DOCTYPE html><body>${STARTUP_BANNERS}<h2>Panel</h2>${script}</body>`, {
    runScripts: options.runScripts ? "dangerously" : undefined,
    virtualConsole,
    url: "https://localhost/",
    beforeParse(window: JsdomWindow): void {
      window.acquireVsCodeApi = () => ({
        getState: () => null,
        setState: () => undefined,
        postMessage: () => undefined,
      });
    },
  });
  openWindows.push(dom.window);
  return {
    errors,
    hidden(id: string): boolean {
      const el = dom.window.document.getElementById(id);
      assert.ok(el, `the shell has no #${id}`);
      return el.hidden === true;
    },
  };
}

function productionSources(): { rel: string; text: string }[] {
  const out: { rel: string; text: string }[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "test") {
          walk(full);
        }
      } else if (entry.name.endsWith(".ts")) {
        out.push({
          rel: path.relative(SRC, full).split(path.sep).join("/"),
          text: fs.readFileSync(full, "utf8"),
        });
      }
    }
  };
  walk(SRC);
  return out;
}

suite("startup banners: what the user sees", () => {
  teardown(() => {
    for (const w of openWindows.splice(0)) {
      w.close();
    }
  });

  test("a panel whose script never runs shows the script-not-started banner", () => {
    const page = shell({ runScripts: false, panelScript: SCRIPT_STARTED_MARK });
    assert.strictEqual(page.hidden(SCRIPT_BANNER_ID), false);
    // No script ran, so the canary did not either. It reports enforcement, not script health.
    assert.strictEqual(page.hidden(CSP_BANNER_ID), true);
  });

  test("the mark hides the script-not-started banner", () => {
    // CONTROL for the test above: the same shell with scripts on. A banner that never hid would
    // pass the first test and warn on every healthy panel.
    const page = shell({
      runScripts: true,
      panelScript: `const vscode = acquireVsCodeApi();${SCRIPT_STARTED_MARK}`,
    });
    assert.deepStrictEqual(page.errors.map(String), []);
    assert.strictEqual(page.hidden(SCRIPT_BANNER_ID), true);
  });

  test("a script that dies acquiring the API leaves the banner up", () => {
    // Why the mark sits AFTER acquireVsCodeApi(): that call is the one that throws on a second run.
    const page = shell({
      runScripts: true,
      panelScript: `const vscode = (() => { throw new Error('already acquired'); })();${SCRIPT_STARTED_MARK}`,
    });
    assert.strictEqual(page.errors.length, 1);
    assert.strictEqual(page.hidden(SCRIPT_BANNER_ID), false);
  });

  test("an engine that does not enforce CSP reveals the CSP banner", () => {
    // jsdom with scripts on runs the un-nonced canary, which is exactly what a non-enforcing
    // engine would do.
    const page = shell({ runScripts: true });
    assert.deepStrictEqual(page.errors.map(String), []);
    assert.strictEqual(page.hidden(CSP_BANNER_ID), false);
  });

  test("the canary is un-nonced, and the banners need no script or stylesheet to read", () => {
    const scripts = STARTUP_BANNERS.match(/<script[^>]*>/g) ?? [];
    // Exactly one script, with no attribute at all. A nonce here would run the canary under an
    // enforcing engine and raise the warning on every healthy panel.
    assert.deepStrictEqual(scripts, ["<script>"]);
    assert.ok(STARTUP_BANNERS.includes(`id="${SCRIPT_BANNER_ID}" role="alert" style=`));
    assert.ok(STARTUP_BANNERS.includes(`id="${CSP_BANNER_ID}" role="alert" hidden style=`));
    // The script banner must not start hidden, by attribute or by inline style.
    const scriptBanner = STARTUP_BANNERS.split("</div>")[0];
    assert.ok(!/\shidden[\s>]/.test(scriptBanner) && !/display\s*:\s*none/.test(STARTUP_BANNERS));
  });
});

suite("startup banners: every real panel script hides its banner", () => {
  teardown(() => {
    for (const w of openWindows.splice(0)) {
      w.close();
    }
  });

  // Each panel's REAL script, so what runs here is what ships. Each is given the least it needs to
  // load; a script that throws later in its own setup has still run the mark, which is the claim.
  const scripts: Record<string, () => string> = {
    alertEditor: () => alertEditorScript("t", [], []),
    codeSetEditor: () => codeSetEditorScript("t", undefined, false, []),
    connectionEditor: () =>
      connectionEditorScript("t", {} as Parameters<typeof connectionEditorScript>[1]),
    home: () => homeScript("t"),
    securityEditor: () => securityEditorScript("t", FIELDS),
    sourceControl: () => sourceControlScript("t"),
    testBench: () => testBenchScript("t"),
    wiringMap: () => wiringMapScript("t"),
  };

  for (const [name, build] of Object.entries(scripts)) {
    test(`${name}: the script source carries the mark after acquireVsCodeApi()`, () => {
      const source = build();
      const acquire = source.indexOf("acquireVsCodeApi()");
      const mark = source.indexOf(SCRIPT_STARTED_MARK);
      assert.ok(acquire >= 0, "no acquireVsCodeApi() call found");
      assert.ok(mark > acquire, "the mark is missing, or runs before the API is acquired");
      // Nothing but the end of that statement sits between them.
      assert.strictEqual(source.slice(acquire, mark), "acquireVsCodeApi();");
    });
  }

  test("a real panel script hides the banner in a DOM", () => {
    const page = shell({ runScripts: true, panelScript: homeScript("t") });
    assert.strictEqual(page.hidden(SCRIPT_BANNER_ID), true);
  });
});

suite("startup banners: every builder that sets a webview's HTML is wired", () => {
  /** Any assignment to a webview's HTML; `==` does not match. */
  const ASSIGN = /\bwebview\.html\s*=(?!=)\s*([A-Za-z_.]*)/g;

  /**
   * The two documents that run NO script, so a script-not-started banner on them would never
   * clear. Named, with the reason, so that a third is a decision and not an oversight.
   */
  const STATIC_NOTICES: Record<string, string> = {
    // Set before `enableScripts`; a one-line text notice shown while the file reopens as text.
    "configEditors.ts": "",
    // `default-src 'none'` with no `script-src`; shown while the resource reopens as text.
    "stepsView.ts": "noticeHtml",
  };

  const sources = productionSources();
  const byRel = new Map(sources.map((s) => [s.rel, s.text]));

  /** Every assignment, as the file it is in and the function it calls ("" for a string literal). */
  function assignments(): { rel: string; callee: string }[] {
    const found: { rel: string; callee: string }[] = [];
    for (const { rel, text } of sources) {
      for (const m of text.matchAll(ASSIGN)) {
        // A mention inside a comment is not an assignment.
        const lineStart = text.lastIndexOf("\n", m.index) + 1;
        const before = text.slice(lineStart, m.index).trim();
        if (before.startsWith("//") || before.startsWith("*")) {
          continue;
        }
        found.push({ rel, callee: m[1] });
      }
    }
    return found;
  }

  /** The file that defines the builder an assignment calls. */
  function definingFile(rel: string, callee: string): string {
    if (callee.startsWith("this.")) {
      return rel;
    }
    const defines = new RegExp(`\\bfunction ${callee}\\s*\\(`);
    // A module's own function wins: two editors each keep a private `formHtml`.
    if (defines.test(byRel.get(rel) ?? "")) {
      return rel;
    }
    const defined = sources.filter((s) => defines.test(s.text));
    assert.strictEqual(
      defined.length,
      1,
      `${rel} assigns webview.html from ${callee}(), defined in ${defined.length} files`,
    );
    return defined[0].rel;
  }

  test("the scan finds the panels that ship today", () => {
    // POSITIVE CONTROL: an extraction that matched nothing would pass everything below.
    const files = new Set(assignments().map((a) => a.rel));
    assert.ok(files.size >= 13, `found ${files.size}: ${[...files].sort().join(", ")}`);
    for (const known of ["home.ts", "stepsView.ts", "configEditors.ts", "testBench.ts"]) {
      assert.ok(files.has(known), `${known} was not found setting a webview's HTML`);
    }
  });

  test("every assignment is a builder that carries the banners, or a named static notice", () => {
    const unwired: string[] = [];
    const usedNotices = new Set<string>();
    for (const { rel, callee } of assignments()) {
      if (STATIC_NOTICES[rel] === callee) {
        usedNotices.add(rel);
        continue;
      }
      if (callee === "") {
        unwired.push(`${rel}: a string literal that is not a named static notice`);
        continue;
      }
      const home = definingFile(rel, callee);
      const text = byRel.get(home) ?? "";
      // The banners go first in the body, so the user reads them before anything inert.
      if (!/<body>\r?\n\s*\$\{STARTUP_BANNERS\}/.test(text)) {
        unwired.push(`${rel}: ${callee}() in ${home} does not open its <body> with STARTUP_BANNERS`);
      }
    }
    assert.deepStrictEqual(unwired, []);
    // Every exception is still in use; a stale one would hide the next unwired builder there.
    assert.deepStrictEqual([...usedNotices].sort(), Object.keys(STATIC_NOTICES).sort());
  });

  test("every file that embeds the banners has exactly one shell, and its script hides the banner", () => {
    const carriers = sources.filter(
      (s) => s.text.includes("${STARTUP_BANNERS}") && s.rel !== "webviewMessaging.ts",
    );
    assert.ok(carriers.length >= 12, `only ${carriers.length} files embed the banners`);
    const stepsScript = fs.readFileSync(path.join(IDE_ROOT, "media", "stepsWebview.js"), "utf8");
    for (const { rel, text } of carriers) {
      assert.strictEqual(text.split("${STARTUP_BANNERS}").length - 1, 1, rel);
      const webview = byRel.get(rel.replace(/\.ts$/, "Webview.ts"));
      const hides =
        text.includes("acquireVsCodeApi();${SCRIPT_STARTED_MARK}") ||
        (webview !== undefined &&
          webview.includes("acquireVsCodeApi();${SCRIPT_STARTED_MARK}")) ||
        // The Steps view's script is a static file, so it spells the id out.
        (rel === "stepsView.ts" &&
          stepsScript.includes(`document.getElementById('${SCRIPT_BANNER_ID}')`) &&
          /mfBanner\.hidden = true/.test(stepsScript));
      assert.ok(hides, `${rel} shows the banner and no script of its own hides it`);
    }
  });

  test("no panel policy would let the un-nonced canary run under an enforcing engine", () => {
    const policies = sources.flatMap(({ rel, text }) =>
      [...text.matchAll(/http-equiv="Content-Security-Policy"\s*content="([^"]*)"/g)].map((m) => ({
        rel,
        policy: m[1].replace(/\\'/g, "'"),
      })),
    );
    assert.ok(policies.length >= 12, `found ${policies.length} policies`);
    for (const { rel, policy } of policies) {
      assert.ok(policy.includes("default-src 'none'"), `${rel}: ${policy}`);
      const scriptSrc = /script-src ([^;]*)/.exec(policy);
      if (scriptSrc === null) {
        // No script-src: default-src 'none' governs, and the document runs no script at all.
        continue;
      }
      assert.ok(scriptSrc[1].includes("'nonce-"), `${rel}: script-src has no nonce: ${policy}`);
      assert.ok(
        !/'unsafe-inline'|'unsafe-eval'|\*/.test(scriptSrc[1]),
        `${rel}: script-src would run the canary: ${policy}`,
      );
    }
  });
});
