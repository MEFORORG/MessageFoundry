// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Promote shows a target-gate refusal the way auth.ts does: through targetRefusalNotice, so a URL
// carrying a markdown link is not rendered as one (BACKLOG #5407).
//
// This drives the real promote.ts against a stubbed `vscode`, with cli.ts's exports replaced so the
// flow reaches the gate without a Python process. Node-side only, as auth-target-gate.test.ts is:
// the Extension Host resolves the real `vscode`.
import * as assert from "assert";
import * as path from "node:path";

let errors: string[];
let target: string;

const vscodeStub = {
  window: {
    showErrorMessage: (message: string): Promise<undefined> => {
      errors.push(message);
      return Promise.resolve(undefined);
    },
    showWarningMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showInformationMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showInputBox: (): Promise<undefined> => Promise.resolve(undefined),
    showQuickPick: (): Promise<undefined> => Promise.resolve(undefined),
  },
  commands: { executeCommand: (): Promise<undefined> => Promise.resolve(undefined) },
  env: { openExternal: (): Promise<boolean> => Promise.resolve(false) },
  Uri: { parse: (v: string): string => v },
};

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

function insideExtensionHost(): boolean {
  try {
    const api = realLoad.call(loader, "vscode", module, false) as {
      version?: unknown;
      env?: { appName?: unknown };
    };
    return typeof api?.version === "string" && typeof api?.env?.appName === "string";
  } catch {
    return false;
  }
}

const NODE_SIDE = !insideExtensionHost();

type PromoteModule = typeof import("../../promote");
let promoteModule!: PromoteModule;

if (NODE_SIDE) {
  // Every extension module is loaded fresh against this stub and the cache put back afterwards, as
  // auth-target-gate.test.ts does, so a sibling suite's stubbed copies are unaffected.
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
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    const cli = require("../../cli") as Record<string, unknown>;
    cli.workspaceDir = (): string => path.join(outDir, "ws");
    cli.writerPathSetting = (): string => "config";
    cli.runJson = (): Promise<unknown> => Promise.resolve([]); // validate: no diagnostics
    cli.environments = (): { name: string; url: string }[] => [{ name: "X", url: target }];
    promoteModule = require("../../promote") as PromoteModule;
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

const gateSuite = NODE_SIDE ? suite : suite.skip;

gateSuite("promote shows a target-gate refusal escaped, as sign-in does (BACKLOG #5407)", () => {
  const context = {} as Parameters<PromoteModule["promote"]>[0];

  setup(() => {
    errors = [];
  });

  test("a refused URL carrying a markdown command link is not shown as a link", async () => {
    target = "[x](command:foo)";
    await promoteModule.promote(context);
    assert.strictEqual(errors.length, 1, JSON.stringify(errors));
    assert.ok(!/\]\(command:/.test(errors[0]), errors[0]);
    // Control: it is the target gate's refusal that was shown, the host still readable.
    assert.match(errors[0], /^MessageFoundry: not a valid engine URL: /);
  });

  test("control: a refused host is shown as written, an underscore unescaped", async () => {
    target = "http://engine_prod.invalid:8765";
    await promoteModule.promote(context);
    assert.strictEqual(errors.length, 1, JSON.stringify(errors));
    assert.ok(errors[0].includes("non-loopback host engine_prod.invalid"), errors[0]);
  });
});
