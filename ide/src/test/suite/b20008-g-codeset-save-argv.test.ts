// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5834: a save from the code-set custom editor ran `codeset upsert` with no `--name`, which
// the CLI reads as a create (`create = --name is None`), so every save of the opened file was refused
// as a collision with that same file.
//
// This drives the save through the provider itself, CodeSetCustomEditorProvider.resolveCustomTextEditor
// and the webview's "save" message, which the provider had before the fix as well as after, and reads
// the argv it hands the CLI runner. b622-5834-codeset-editor-upsert.test.ts pins the argv helper the fix
// added, so it cannot run against the code before it; this one can, and fails there as an assertion.
//
// configEditors.ts imports vscode, so it is loaded against a stub with cli.ts's exports replaced, as
// promote-target-gate.test.ts does. Node-side only: the Extension Host resolves the real `vscode`.
import * as assert from "assert";
import * as path from "node:path";

const WIN = process.platform === "win32";
const WS = WIN ? "C:\\ws" : "/ws";
const CONFIG = "samples/config";
const STEM = "epic_diets";
const FILE = path.join(WS, "samples", "config", "codesets", `${STEM}.csv`);
const DETAIL = { name: STEM, format: "csv", columns: ["key", "value"], rows: [["A", "B"]] };

/** Every argv the provider handed the CLI runner, in order. */
let calls: string[][] = [];

const disposable = { dispose: (): void => undefined };
const vscodeStub = {
  window: {
    showInformationMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showWarningMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showErrorMessage: (): Promise<undefined> => Promise.resolve(undefined),
  },
  commands: { executeCommand: (): Promise<undefined> => Promise.resolve(undefined) },
  workspace: { onDidChangeTextDocument: () => disposable },
};

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

type Editors = typeof import("../../configEditors");
let editors: Editors | undefined;

if (!insideExtensionHost()) {
  // Every extension module is loaded fresh against the stub and the cache put back afterwards, so a
  // sibling suite's stubbed copies are unaffected.
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
    cli.workspaceDir = (): string => WS;
    cli.configDir = (): string => CONFIG;
    cli.writerPathSetting = (): string => CONFIG;
    cli.runJson = (args: string[]): Promise<unknown> => {
      calls.push(args);
      if (args[0] === "codeset" && args[1] === "show") {
        return Promise.resolve(DETAIL);
      }
      if (args[0] === "codeset" && args[1] === "list") {
        return Promise.resolve([{ name: STEM }]);
      }
      return Promise.resolve({});
    };
    editors = require("../../configEditors") as Editors;
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

const providerSuite = editors === undefined ? suite.skip : suite;

/** Let the provider's un-awaited first render (two runJson calls) settle. */
async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

providerSuite("CodeSetCustomEditorProvider: a save of the opened file passes --name <stem> (BACKLOG #5834)", () => {
  setup(() => {
    calls = [];
  });

  test("the upsert argv the provider sends carries --name and the file's stem", async () => {
    let onMessage: ((m: unknown) => Promise<void>) | undefined;
    let onDispose: (() => void) | undefined;
    const posted: unknown[] = [];
    const webview = {
      options: {},
      html: "",
      cspSource: "vscode-resource:",
      onDidReceiveMessage: (cb: (m: unknown) => Promise<void>) => {
        onMessage = cb;
        return disposable;
      },
      postMessage: (m: unknown): Promise<boolean> => {
        posted.push(m);
        return Promise.resolve(true);
      },
    };
    const panel = {
      webview,
      onDidDispose: (cb: () => void) => {
        onDispose = cb;
        return disposable;
      },
    };
    const document = {
      uri: { scheme: "file", fsPath: FILE, toString: (): string => `file://${FILE}` },
      fileName: FILE,
      getText: (): string => "key,value\nA,B\n",
    };
    type Resolve = Parameters<InstanceType<Editors["CodeSetCustomEditorProvider"]>["resolveCustomTextEditor"]>;
    const provider = new (editors as Editors).CodeSetCustomEditorProvider();
    provider.resolveCustomTextEditor(
      document as unknown as Resolve[0],
      panel as unknown as Resolve[1],
      {} as Resolve[2],
    );
    try {
      await settle();
      // Control: the guard took the file as the config dir's own, so the grid rendered from the CLI's
      // read of it. The guard's refusal paints a notice page and never runs `codeset show`.
      assert.ok(
        calls.some((a) => a[0] === "codeset" && a[1] === "show" && a.includes(STEM)),
        `the grid never read the code set; posted ${JSON.stringify(posted)}`,
      );
      assert.ok(onMessage !== undefined, "the provider registered no message handler");
      await onMessage({ command: "save", detail: DETAIL });
      const upsert = calls.find((a) => a[0] === "codeset" && a[1] === "upsert");
      assert.ok(upsert !== undefined, `no codeset upsert was sent; posted ${JSON.stringify(posted)}`);
      const i = upsert.indexOf("--name");
      assert.ok(i !== -1, `no --name in the upsert argv: ${upsert.join(" ")}`);
      assert.strictEqual(upsert[i + 1], STEM);
      assert.deepStrictEqual(upsert.slice(0, 4), ["codeset", "upsert", "--config", CONFIG]);
    } finally {
      onDispose?.(); // clears the provider's save-guard timer
    }
  });
});
