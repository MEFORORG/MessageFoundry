// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 20008 Builder A (BACKLOG #5409 added item 1, the failing-test half): the Test Bench Debug
// launch hands debugpy the interpreter options the CLI bridge launches with, so `-P` keeps the
// workspace off the import path. b532w3-ide-debugpy.test.ts pins the wiring by reading testBench.ts's
// source, and pins the program form that later replaced the module form; neither drives the launch.
// This drives the real TestBench.debugRow, a method present before and after the fix, with `vscode`
// stubbed, and asserts on the configuration it hands `vscode.debug.startDebugging`. With
// testBench.ts at cc1b376f15^ (before engine PR 3127) the configuration carries no `pythonArgs`, so
// the assertion below fails; with testBench.ts on main it passes.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** Every configuration the stubbed `vscode.debug.startDebugging` received. */
let launched: { folder: unknown; config: Record<string, unknown> }[] = [];
let workspace = "";

const vscodeStub = {
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] {
      return [{ uri: { fsPath: workspace } }];
    },
    isTrusted: true,
    // No setting is set, so cli.ts's readers return their manifest fallbacks.
    getConfiguration: () => ({
      get: (_key: string, fallback: unknown): unknown => fallback,
      inspect: (): undefined => undefined,
    }),
  },
  window: {
    showErrorMessage: (m: string): Promise<undefined> => {
      throw new Error(`debugRow showed an error: ${m}`);
    },
    showWarningMessage: (): Promise<undefined> => Promise.resolve(undefined),
    createOutputChannel: () => ({ appendLine: (): void => {}, show: (): void => {}, dispose: (): void => {} }),
  },
  debug: {
    startDebugging: (folder: unknown, config: Record<string, unknown>): Promise<boolean> => {
      launched.push({ folder, config });
      return Promise.resolve(true);
    },
  },
  ViewColumn: { Active: -1 },
  Uri: { file: (fsPath: string) => ({ scheme: "file", fsPath }) },
};

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

/** True inside the Extension Host, where the REAL `vscode` API resolves; engine-trust-shell.test.ts
 *  says why it asks for the API rather than for resolution, and why the suite skips there. */
function insideExtensionHost(): boolean {
  try {
    const api = realLoad.call(loader, "vscode", module, false) as { version?: unknown; env?: { appName?: unknown } };
    return typeof api?.version === "string" && typeof api?.env?.appName === "string";
  } catch {
    return false;
  }
}

const NODE_SIDE = !insideExtensionHost();

type TestBenchModule = typeof import("../../testBench");
let testBenchModule!: TestBenchModule;

if (NODE_SIDE) {
  // Every extension module, not only testBench.js, is loaded fresh against THIS stub and the cache
  // put back afterwards: another suite's cached cli.js is bound to another suite's stub, and a copy
  // bound to this one must not replace it for the rest of the run.
  const outRoot = path.resolve(__dirname, "..", "..");
  const testRoot = path.join(outRoot, "test") + path.sep;
  const ours = (f: string): boolean => f.startsWith(outRoot + path.sep) && !f.startsWith(testRoot);
  const saved = new Map(Object.keys(require.cache).filter(ours).map((f) => [f, require.cache[f]]));
  for (const f of saved.keys()) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    testBenchModule = require("../../testBench") as TestBenchModule;
  } finally {
    loader._load = realLoad;
    for (const f of Object.keys(require.cache).filter(ours)) {
      delete require.cache[f];
    }
    for (const [f, entry] of saved) {
      require.cache[f] = entry;
    }
  }
}

/** The private members of TestBench this test reaches, as they read in both versions. */
interface TestBenchInternals {
  rows: { source: string; path?: string }[];
  debugRow(index: number): Promise<void>;
}

const launchSuite = NODE_SIDE ? suite : suite.skip;

launchSuite("b20008-a: the Test Bench Debug launch carries -P (BACKLOG #5409 added item 1)", () => {
  let base: string;

  setup(() => {
    base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "b20008-a-debug-")));
    workspace = path.join(base, "ws");
    fs.mkdirSync(workspace);
    launched = [];
  });

  teardown(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  /** A TestBench with one loaded row, its debugRow driven for that row; returns what was launched. */
  async function debugOneRow(): Promise<Record<string, unknown>> {
    const storage = path.join(base, "storage");
    const context = {
      subscriptions: [],
      globalStorageUri: { scheme: "file", fsPath: storage, with: () => ({ fsPath: storage }) },
    };
    const bench = new testBenchModule.TestBench(context as unknown as import("vscode").ExtensionContext);
    const internals = bench as unknown as TestBenchInternals;
    internals.rows = [{ source: "adt_a01.hl7", path: path.join(workspace, "adt_a01.hl7") }];
    await internals.debugRow(0);
    // THE CONTROL: the launch was reached and captured, so an assertion below is about its content.
    assert.strictEqual(launched.length, 1, "debugRow did not call startDebugging exactly once");
    const { config } = launched[0];
    assert.strictEqual(config.type, "debugpy");
    assert.strictEqual(config.request, "launch");
    return config;
  }

  test("the launch hands debugpy -P (or -I) in pythonArgs, so the workspace is off the import path", async () => {
    const config = await debugOneRow();
    const args = config.pythonArgs;
    assert.ok(
      Array.isArray(args) && (args.includes("-P") || args.includes("-I")),
      `the Debug launch carries no -P or -I in pythonArgs: ${JSON.stringify(config)}`,
    );
  });

  test("the launch's pythonArgs are the CLI bridge's interpreter options, in order", async () => {
    const { INTERPRETER_OPTIONS } = require("../../engineControlModel") as typeof import("../../engineControlModel");
    const config = await debugOneRow();
    assert.deepStrictEqual(config.pythonArgs, [...INTERPRETER_OPTIONS], JSON.stringify(config));
  });
});
