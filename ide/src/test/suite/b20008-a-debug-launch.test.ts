// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 20008 Builder A (BACKLOG #5409 added item 1, the failing-test half).
// The Test Bench Debug launch hands debugpy the CLI bridge's interpreter options, `-P` among them.
// `-P` alone is not the whole control. TEST_BENCH_DEBUG_PROGRAM's docblock in
// testBenchDebugProgram.ts says which debugpy builds need the written program, and what stays open.
// b532w3-ide-debugpy.test.ts pins this wiring by reading testBench.ts's source.
// None of its tests drives debugRow. This file drives the real TestBench.debugRow, with `vscode`
// stubbed. That method exists before and after the fix. The tests assert on what it hands
// `vscode.debug.startDebugging`. With testBench.ts at cc1b376f15^ (before engine PR 3127), the
// configuration has no `pythonArgs`, so the item 1 test fails as an assertion. On main all pass.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { INTERPRETER_OPTIONS } from "../../engineControlModel";
import { TEST_BENCH_DEBUG_PROGRAM, debugProgramFileName } from "../../testBenchDebugProgram";

/** Every configuration the stubbed `vscode.debug.startDebugging` received. */
let launched: { folder: unknown; config: Record<string, unknown> }[] = [];
/** Every error notice debugRow showed. */
let errors: string[] = [];
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
      errors.push(m);
      return Promise.resolve(undefined);
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
    errors = [];
  });

  teardown(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  /** The global storage folder the stubbed context hands debugRow. */
  const storageDir = (): string => path.join(base, "storage");

  /** A TestBench with one loaded row whose global storage has `scheme`, its debugRow driven. */
  async function driveDebugRow(scheme: string): Promise<void> {
    const storage = storageDir();
    const context = {
      subscriptions: [],
      globalStorageUri: { scheme, fsPath: storage, with: () => ({ fsPath: storage }) },
    };
    const bench = new testBenchModule.TestBench(context as unknown as import("vscode").ExtensionContext);
    const internals = bench as unknown as TestBenchInternals;
    internals.rows = [{ source: "adt_a01.hl7", path: path.join(workspace, "adt_a01.hl7") }];
    await internals.debugRow(0);
  }

  /** debugRow driven with local storage; returns the one configuration it launched. */
  async function debugOneRow(): Promise<Record<string, unknown>> {
    await driveDebugRow("file");
    // THE CONTROL: the launch was reached and captured, so an assertion below is about its content.
    assert.deepStrictEqual(errors, []);
    assert.strictEqual(launched.length, 1, "debugRow did not call startDebugging exactly once");
    const { config } = launched[0];
    assert.strictEqual(config.type, "debugpy");
    assert.strictEqual(config.request, "launch");
    return config;
  }

  test("item 1: the launch hands debugpy the CLI bridge's interpreter options, -P among them, as pythonArgs", async () => {
    const config = await debugOneRow();
    const args = config.pythonArgs;
    assert.ok(Array.isArray(args) && args.includes("-P"), `the Debug launch carries no -P in pythonArgs: ${JSON.stringify(config)}`);
    assert.deepStrictEqual(args, [...INTERPRETER_OPTIONS], JSON.stringify(config));
  });

  // The two item 2 tests are not this row's failing-test half; item 2 closed on its own evidence.
  // They pin, by driving the launch, the form that the docblock the header names says -P needs.
  test("item 2: the launch names the program writeDebugProgram wrote, never the module", async () => {
    const config = await debugOneRow();
    assert.strictEqual(config.module, undefined, JSON.stringify(config));
    const program = path.join(storageDir(), TEST_BENCH_DEBUG_PROGRAM.folder, debugProgramFileName(TEST_BENCH_DEBUG_PROGRAM.source));
    assert.strictEqual(config.program, program, JSON.stringify(config));
    assert.strictEqual(fs.readFileSync(program, "utf8"), TEST_BENCH_DEBUG_PROGRAM.source);
  });

  test("item 2: a program that cannot be written refuses the launch, never falling back to the module", async () => {
    // A remote window's storage has no local path, so writeDebugProgram refuses it.
    await driveDebugRow("vscode-remote");
    assert.deepStrictEqual(launched, [], "debugRow launched though the program was not written");
    assert.strictEqual(errors.length, 1, JSON.stringify(errors));
    assert.ok(errors[0].startsWith("MessageFoundry: Debug did not start: "), errors[0]);
  });
});
