// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 20008 Builder A (BACKLOG #5307, the failing-test half).
// The Extension Host entry point's `run` must reject an empty run. That covers a tests root with no
// compiled test file, and files that register no test. test-entry.test.ts tests findTestFiles and
// newSuiteMocha. Engine PR 3109 added both, so that file cannot run against the code before it.
// This file drives `run`, which both versions export, without the Extension Host. The compiled
// index.js is copied into a temporary folder, so its `__dirname`, the root it searches, is that
// folder. The real `glob` searches it. `mocha` is a stand-in for the copy alone: a second real Mocha
// inside this run would load files into the globals this run's own suites use.
// Each guard is pinned on its own: the zero-file refusal, the zero-test refusal, and failZero.
// With index.ts at b4b1f7694eb^, the three fail as assertions. On main all four tests pass.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** What the stand-in mocha's run reports: the failure count, and the runner's `total`. */
let report: { failures: number; total: number };
/** The files the entry point handed the stand-in mocha. */
let added: string[];
/** How many times the entry point called the stand-in's run. */
let runs: number;
/** The options the last stand-in was built with. */
let lastOptions: Record<string, unknown> | undefined;

class MochaStandIn {
  constructor(readonly options: Record<string, unknown>) {
    lastOptions = options;
  }
  addFile(file: string): void {
    added.push(file);
  }
  run(done: (failures: number) => void): { total: number } {
    runs++;
    const runner = { total: report.total };
    // Mocha 12 counts a run of zero tests as one failure when failZero is set.
    const failures = report.failures + (this.options.failZero === true && report.total === 0 ? 1 : 0);
    // Mocha calls back after run returns, so the entry point's `runner` is bound when it reads it.
    setImmediate(() => done(failures));
    return runner;
  }
}

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

/** The compiled entry point, beside these compiled tests. */
const ENTRY = path.join(__dirname, "index.js");

suite("b20008-a: the test entry point's run refuses an empty run (BACKLOG #5307)", () => {
  let root: string;

  setup(() => {
    // The real path, so the folder the copy reads as __dirname matches the paths asserted here.
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "b20008-a-entry-")));
    added = [];
    runs = 0;
    lastOptions = undefined;
    report = { failures: 0, total: 1 };
  });

  teardown(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  /** `run` from a copy of the compiled entry point whose tests root is `root`. */
  function entryRun(): () => Promise<void> {
    const copy = path.join(root, "index.js");
    fs.copyFileSync(ENTRY, copy);
    loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
      if ((parent as { filename?: unknown } | null)?.filename !== copy) {
        return realLoad.call(this, request, parent, isMain);
      }
      // Only the copy gets the stand-in, so no module cached for the rest of the run is bound to it.
      if (request === "mocha") {
        return MochaStandIn;
      }
      // The copy's other imports resolve as the original's would, since the temporary folder has
      // no node_modules and no siblings: a package from here, a relative import beside the original.
      const target = request.startsWith(".") ? path.resolve(path.dirname(ENTRY), request) : request;
      return realLoad.call(this, target, module, isMain);
    };
    try {
      return (require(copy) as { run: () => Promise<void> }).run;
    } finally {
      loader._load = realLoad;
      delete require.cache[copy];
    }
  }

  test("THE CONTROL: a tests root with a compiled test that registers a test and passes resolves", async () => {
    fs.writeFileSync(path.join(root, "a.test.js"), "");
    await entryRun()();
    assert.deepStrictEqual(added, [path.join(root, "a.test.js")]);
    assert.strictEqual(runs, 1);
  });

  test("a tests root with no compiled *.test.js rejects before mocha runs, so a broken build is not a green leg", async () => {
    // A non-test .js (the entry point itself) and a .ts source do not count.
    fs.writeFileSync(path.join(root, "a.test.ts"), "");
    report = { failures: 0, total: 0 };
    await assert.rejects(entryRun()(), /no compiled \*\.test\.js/);
    assert.deepStrictEqual(added, []);
    assert.strictEqual(runs, 0, "mocha ran, so a later guard, not the zero-file refusal, rejected");
  });

  test("compiled test files that register no test reject on the runner's own count", async () => {
    fs.writeFileSync(path.join(root, "a.test.js"), "");
    report = { failures: 0, total: 0 };
    await assert.rejects(entryRun()(), /registered no test/);
  });

  test("the run's mocha is built with failZero, so mocha's own count fails a run of no test", async () => {
    fs.writeFileSync(path.join(root, "a.test.js"), "");
    await entryRun()();
    assert.strictEqual(lastOptions?.failZero, true, JSON.stringify(lastOptions));
  });
});
