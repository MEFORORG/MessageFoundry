// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 20008 Builder A (BACKLOG #5307, the failing-test half): the Extension Host entry point's
// `run` must reject when the tests root holds no compiled test file, and when the files it loads
// register no test. test-entry.test.ts tests findTestFiles and newSuiteMocha, which engine PR 3109
// added, so it cannot run against the entry point before that PR. This drives `run`, exported before
// and after, without the Extension Host: the compiled index.js is copied into a temporary folder, so
// its `__dirname`, the tests root it searches, is that folder; the real `glob` searches it, and
// `mocha` is a stand-in, since a second real Mocha inside this run would load files into the
// globals this run's own suites use. With index.ts at b4b1f7694eb^ both cases resolve, so
// assert.rejects fails; with index.ts on main both reject.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** What the stand-in mocha's run reports: the failure count, and the runner's `total`. */
let report: { failures: number; total: number };
/** The files the entry point handed the stand-in mocha. */
let added: string[];

class MochaStandIn {
  constructor(readonly options: Record<string, unknown>) {}
  addFile(file: string): void {
    added.push(file);
  }
  run(done: (failures: number) => void): { total: number } {
    const runner = { total: report.total };
    // Mocha calls back after run returns, so the entry point's `runner` is bound when it reads it.
    setImmediate(() => done(report.failures));
    return runner;
  }
}

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;
const realGlob: unknown = require("glob");

/** The compiled entry point, beside these compiled tests. */
const ENTRY = path.join(__dirname, "index.js");

suite("b20008-a: the test entry point's run refuses an empty run (BACKLOG #5307)", () => {
  let root: string;

  setup(() => {
    // The real path, so the folder the copy reads as __dirname matches the paths asserted here.
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "b20008-a-entry-")));
    added = [];
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
      if (request === "mocha") {
        return MochaStandIn;
      }
      // Resolved from here, since the temporary folder has no node_modules.
      return request === "glob" ? realGlob : realLoad.call(this, request, parent, isMain);
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
  });

  test("a tests root with no compiled *.test.js rejects, so a broken build is not a green leg", async () => {
    // A non-test .js (the entry point itself) and a .ts source do not count.
    fs.writeFileSync(path.join(root, "a.test.ts"), "");
    report = { failures: 0, total: 0 };
    await assert.rejects(entryRun()(), /no compiled \*\.test\.js/);
    assert.deepStrictEqual(added, []);
  });

  test("compiled test files that register no test reject, though mocha reports zero failures", async () => {
    fs.writeFileSync(path.join(root, "a.test.js"), "");
    report = { failures: 0, total: 0 };
    await assert.rejects(entryRun()(), /registered no test/);
  });
});
