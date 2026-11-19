// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The full-suite entry point refuses to run zero test files (vault BACKLOG #5307): mocha over an empty
// file list reports zero failures, so a broken build or a wrong output path would read as a green leg.
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { findTestFiles, newSuiteMocha } from "./index";

suite("test entry point: newSuiteMocha", () => {
  test("fails a run in which the loaded files register no test", () => {
    assert.strictEqual(newSuiteMocha().options.failZero, true);
  });
});

suite("test entry point: findTestFiles", () => {
  let root: string;

  setup(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "mf-ide-entry-"));
  });

  teardown(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  test("rejects when the tests root holds no compiled test file", async () => {
    // A non-test .js file and a .ts source do not count: only compiled *.test.js would run.
    fs.writeFileSync(path.join(root, "index.js"), "");
    fs.writeFileSync(path.join(root, "a.test.ts"), "");
    await assert.rejects(findTestFiles(root), /no compiled \*\.test\.js files under/);
  });

  test("returns the absolute path of each compiled test file, nested ones included", async () => {
    fs.mkdirSync(path.join(root, "sub"));
    fs.writeFileSync(path.join(root, "a.test.js"), "");
    fs.writeFileSync(path.join(root, "sub", "b.test.js"), "");
    fs.writeFileSync(path.join(root, "index.js"), "");
    const found = (await findTestFiles(root)).sort();
    assert.deepStrictEqual(found, [path.join(root, "a.test.js"), path.join(root, "sub", "b.test.js")].sort());
  });
});
