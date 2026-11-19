// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as path from "path";

import { glob } from "glob";
import Mocha from "mocha";

/**
 * The absolute path of every compiled *.test.js under `testsRoot`. Rejects when there are none:
 * mocha run over zero files reports zero failures, so a build that emitted no tests, or an output
 * path that holds none, would otherwise resolve as a passing IDE test leg. It does not catch stale
 * tests left in an uncleaned out/ by an earlier build.
 */
export async function findTestFiles(testsRoot: string): Promise<string[]> {
  const files = await glob("**/*.test.js", { cwd: testsRoot });
  if (files.length === 0) {
    throw new Error(`no compiled *.test.js files under ${testsRoot}; refusing to report an empty run as passing`);
  }
  return files.map((file) => path.resolve(testsRoot, file));
}

/** The suite's mocha. failZero: files that load but register no test fail the run too. */
export function newSuiteMocha(): Mocha {
  return new Mocha({ ui: "tdd", color: true, timeout: 60_000, failZero: true });
}

// The entry point VS Code's test host loads (extensionTestsPath). It boots mocha in the TDD interface
// (suite()/test()), discovers every compiled *.test.js next to this file, and runs them inside the
// Extension Host process — so the tests can drive the real `vscode` API against the loaded extension.
export async function run(): Promise<void> {
  const mocha = newSuiteMocha();
  for (const file of await findTestFiles(__dirname)) {
    mocha.addFile(file);
  }

  await new Promise<void>((resolve, reject) => {
    try {
      const runner = mocha.run((failures) => {
        if (runner.total === 0) {
          reject(new Error("the compiled test files registered no test; refusing to report an empty run as passing"));
        } else if (failures > 0) {
          reject(new Error(`${failures} test(s) failed.`));
        } else {
          resolve();
        }
      });
    } catch (err) {
      reject(err instanceof Error ? err : new Error(String(err)));
    }
  });
}
