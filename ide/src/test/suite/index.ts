// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as path from "path";

import { glob } from "glob";
import Mocha from "mocha";

/**
 * The absolute path of every compiled *.test.js under `testsRoot`. Rejects when there are none:
 * mocha run over zero files reports zero failures, so a broken build or a wrong output path would
 * otherwise resolve as a passing IDE test leg.
 */
export async function findTestFiles(testsRoot: string): Promise<string[]> {
  const files = await glob("**/*.test.js", { cwd: testsRoot });
  if (files.length === 0) {
    throw new Error(`no compiled *.test.js files under ${testsRoot}; refusing to report an empty run as passing`);
  }
  return files.map((file) => path.resolve(testsRoot, file));
}

// The entry point VS Code's test host loads (extensionTestsPath). It boots mocha in the TDD interface
// (suite()/test()), discovers every compiled *.test.js next to this file, and runs them inside the
// Extension Host process — so the tests can drive the real `vscode` API against the loaded extension.
export async function run(): Promise<void> {
  const mocha = new Mocha({ ui: "tdd", color: true, timeout: 60_000 });
  for (const file of await findTestFiles(__dirname)) {
    mocha.addFile(file);
  }

  await new Promise<void>((resolve, reject) => {
    try {
      mocha.run((failures) => {
        if (failures > 0) {
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
