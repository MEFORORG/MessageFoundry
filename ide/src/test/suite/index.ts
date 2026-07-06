import * as path from "path";

import { glob } from "glob";
import Mocha from "mocha";

// The entry point VS Code's test host loads (extensionTestsPath). It boots mocha in the TDD interface
// (suite()/test()), discovers every compiled *.test.js next to this file, and runs them inside the
// Extension Host process — so the tests can drive the real `vscode` API against the loaded extension.
export async function run(): Promise<void> {
  const mocha = new Mocha({ ui: "tdd", color: true, timeout: 60_000 });
  const testsRoot = __dirname;

  const files = await glob("**/*.test.js", { cwd: testsRoot });
  for (const file of files) {
    mocha.addFile(path.resolve(testsRoot, file));
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
