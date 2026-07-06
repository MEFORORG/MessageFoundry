import * as path from "path";

import { runTests } from "@vscode/test-electron";

// Launch a headless VS Code (downloaded on first run), load THIS extension from the repo, and run the
// mocha suite at ./suite/index inside its Extension Host. Invoked by `npm test` after the build steps
// produce dist/extension.js (the loaded extension resolves through package.json "main") and out/ (the
// compiled tests). See ide/README.md.
async function main(): Promise<void> {
  try {
    // The compiled launcher lives at out/test/runTest.js, so ../../ is the ide/ extension root
    // (package.json + dist/extension.js), and ./suite/index is the compiled mocha bootstrap.
    const extensionDevelopmentPath = path.resolve(__dirname, "../../");
    const extensionTestsPath = path.resolve(__dirname, "./suite/index");
    await runTests({ extensionDevelopmentPath, extensionTestsPath });
  } catch (err) {
    console.error("Failed to run VS Code integration tests:", err);
    process.exit(1);
  }
}

void main();
