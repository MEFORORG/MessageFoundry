// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as fs from "fs";
import * as path from "path";

import { downloadAndUnzipVSCode, runTests } from "@vscode/test-electron";

/**
 * The oldest VS Code this extension claims to run on, read from package.json `engines.vscode`.
 *
 * Read rather than written here, so raising the floor there moves the test with it. Only the plain
 * `^X.Y.Z` form is accepted: any other range has no single floor to test, and guessing one would
 * report a version as covered that nobody ran.
 */
function declaredFloor(extensionRoot: string): string {
  const pkg = JSON.parse(fs.readFileSync(path.join(extensionRoot, "package.json"), "utf8")) as {
    engines?: { vscode?: string };
  };
  const range = pkg.engines?.vscode ?? "";
  const m = /^\^(\d+\.\d+\.\d+)$/.exec(range);
  if (!m) {
    throw new Error(`engines.vscode is ${JSON.stringify(range)}; expected ^X.Y.Z to derive a test floor`);
  }
  return m[1];
}

/** One launch: which VS Code build, and which test entry its Extension Host loads. */
interface Run {
  readonly name: "floor" | "stable";
  /** Resolved lazily, so a run that is not selected never has to derive its version. */
  readonly version: () => string;
  readonly extensionTestsPath: string;
  readonly what: string;
}

/**
 * The launches `npm test` makes. Default: both.
 *
 * `floor` is the build package.json declares as the minimum, and it runs the webview delivery probe
 * ALONE, through the mocha-free probeHost.ts: the test harness's own dev dependencies need a newer
 * Node than that build's Extension Host carries (probeHost.ts records the measurement), so the full
 * suite cannot load there. `stable` runs the full suite, which includes the same probe. So the probe
 * is measured at both ENDS of the declared range, and the builds between them are not measured.
 *
 * `MF_IDE_TEST_RUNS` (comma-separated `floor` / `stable`) narrows it for a quicker local run.
 */
function runsToMake(extensionRoot: string, testsRoot: string): Run[] {
  const all: Run[] = [
    {
      name: "floor",
      version: () => declaredFloor(extensionRoot),
      extensionTestsPath: path.resolve(testsRoot, "./probeHost"),
      what: "delivery probe only",
    },
    {
      name: "stable",
      version: () => "stable",
      extensionTestsPath: path.resolve(testsRoot, "./suite/index"),
      what: "full suite",
    },
  ];
  const raw = process.env.MF_IDE_TEST_RUNS?.trim();
  if (!raw) {
    return all;
  }
  const wanted = raw.split(",").map((v) => v.trim());
  const unknown = wanted.filter((w) => !all.some((r) => r.name === w));
  if (unknown.length > 0) {
    throw new Error(`MF_IDE_TEST_RUNS names no run: ${unknown.join(", ")} (expected floor and/or stable)`);
  }
  return all.filter((r) => wanted.includes(r.name));
}

// Launch a headless VS Code (downloaded on first run), load THIS extension from the repo, and run a
// test entry inside its Extension Host, once per run above. Invoked by `npm test` after the build
// steps produce dist/extension.js (the loaded extension resolves through package.json "main") and
// out/ (the compiled tests). See ide/README.md.
//
// Every run is attempted even when an earlier one fails, so a floor-only problem cannot hide the
// stable suite's result. The exit code is non-zero if any run failed.
async function main(): Promise<void> {
  // The compiled launcher lives at out/test/runTest.js, so ../../ is the ide/ extension root
  // (package.json + dist/extension.js), and this directory holds the compiled test entries.
  const extensionDevelopmentPath = path.resolve(__dirname, "../../");
  let runs: Run[];
  try {
    runs = runsToMake(extensionDevelopmentPath, __dirname);
  } catch (err) {
    console.error("Failed to choose the VS Code integration test runs:", err);
    process.exit(1);
  }
  const passed: string[] = [];
  const failed: string[] = [];
  for (const run of runs) {
    const label = `${run.name} (${run.what})`;
    try {
      const version = run.version();
      console.log(`\n=== VS Code integration tests: ${label}, version ${version} ===`);
      // Resolve the build first, so the log names the one that ran rather than the word "stable".
      const vscodeExecutablePath = await downloadAndUnzipVSCode(version);
      console.log(`=== ${label}: ${vscodeExecutablePath} ===`);
      // A profile per run. The default one is shared, and a much older build opening state that the
      // newest build wrote is a downgrade VS Code does not promise to handle.
      const profile = path.join(extensionDevelopmentPath, ".vscode-test", `profile-${run.name}`);
      await runTests({
        vscodeExecutablePath,
        extensionDevelopmentPath,
        extensionTestsPath: run.extensionTestsPath,
        launchArgs: [
          `--user-data-dir=${path.join(profile, "user-data")}`,
          `--extensions-dir=${path.join(profile, "extensions")}`,
        ],
      });
      passed.push(label);
    } catch (err) {
      console.error(`Failed to run VS Code integration tests: ${label}:`, err);
      failed.push(label);
    }
  }
  console.log(`\n=== VS Code integration tests passed: ${passed.join(", ") || "none"} ===`);
  if (failed.length > 0) {
    console.error(`=== VS Code integration tests FAILED: ${failed.join(", ")} ===`);
    process.exit(1);
  }
}

void main();
