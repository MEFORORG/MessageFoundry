// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// How cli.ts launches the Python CLI. cli.ts imports vscode, so these read its source and pin the
// decisions on the node-side leg that runs on every CI job.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { ENGINE_MODULE, TOOLKIT_MODULE, cliArgv } from "../../cliJson";
import { INTERPRETER_OPTIONS } from "../../engineControlModel";

const SRC = path.join(__dirname, "..", "..", "..", "src");

/** A source file with its comments stripped, so a comment cannot satisfy or defeat a scan. */
function code(file: string): string {
  return fs.readFileSync(path.join(SRC, file), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");
}

/** The body of `export function <name>(...)...{ ... }` up to its first closing brace at column 0. */
function body(src: string, name: string): string {
  const m = new RegExp(`export function ${name}\\([^)]*\\)[^{]*\\{([\\s\\S]*?)\\n\\}`).exec(src);
  assert.ok(m, `${name} moved; re-point this scan before trusting it`);
  return m[1];
}

suite("cli.ts launches the CLI with -P ahead of -m (BACKLOG #5409)", () => {
  test("cliArgv puts the interpreter options, -P first among them, before -m", () => {
    const argv = cliArgv(ENGINE_MODULE, ["validate", "--config", "cfg"]);
    const n = INTERPRETER_OPTIONS.length;
    assert.ok(INTERPRETER_OPTIONS.includes("-P"), "the interpreter options lost -P");
    assert.deepStrictEqual(argv.slice(0, n), [...INTERPRETER_OPTIONS]);
    assert.deepStrictEqual(argv.slice(n), ["-m", ENGINE_MODULE, "validate", "--config", "cfg"]);
    assert.ok(argv.indexOf("-P") < argv.indexOf("-m"), "-P after -m is a script argument, not an option");
  });

  test("cliArgv carries the toolkit module the same way", () => {
    const argv = cliArgv(TOOLKIT_MODULE, ["lens", "schema"]);
    assert.deepStrictEqual(argv, [...INTERPRETER_OPTIONS, "-m", TOOLKIT_MODULE, "lens", "schema"]);
  });

  test("run and runWithStdin both build their argv with cliArgv", () => {
    const src = code("cli.ts");
    for (const name of ["run", "runWithStdin"]) {
      const b = body(src, name);
      assert.ok(/execFile\(\s*pythonPath\(\),\s*cliArgv\(module, args\),/.test(b), `${name} does not launch through cliArgv`);
      // The control: the argv the runners carried before the fix.
      assert.ok(!/\[\s*"-m",\s*module/.test(b), `${name} still builds a bare -m argv`);
    }
  });
});

suite("cli.ts exec gate refuses every untrusted window (BACKLOG #5408)", () => {
  // The gate must be trust alone. The defect form also required a workspace folder, so a Restricted
  // Mode window with no folder spawned Python.
  const gatesOnTrustAlone = (b: string): boolean => /^\s*return\s+!vscode\.workspace\.isTrusted;\s*$/.test(b);

  test("isExecGated reads trust alone, with no workspace precondition", () => {
    const b = body(code("cli.ts"), "isExecGated");
    assert.ok(gatesOnTrustAlone(b), `isExecGated is not trust alone: ${b.trim()}`);
    assert.ok(!/workspaceDir|workspaceFolders/.test(b), "isExecGated consults the workspace folder");
  });

  test("control: the pre-fix body fails the predicate", () => {
    assert.ok(!gatesOnTrustAlone("\n  return Boolean(workspaceDir()) && !vscode.workspace.isTrusted;"));
  });
});
