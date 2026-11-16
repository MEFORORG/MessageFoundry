// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// How the IDE launches the Python CLI. cli.ts and aiPolicy.ts import vscode, so these read their
// source and pin the decisions on the node-side leg that runs on every CI job.
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

const CLI = code("cli.ts");

/** The body of `export function <name>(...)...{ ... }` up to its first closing brace at column 0. */
function body(src: string, name: string): string {
  const m = new RegExp(`export function ${name}\\([^)]*\\)[^{]*\\{([\\s\\S]*?)\\n\\}`).exec(src);
  assert.ok(m, `${name} moved; re-point this scan before trusting it`);
  return m[1];
}

suite("cli.ts launches the CLI with -P ahead of -m (BACKLOG #5409)", () => {
  test("cliArgv puts the interpreter options, -P among them, before -m", () => {
    assert.ok(INTERPRETER_OPTIONS.includes("-P"), "the interpreter options lost -P");
    assert.deepStrictEqual(cliArgv(ENGINE_MODULE, ["validate", "--config", "cfg"]), [
      ...INTERPRETER_OPTIONS,
      "-m",
      ENGINE_MODULE,
      "validate",
      "--config",
      "cfg",
    ]);
    assert.deepStrictEqual(cliArgv(TOOLKIT_MODULE, ["lens", "schema"]), [
      ...INTERPRETER_OPTIONS,
      "-m",
      TOOLKIT_MODULE,
      "lens",
      "schema",
    ]);
  });

  test("run and runWithStdin both build their argv with cliArgv", () => {
    for (const name of ["run", "runWithStdin"]) {
      const b = body(CLI, name);
      assert.ok(/execFile\(\s*pythonPath\(\),\s*cliArgv\(module, args\),/.test(b), `${name} does not launch through cliArgv`);
      // The control: the argv the runners carried before the fix.
      assert.ok(!/\[\s*"-m",\s*module/.test(b), `${name} still builds a bare -m argv`);
    }
  });
});

suite("the AI-policy CLI fallback names the configured service settings (BACKLOG #5405)", () => {
  const namesSettings = (entry: string): boolean =>
    /runJson<AiPolicyWire>\(\s*\[\s*"ai-policy",\s*"--service-config",\s*serviceConfig\(\)\s*\],\s*workspaceDir\(\)\s*\)/.test(entry);

  test("DEFAULT_AI_POLICY_IO.getCliPolicy runs ai-policy with --service-config serviceConfig()", () => {
    const block = /DEFAULT_AI_POLICY_IO: AiPolicyIo = \{([\s\S]*?)\n\};/.exec(code("aiPolicy.ts"));
    assert.ok(block, "DEFAULT_AI_POLICY_IO moved; re-point this scan before trusting it");
    const entry = /getCliPolicy:([\s\S]*?),\s*\n\s*\w+:/.exec(block[1]);
    assert.ok(entry, "expected a getCliPolicy entry followed by another entry in DEFAULT_AI_POLICY_IO");
    assert.ok(namesSettings(entry[1]), `the fallback does not name the service settings: ${entry[1].trim()}`);
  });

  test("control: the pre-fix entry fails the predicate", () => {
    assert.ok(!namesSettings(' () => runJson<AiPolicyWire>(["ai-policy"], workspaceDir())'));
  });
});

suite("cli.ts exec gate refuses every untrusted window (BACKLOG #5408)", () => {
  // The gate must be trust alone. The defect form also required a workspace folder, so a Restricted
  // Mode window with no folder spawned Python.
  const gatesOnTrustAlone = (b: string): boolean => /^\s*return\s+!vscode\.workspace\.isTrusted;\s*$/.test(b);

  test("isExecGated reads trust alone, with no workspace precondition", () => {
    const b = body(CLI, "isExecGated");
    assert.ok(gatesOnTrustAlone(b), `isExecGated is not trust alone: ${b.trim()}`);
  });

  test("control: the pre-fix body fails the predicate", () => {
    assert.ok(!gatesOnTrustAlone("\n  return Boolean(workspaceDir()) && !vscode.workspace.isTrusted;"));
  });
});
