// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// How the IDE launches the Python CLI. cli.ts and aiPolicy.ts import vscode, so these
// read their source and pin the decisions on the node-side leg that runs on every CI job.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { ENGINE_MODULE, TOOLKIT_MODULE } from "../../cliJson";
import { INTERPRETER_OPTIONS, aiPolicyCliArgs, cliArgv } from "../../engineControlModel";

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

suite("the IDE launches the CLI with -P ahead of -m (BACKLOG #5409)", () => {
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

  const launchesThroughCliArgv = (b: string): boolean => /execFile\(\s*pythonPath\(\),\s*cliArgv\(module, args\),/.test(b);

  test("every execFile in cli.ts is run or runWithStdin, and each builds its argv with cliArgv", () => {
    // The floor: a third launch site would not be covered by the two bodies read below.
    assert.strictEqual((CLI.match(/\bexecFile\(/g) ?? []).length, 2, "cli.ts gained or lost an execFile site");
    for (const name of ["run", "runWithStdin"]) {
      assert.ok(launchesThroughCliArgv(body(CLI, name)), `${name} does not launch through cliArgv`);
    }
  });

  test("control: the pre-fix runner argv fails the predicate", () => {
    assert.ok(!launchesThroughCliArgv('execFile(\n      pythonPath(),\n      ["-m", module, ...args],'));
  });
});

suite("the AI-policy CLI fallback names the configured service settings (BACKLOG #5405)", () => {
  test("an unset or blank setting names the file serve reads with no flag", () => {
    const named = ["ai-policy", "--service-config=messagefoundry.toml"];
    assert.deepStrictEqual(aiPolicyCliArgs("messagefoundry.toml", false), named);
    assert.deepStrictEqual(aiPolicyCliArgs("", true), named);
    assert.deepStrictEqual(aiPolicyCliArgs("   ", true), named);
  });

  test("a set setting is named as it is, bound with = so a leading dash stays a value", () => {
    assert.deepStrictEqual(aiPolicyCliArgs("conf/prod.toml", true), ["ai-policy", "--service-config=conf/prod.toml"]);
    assert.deepStrictEqual(aiPolicyCliArgs("-odd.toml", true), ["ai-policy", "--service-config=-odd.toml"]);
  });

  test("a non-string setting is named as an empty path, which the CLI refuses", () => {
    assert.deepStrictEqual(aiPolicyCliArgs(42, true), ["ai-policy", "--service-config="]);
  });

  const wired = (entry: string): boolean =>
    /runJson<AiPolicyWire>\(\s*aiPolicyCliArgs\(serviceConfig\(\),\s*serviceConfigIsSet\(\)\),\s*workspaceDir\(\)\s*\)/.test(entry);

  test("DEFAULT_AI_POLICY_IO.getCliPolicy runs aiPolicyCliArgs over the setting", () => {
    const block = /DEFAULT_AI_POLICY_IO: AiPolicyIo = \{([\s\S]*?)\n\};/.exec(code("aiPolicy.ts"));
    assert.ok(block, "DEFAULT_AI_POLICY_IO moved; re-point this scan before trusting it");
    const entry = /getCliPolicy:([\s\S]*?),\s*\n\s*\w+:/.exec(block[1]);
    assert.ok(entry, "expected a getCliPolicy entry followed by another entry in DEFAULT_AI_POLICY_IO");
    assert.ok(wired(entry[1]), `the fallback does not name the service settings: ${entry[1].trim()}`);
  });

  test("control: the pre-fix entry fails the predicate", () => {
    assert.ok(!wired(' () => runJson<AiPolicyWire>(["ai-policy"], workspaceDir())'));
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
