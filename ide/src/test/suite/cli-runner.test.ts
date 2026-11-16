// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// How the IDE launches the Python CLI. cli.ts and aiPolicy.ts import vscode, so these
// read their source and pin the decisions on the node-side leg that runs on every CI job.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { ENGINE_MODULE, TOOLKIT_MODULE } from "../../cliJson";
import { INTERPRETER_OPTIONS, aiPolicyCliArgs, aiPolicyCliPlan, cliArgv } from "../../engineControlModel";
import { containedPathSetting } from "../../workspaceContainment";

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

  // The relative/absolute split is the host platform's, so the absolute case is spelled for it.
  const ABS = process.platform === "win32" ? "C:\\svc\\messagefoundry.toml" : "/svc/messagefoundry.toml";

  test("with no workspace folder a relative service-config path does not run", () => {
    // The CLI would run in the extension host's own cwd and read a stray file there.
    assert.strictEqual(aiPolicyCliPlan("messagefoundry.toml", false, undefined), undefined);
    assert.strictEqual(aiPolicyCliPlan("conf/prod.toml", true, undefined), undefined);
    assert.strictEqual(aiPolicyCliPlan("conf/prod.toml", true, ""), undefined);
    assert.strictEqual(aiPolicyCliPlan(42, true, undefined), undefined);
  });

  test("control: with a folder the same path runs there, and with none an absolute path runs", () => {
    assert.deepStrictEqual(aiPolicyCliPlan("conf/prod.toml", true, "/ws"), {
      args: ["ai-policy", "--service-config=conf/prod.toml"],
      cwd: "/ws",
    });
    assert.deepStrictEqual(aiPolicyCliPlan(ABS, true, undefined), {
      args: ["ai-policy", `--service-config=${ABS}`],
      cwd: undefined,
    });
  });

  const wired = (entry: string): boolean =>
    /aiPolicyCliPlan\(\s*serviceConfig\(\),\s*serviceConfigIsSet\(\),\s*workspaceDir\(\)\s*\)/.test(entry) &&
    /plan === undefined\s*\?\s*Promise\.reject\(/.test(entry) &&
    /runJson<AiPolicyWire>\(\s*plan\.args,\s*plan\.cwd\s*\)/.test(entry);

  test("DEFAULT_AI_POLICY_IO.getCliPolicy runs aiPolicyCliPlan over the setting, and refuses with no plan", () => {
    const block = /DEFAULT_AI_POLICY_IO: AiPolicyIo = \{([\s\S]*?)\n\};/.exec(code("aiPolicy.ts"));
    assert.ok(block, "DEFAULT_AI_POLICY_IO moved; re-point this scan before trusting it");
    const entry = /getCliPolicy:([\s\S]*?)\n {2}\},\s*\n\s*\w+:/.exec(block[1]);
    assert.ok(entry, "expected a getCliPolicy block entry followed by another entry in DEFAULT_AI_POLICY_IO");
    assert.ok(wired(entry[1]), `the fallback is not wired through aiPolicyCliPlan: ${entry[1].trim()}`);
  });

  test("control: the pre-fix entries fail the predicate", () => {
    assert.ok(!wired(' () => runJson<AiPolicyWire>(["ai-policy"], workspaceDir())'));
    assert.ok(
      !wired(" () => runJson<AiPolicyWire>(aiPolicyCliArgs(serviceConfig(), serviceConfigIsSet()), workspaceDir())"),
    );
  });
});

suite("the path settings are contained to the workspace folder (BACKLOG #5404)", () => {
  const WS = path.resolve("ws-root");
  const OUT = path.resolve("elsewhere", "cfg");
  const valueOf = (...a: Parameters<typeof containedPathSetting>): string => containedPathSetting(...a).value;

  test("the answer names its scope and whether a workspace value was dropped", () => {
    assert.deepStrictEqual(containedPathSetting({ workspaceValue: "cfg" }, WS, "d"), {
      value: "cfg",
      source: "workspace",
      dropped: false,
    });
    // A dropped value counts as unset, so serviceConfigIsSet agrees with serviceConfig.
    assert.deepStrictEqual(containedPathSetting({ defaultValue: "x.toml", workspaceValue: OUT }, WS, "d"), {
      value: "x.toml",
      source: "default",
      dropped: true,
    });
    assert.deepStrictEqual(containedPathSetting({ globalValue: "u", workspaceFolderValue: "..", workspaceValue: "in" }, WS, "d"), {
      value: "in",
      source: "workspace",
      dropped: true,
    });
    // A malformed user value passes through as `get` returned it, for the callers' own refusals.
    assert.strictEqual(containedPathSetting({ globalValue: 42 }, WS, "d").source, "user");
  });

  test("a workspace value inside the folder is used", () => {
    assert.strictEqual(valueOf({ defaultValue: "samples/config", workspaceValue: "cfg" }, WS, "d"), "cfg");
    assert.strictEqual(valueOf({ workspaceValue: "." }, WS, "d"), ".");
    const inside = path.join(WS, "cfg");
    assert.strictEqual(valueOf({ workspaceValue: inside }, WS, "d"), inside);
  });

  test("a workspace value that leaves the folder is dropped for the user value, else the default", () => {
    const scopes = { defaultValue: "samples/config", globalValue: "mine", workspaceValue: "../x" };
    assert.strictEqual(valueOf(scopes, WS, "d"), "mine");
    assert.strictEqual(valueOf({ defaultValue: "samples/config", workspaceValue: OUT }, WS, "d"), "samples/config");
    assert.strictEqual(valueOf({ workspaceFolderValue: "..", workspaceValue: "in" }, WS, "d"), "in");
    assert.strictEqual(valueOf({ workspaceValue: 42 }, WS, "d"), "d");
  });

  test("with no folder open a workspace value is dropped", () => {
    assert.strictEqual(valueOf({ defaultValue: "samples/config", workspaceValue: "cfg" }, undefined, "d"), "samples/config");
    assert.strictEqual(valueOf({ workspaceValue: "cfg" }, "", "d"), "d");
  });

  test("a user value is the operator's own and is used as written", () => {
    assert.strictEqual(valueOf({ defaultValue: "samples/config", globalValue: OUT }, WS, "d"), OUT);
    assert.strictEqual(valueOf({ globalValue: "../shared" }, undefined, "d"), "../shared");
  });

  test("no inspect answer gives the fallback", () => {
    assert.strictEqual(valueOf(undefined, WS, "d"), "d");
  });

  const contained = (src: string, name: string): boolean =>
    new RegExp(`^\\s*return pathSetting\\("${name}", "[^"]+"\\)\\.value;\\s*$`).test(body(src, name));

  test("configDir, serviceConfig and messageSetsDir read through pathSetting, which contains them", () => {
    for (const name of ["configDir", "serviceConfig", "messageSetsDir"]) {
      assert.ok(contained(CLI, name), `${name} does not read through pathSetting`);
    }
    assert.ok(/containedPathSetting\(seen, workspaceDir\(\), fallback\)/.test(CLI), "pathSetting no longer contains");
  });

  test("control: the pre-fix reader fails the predicate", () => {
    const pre = 'export function configDir(): string {\n  return config().get<string>("configDir", "samples/config");\n}';
    assert.ok(!contained(pre, "configDir"));
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
