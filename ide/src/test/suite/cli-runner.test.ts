// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// How the IDE launches the Python CLI. cli.ts and aiPolicy.ts import vscode, so these
// read their source and pin the decisions on the node-side leg that runs on every CI job.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { ENGINE_MODULE, TOOLKIT_MODULE } from "../../cliJson";
import { INTERPRETER_OPTIONS, aiPolicyCliArgs, aiPolicyCliPlan, cliArgv } from "../../engineControlModel";
import { committedRelativePath, containedPathSetting, droppedNotice, writerRefusal } from "../../workspaceContainment";

const SRC = path.join(__dirname, "..", "..", "..", "src");

/** `src` with its comments stripped, so a comment cannot satisfy or defeat a scan. String and
 *  template literals are matched first and kept, so a `/*` or `//` inside one (a glob, a URL) does
 *  not start a comment. A template's `${...}` holding a backtick is not modelled. */
function stripComments(src: string): string {
  return src.replace(
    /("(?:\\[\s\S]|[^"\\\n])*"|'(?:\\[\s\S]|[^'\\\n])*'|`(?:\\[\s\S]|[^`\\])*`)|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,
    (m, literal: string | undefined) => literal ?? "",
  );
}

/** A source file with its comments stripped; see {@link stripComments}. */
function code(file: string): string {
  return stripComments(fs.readFileSync(path.join(SRC, file), "utf8"));
}

test("control: the comment stripper keeps a `/*` inside a string and drops real comments", () => {
  const src = 'const G = "{**/*.py}"; // gone\nconst after = 1; /* gone too */ const u = "http://x";';
  const out = stripComments(src);
  assert.ok(out.includes("const after = 1;"), out);
  assert.ok(out.includes('"http://x"'), out);
  assert.ok(!out.includes("gone"), out);
});

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
    if (process.platform === "win32") {
      // Absolute but root-relative: it still takes the extension host's current drive.
      assert.strictEqual(aiPolicyCliPlan("\\svc\\messagefoundry.toml", true, undefined), undefined);
    }
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

  // A dropped value gives no plan (BACKLOG #5404), so the fallback fails closed to unverified.
  const wired = (entry: string): boolean =>
    /const s = writerCheckSetting\("serviceConfig"\);/.test(entry) &&
    /s\.dropped === false\s*\?\s*aiPolicyCliPlan\(\s*s\.value,\s*s\.source !== "default",\s*workspaceDir\(\)\s*\)\s*:\s*undefined/.test(entry) &&
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
    // The round-1 entry, which ran the CLI on the file used in place of a dropped value.
    assert.ok(
      !wired(
        " () => { const plan = aiPolicyCliPlan(serviceConfig(), serviceConfigIsSet(), workspaceDir()); " +
          "return plan === undefined ? Promise.reject(new Error()) : runJson<AiPolicyWire>(plan.args, plan.cwd); }",
      ),
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
    // Dropped is reported, so serviceConfigIsSet can name the file used in its place.
    assert.deepStrictEqual(containedPathSetting({ defaultValue: "x.toml", workspaceValue: OUT }, WS, "d"), {
      value: "x.toml",
      source: "default",
      dropped: "workspace",
    });
    assert.deepStrictEqual(containedPathSetting({ globalValue: "u", workspaceValue: "../in" }, WS, "d"), {
      value: "u",
      source: "user",
      dropped: "workspace",
    });
  });

  test("a user value that is not text is dropped for the default, so node:path never sees it", () => {
    for (const bad of [42, null, { a: 1 }, ["cfg"], true]) {
      const s = containedPathSetting({ defaultValue: "x.toml", globalValue: bad }, WS, "d");
      assert.deepStrictEqual(s, { value: "x.toml", source: "default", dropped: "user" }, JSON.stringify(bad));
      // The value every reader hands node:path is text, so these cannot throw.
      assert.doesNotThrow(() => path.isAbsolute(s.value));
    }
    // With a workspace value dropped too, the workspace drop is the one named.
    assert.strictEqual(containedPathSetting({ globalValue: 42, workspaceValue: OUT }, WS, "d").dropped, "workspace");
    // Control: before the fix, path.isAbsolute throws on the value as `get` returned it.
    assert.throws(() => path.isAbsolute(42 as unknown as string), TypeError);
  });

  test("a drop a writer refuses is reported as dropped, and both notices name the setting and scope", () => {
    // writerSetting in cli.ts refuses exactly when `dropped` is not false.
    assert.strictEqual(containedPathSetting({ globalValue: "mine", workspaceValue: OUT }, WS, "d").dropped, "workspace");
    assert.strictEqual(containedPathSetting({ defaultValue: "x", globalValue: 42 }, WS, "d").dropped, "user");
    assert.strictEqual(containedPathSetting({ workspaceValue: "cfg" }, undefined, "d").dropped, "workspace");
    // Controls: nothing dropped, so the writer acts on the value a reader sees.
    assert.strictEqual(containedPathSetting({ globalValue: OUT }, WS, "d").dropped, false);
    assert.strictEqual(containedPathSetting({ workspaceValue: "cfg" }, WS, "d").dropped, false);
    assert.strictEqual(containedPathSetting({ defaultValue: "x" }, WS, "d").dropped, false);
    assert.match(writerRefusal("configDir", "workspace"), /messagefoundry\.configDir, set in workspace settings, is not a path inside/);
    assert.match(writerRefusal("serviceConfig", "user"), /messagefoundry\.serviceConfig, set in user settings, is not text/);
    assert.match(droppedNotice("configDir", "workspace"), /^messagefoundry\.configDir, set in workspace settings, is not a path inside .*so it is not used\./);
    assert.match(droppedNotice("serviceConfig", "user"), /set in user settings, is not text, so it is not used\. /);
    // The notice says what each command does with the value: readers, the paths that still read the
    // substitute among them, go on with it; writers and Start and Restart refuse, for either scope.
    for (const scope of ["workspace", "user"] as const) {
      const notice = droppedNotice("configDir", scope);
      assert.match(notice, /Test Bench Run and Debug, Live Debug and validate-on-save, go on with the value used in its place\./);
      assert.match(notice, /Commands that write, and Start and Restart, refuse until it is/);
    }
    assert.match(droppedNotice("configDir", "user"), /refuse until it is corrected\.$/);
    assert.match(droppedNotice("configDir", "workspace"), /refuse until it is removed; a path elsewhere goes in user settings\.$/);
    const writer = body(CLI, "writerPathSetting");
    assert.match(writer, /^\s*return writerSetting\(key\)\?\.value;\s*$/);
    assert.match(CLI, /function writerSetting\([^)]*\)[^{]*\{\s*const s = writerCheckSetting\(key\);\s*if \(s\.dropped !== false\) \{/);
    assert.match(body(CLI, "writerCheckSetting"), /^\s*return pathSetting\(key, PATH_FALLBACK\[key\], false\);\s*$/);
  });

  test("a committed hook path is workspace-relative with forward slashes, or refused", () => {
    assert.strictEqual(committedRelativePath(WS, "samples/config"), "samples/config");
    assert.strictEqual(committedRelativePath(WS, path.join(WS, "samples", "config")), "samples/config");
    assert.strictEqual(committedRelativePath(WS, "."), ".");
    assert.strictEqual(committedRelativePath(WS, OUT), undefined);
    assert.strictEqual(committedRelativePath(WS, "../shared"), undefined);
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
    new RegExp(`^\\s*return ${name}Setting\\(\\)\\.value;\\s*$`).test(body(src, name));

  test("configDir, serviceConfig and messageSetsDir read through pathSetting, which contains them", () => {
    assert.match(body(CLI, "messageSetsDir"), /^\s*return messageSetsDirSetting\(\)\.value;\s*$/);
    assert.match(body(CLI, "messageSetsDirSetting"), /^\s*return pathSetting\("messageSetsDir", PATH_FALLBACK\.messageSetsDir\);\s*$/);
    assert.match(body(CLI, "configDir"), /^\s*return configDirSetting\(\)\.value;\s*$/);
    assert.match(body(CLI, "configDirSetting"), /^\s*return pathSetting\("configDir", PATH_FALLBACK\.configDir\);\s*$/);
    assert.match(body(CLI, "serviceConfig"), /^\s*return serviceConfigSetting\(\)\.value;\s*$/);
    assert.match(body(CLI, "serviceConfigSetting"), /^\s*return pathSetting\("serviceConfig", PATH_FALLBACK\.serviceConfig\);\s*$/);
    // The fallbacks agree with the manifest defaults.
    assert.match(CLI, /configDir: "samples\/config",\s*serviceConfig: "messagefoundry\.toml",\s*messageSetsDir: "samples\/messages",/);
    assert.ok(/containedPathSetting\(seen, workspaceDir\(\), fallback\)/.test(CLI), "pathSetting no longer contains");
  });

  test("serviceConfigIsSet reads the contained setting and counts a dropped value as set", () => {
    // Counted unset, a dropped value would leave connection edits checked against no file.
    const b = body(CLI, "serviceConfigIsSet");
    assert.match(b, /serviceConfigSetting\(\)/);
    assert.match(b, /source !== "default" \|\| s\.dropped/);
    assert.doesNotMatch(b, /settingIsSet\(/, "serviceConfigIsSet reads the raw scopes again");
  });

  test("control: the pre-fix reader fails the predicate", () => {
    const pre = 'export function configDir(): string {\n  return config().get<string>("configDir", "samples/config");\n}';
    assert.ok(!contained(pre, "configDir"));
  });

  // A writer that read the substitute would act on a file or folder nobody chose (BACKLOG #5404).
  const READER_IN_WRITE = [
    /"codeset", "(?:upsert|rename|remove)", "--config", configDir\(\)/,
    /"alert", "(?:add|remove)", (?:"--service-config", serviceConfig\(\)|`--service-config=\$\{serviceConfig\(\)\}`)/,
    /connection(?:Upsert|Remove)Args\(configDir\(\)/,
    /connectionServiceConfig\(serviceConfig\(\), serviceConfigIsSet\(\)\)/,
  ];
  const offenders = (src: string): RegExp[] => READER_IN_WRITE.filter((re) => re.test(src));

  test("no writer hands the CLI a path setting read by a reader accessor", () => {
    const files = fs.readdirSync(SRC).filter((f) => f.endsWith(".ts"));
    for (const f of files) {
      assert.deepStrictEqual(offenders(code(f)).map(String), [], `${f} writes with a reader accessor`);
    }
  });

  test("control: the pre-fix writer argvs fail the scan", () => {
    assert.strictEqual(offenders('["codeset", "remove", "--config", configDir(), "--name", n]').length, 1);
    assert.strictEqual(offenders('["alert", "add", "--service-config", serviceConfig(), "--data", d]').length, 1);
    assert.strictEqual(offenders('["alert", "add", `--service-config=${serviceConfig()}`, `--data=${d}`]').length, 1);
    assert.strictEqual(
      offenders("connectionUpsertArgs(configDir(), connectionServiceConfig(serviceConfig(), serviceConfigIsSet()), c)").length,
      2,
    );
  });

  test("the writers read through writerPathSetting", () => {
    for (const [file, key] of [
      ["alertEditor.ts", "serviceConfig"],
      ["codeSetEditor.ts", "configDir"],
      ["configEditors.ts", "configDir"],
      ["extension.ts", "configDir"],
      ["generate.ts", "messageSetsDir"],
      ["promote.ts", "configDir"],
      ["newRoute.ts", "configDir"],
      ["sourceControl.ts", "configDir"],
      ["sourceControl.ts", "messageSetsDir"],
    ] as const) {
      assert.ok(code(file).includes(`writerPathSetting("${key}")`), `${file} no longer reads ${key} as a writer`);
    }
    for (const file of ["configEditors.ts", "connectionEditor.ts", "connectionQuickInput.ts", "statusBar.ts"]) {
      assert.ok(code(file).includes("writerConfigTarget()"), `${file} no longer reads its target as a writer`);
    }
    const t = body(CLI, "writerConfigTarget");
    assert.match(t, /writerPathSetting\("configDir"\)/);
    assert.match(t, /writerSetting\("serviceConfig"\)/);
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
