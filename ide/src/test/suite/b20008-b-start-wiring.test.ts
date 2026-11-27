// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The status bar's Start hands `messagefoundry.serviceConfig` to every command it runs (BACKLOG #5566,
// #5939), driven end to end rather than read from the source: the real `startEngine` and copy-start
// command run against a stubbed `vscode` (b20008-b-harness.ts), and each pin compares the WHOLE argv
// of what was launched against the fixtures the engine-parser tests read.
//
// The workspace holds the configured service TOML and nothing else, so the fork guard passes on the
// configured file in both the fixed and the unfixed code: the unfixed code judged that file too, and
// then started serve, the probe and provision-admin without it. Each test below but the last, a
// control, fails on that code (engine 5fdb7bceaa, the parent of PR 2966's merge) on its argv or its
// tooltip, not on a missing symbol.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  NODE_SIDE,
  NO_ADMIN,
  ADMIN_EXISTS,
  changeSetting,
  idle,
  installFakes,
  makeContext,
  mods,
  reset,
  state,
  uninstallFakes,
} from "./b20008-b-harness";

const FIXTURES = path.join(__dirname, "..", "..", "..", "src", "test", "fixtures");
const readFixture = <T>(name: string): T => JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf8")) as T;
const SERVE = readFixture<{ serviceConfig: string; serve: string[]; copyLine: string }>("b20008-b-serve-argv.json");
const ADMIN = readFixture<{ serviceConfig: string; provision: string[]; probe: string[] }>("provision-admin-argv.json");

const startSuite = NODE_SIDE ? suite : suite.skip;

startSuite("the status bar's Start runs every command with the service TOML the guard judged (BACKLOG #5566, #5939)", function () {
  // Above the harness's own 3 s waits, so a wait that runs out fails with its own message.
  this.timeout(10_000);
  let ws: string;
  let ctx: ReturnType<typeof makeContext>;
  let bar: object;

  setup(async () => {
    assert.strictEqual(SERVE.serviceConfig, ADMIN.serviceConfig, "the two fixtures name one file");
    reset();
    ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008-b-"));
    // The configured TOML is the only engine file here: no default messagefoundry.toml, no *.db.
    fs.mkdirSync(path.join(ws, path.dirname(SERVE.serviceConfig)), { recursive: true });
    fs.writeFileSync(path.join(ws, SERVE.serviceConfig), "");
    state.workspace = ws;
    state.settings.set("serviceConfig", SERVE.serviceConfig);
    installFakes();
    ctx = makeContext();
    bar = mods.statusBar.registerEngineStatusBar(ctx.ctx);
    await idle(bar);
  });

  teardown(async () => {
    await idle(bar);
    ctx.dispose();
    uninstallFakes();
    reset();
    fs.rmSync(ws, { recursive: true, force: true });
  });

  /** Run the registered Start command: no Administrator at first, so it provisions, then serves. */
  async function start(): Promise<void> {
    state.probeAnswers = [NO_ADMIN, ADMIN_EXISTS];
    const run = state.commands.get("messagefoundry.startEngine");
    assert.ok(run !== undefined, "the Start command is registered");
    await run();
    assert.ok(
      !state.warnings.some((w) => /no engine store found/i.test(w)),
      "the fork guard found the configured service TOML",
    );
  }

  test("the admin probe runs with the --service-config the guard judged, both times", async () => {
    await start();
    const probes = state.execCalls.filter((c) => c.args.includes("provision-admin"));
    assert.strictEqual(probes.length, 2, JSON.stringify(state.execCalls));
    for (const probe of probes) {
      assert.deepStrictEqual(probe.args, ADMIN.probe);
    }
  });

  test("provision-admin's terminal runs with the --service-config the guard judged", async () => {
    await start();
    const terms = state.terminals.filter((t) => /provision/i.test(t.name));
    assert.strictEqual(terms.length, 1, state.terminals.map((t) => t.name).join(", "));
    const { shellArgs, cwd } = terms[0].creationOptions;
    const m = mods.engineControlModel;
    // The held wrapper, then provision-admin's own argv: the whole list.
    assert.deepStrictEqual(shellArgs, [...m.INTERPRETER_OPTIONS, "-c", m.HOLD_OPEN_SCRIPT, ...ADMIN.provision]);
    assert.strictEqual(cwd, ws);
  });

  test("serve's terminal runs with the --service-config the guard judged", async () => {
    await start();
    const terms = state.terminals.filter((t) => t.name === "MessageFoundry Engine");
    assert.strictEqual(terms.length, 1, state.terminals.map((t) => t.name).join(", "));
    assert.deepStrictEqual(terms[0].creationOptions.shellArgs, SERVE.serve);
    assert.strictEqual(terms[0].creationOptions.cwd, ws);
  });

  test("the copied start command names the --service-config Start passes", async () => {
    const copy = state.commands.get("messagefoundry.engineCopyStartCommand");
    assert.ok(copy !== undefined, "the copy command is registered");
    await copy();
    assert.deepStrictEqual(state.clipboard, [SERVE.copyLine]);
  });

  test("a change to messagefoundry.serviceConfig re-plans the hover's actions", () => {
    const tooltip = (): string => String((state.tooltips[state.tooltips.length - 1] as { value?: string })?.value);
    const before = tooltip();
    assert.ok(before.includes("command:messagefoundry.startEngine"), `Start offered on the configured file: ${before}`);
    // Back to the default file, which this workspace does not hold: no store, so Start is not offered.
    state.settings.delete("serviceConfig");
    changeSetting("serviceConfig");
    const after = tooltip();
    assert.ok(!after.includes("command:messagefoundry.startEngine"), `Start still offered: ${after}`);
    // Control: a repainted hover with its action links, not the busy text, which has no links.
    assert.ok(after.includes("command:messagefoundry."), `no action links: ${after}`);
  });

  test("control: a change to an unrelated setting does not re-plan, so the test above reads the listener", () => {
    const count = state.tooltips.length;
    state.settings.delete("serviceConfig");
    changeSetting("pythonPath");
    assert.strictEqual(state.tooltips.length, count);
  });
});
