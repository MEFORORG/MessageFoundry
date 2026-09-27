// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  HOLD_OPEN_SCRIPT,
  PROBE_USERNAME,
  buildAdminProbeInvocation,
  buildBootstrapPlan,
  buildHeldInvocation,
  buildProvisionInvocation,
  buildServeInvocation,
  classifyAdminProbe,
  classifyPreflight,
  preflightArgs,
  runDirHasEngine,
  runStartPlan,
  type AdminDetails,
  type AdminProbeResult,
  type StartPlanEffects,
} from "../../engineControlModel";
import {
  CMD,
  planActions,
  resolveEngineStatusTarget,
  type EngineControlContext,
  type EngineLink,
  type LinkState,
} from "../../engineStatusModel";

// The engine LIFECYCLE the pill now drives (ADR 0112, superseding ADR 0110 §5). Two things are asserted
// node-side: the pure invocation/preflight/bootstrap helpers, and — the part that carries the safety
// property — that planActions offers Start/Stop/Restart ONLY under the right control context, and never
// reintroduces a workload field or a non-CMD command while doing so.

const T = resolveEngineStatusTarget("http://127.0.0.1:8765", []);
const NOW = 1_000_000;
const link = (state: LinkState): EngineLink => ({ state, target: T, checkedAt: NOW, verifiedAt: NOW });

suite("engine control — the serve invocation is the ADR-blessed command, RUN not copied", () => {
  test("serve is launched with --config only — no --db/--env/--port override (TOML stays authority)", () => {
    const inv = buildServeInvocation({ python: "C:\\ws\\.venv\\Scripts\\python.exe", configDir: "samples/config" });
    assert.strictEqual(inv.command, "C:\\ws\\.venv\\Scripts\\python.exe");
    assert.deepStrictEqual(inv.args, ["-m", "messagefoundry", "serve", "--config", "samples/config"]);
    // The whole point of ADR 0110 §5's caution: no store/env override that could fork the user's engine.
    assert.ok(!inv.args.includes("--db"), "must not override the store — the service TOML is the authority");
    assert.ok(!inv.args.includes("--env"), "must not override the environment — the service TOML is the authority");
    assert.ok(!inv.args.includes("--port"), "must not override the bind port — the service TOML is the authority");
  });

  test("a config dir with spaces needs no quoting — it is a single argv element", () => {
    const inv = buildServeInvocation({ python: "python", configDir: "my configs/prod" });
    assert.strictEqual(inv.args[inv.args.length - 1], "my configs/prod");
  });

  test("the preflight imports serve's own early module (so a missing pydantic is caught)", () => {
    assert.deepStrictEqual(preflightArgs(), ["-c", "import messagefoundry.config.models"]);
  });
});

suite("engine control — the preflight classifier picks the right remedy", () => {
  test("exit 0 ⇒ ok", () => {
    assert.strictEqual(classifyPreflight({ code: 0, stderr: "" }), "ok");
  });

  test("a missing dependency ⇒ missingDeps (the reported ModuleNotFoundError: pydantic)", () => {
    assert.strictEqual(
      classifyPreflight({ code: 1, stderr: "ModuleNotFoundError: No module named 'pydantic'" }),
      "missingDeps",
    );
  });

  test("messagefoundry itself not installed ⇒ missingDeps", () => {
    assert.strictEqual(
      classifyPreflight({ code: 1, stderr: "ModuleNotFoundError: No module named 'messagefoundry'" }),
      "missingDeps",
    );
  });

  test("the interpreter cannot be spawned ⇒ missingInterpreter", () => {
    assert.strictEqual(
      classifyPreflight({ code: -1, stderr: "", spawnError: "ENOENT" }),
      "missingInterpreter",
    );
  });

  test("any other non-zero exit ⇒ error (surface it, let the user decide)", () => {
    assert.strictEqual(
      classifyPreflight({ code: 1, stderr: "SyntaxError: unexpected EOF" }),
      "error",
    );
  });
});

suite("engine control — the fork guard: is there already an engine store here?", () => {
  test("a service TOML present ⇒ an engine lives here", () => {
    assert.strictEqual(runDirHasEngine({ serviceTomlExists: true, dbFiles: [] }), true);
  });

  test("a *.db present ⇒ an engine lives here", () => {
    assert.strictEqual(runDirHasEngine({ serviceTomlExists: false, dbFiles: ["messagefoundry.db"] }), true);
  });

  test("neither ⇒ NO store here — Start must confirm before creating one", () => {
    assert.strictEqual(runDirHasEngine({ serviceTomlExists: false, dbFiles: [] }), false);
  });
});

suite("engine control — the bootstrap plan installs the right thing per platform", () => {
  test("Windows + a source checkout (pyproject) ⇒ .venv + editable install", () => {
    const plan = buildBootstrapPlan({ hasPyproject: true, platform: "win32" });
    assert.strictEqual(plan.venvPython, ".\\.venv\\Scripts\\python.exe");
    assert.deepStrictEqual(plan.steps, [
      "python -m venv .venv",
      ".\\.venv\\Scripts\\python.exe -m pip install -e .",
    ]);
  });

  test("POSIX + a config repo (no pyproject) ⇒ .venv + published-package install", () => {
    const plan = buildBootstrapPlan({ hasPyproject: false, platform: "linux" });
    assert.strictEqual(plan.venvPython, "./.venv/bin/python");
    assert.deepStrictEqual(plan.steps, [
      "python -m venv .venv",
      "./.venv/bin/python -m pip install messagefoundry",
    ]);
  });
});

suite("engine control — planActions offers lifecycle only under the right context", () => {
  const CONTROL = (over: Partial<EngineControlContext>): EngineControlContext => ({
    canControl: false,
    hasStore: false,
    weStartedIt: false,
    ...over,
  });
  const cmds = (l: EngineLink, ctx?: EngineControlContext): string[] =>
    planActions(l, NOW, ctx).map((a) => a.command);

  test("no context (the 2-arg default) ⇒ NO lifecycle actions — the pre-ADR menu is unchanged", () => {
    const c = cmds(link("unreachable"));
    assert.ok(!c.includes(CMD.startEngine));
    assert.ok(!c.includes(CMD.stopEngine));
    assert.ok(c.includes(CMD.copyStart), "the copy-start fallback survives");
  });

  test("down + we can run it here + a store exists ⇒ Start leads the menu", () => {
    const actions = planActions(link("unreachable"), NOW, CONTROL({ canControl: true, hasStore: true }));
    assert.strictEqual(actions[0].command, CMD.startEngine);
    assert.ok(/start the engine/i.test(actions[0].label));
    // The copy-start fallback is still there for anyone who wants to run it elsewhere.
    assert.ok(actions.map((a) => a.command).includes(CMD.copyStart));
  });

  test("down + can run it here + NO store ⇒ the guided setup page leads, and Start is NOT offered (AC-7)", () => {
    // ADR 0112 amendment (2026-07-16, BACKLOG #238): a store-less workspace is an authoring checkout,
    // so the pill leads with the setup page — the create-DB start moved behind that page's dev-engine
    // button (startEngine's modal confirm remains the fork guard there).
    const actions = planActions(link("unreachable"), NOW, CONTROL({ canControl: true, hasStore: false }));
    assert.strictEqual(actions[0].command, CMD.openEngineSetup);
    assert.ok(/set up/i.test(actions[0].label), "the store-less lead must read as setup, not start");
    assert.ok(
      !actions.map((a) => a.command).includes(CMD.startEngine),
      "the create-DB start must not be offered from the pill when no store exists here",
    );
  });

  test("down but we CANNOT run it (remote / untrusted) ⇒ no Start, only the copy fallback", () => {
    const c = cmds(link("unreachable"), CONTROL({ canControl: false }));
    assert.ok(!c.includes(CMD.startEngine));
    assert.ok(c.includes(CMD.copyStart));
  });

  test("we own a live process ⇒ Stop + Restart lead, whatever the link reads", () => {
    for (const state of ["ok", "unverified", "signedOut", "unreachable"] as LinkState[]) {
      const actions = planActions(link(state), NOW, CONTROL({ weStartedIt: true, canControl: true }));
      assert.strictEqual(actions[0].command, CMD.stopEngine, `${state}: Stop should lead`);
      assert.strictEqual(actions[1].command, CMD.restartEngine, `${state}: Restart should follow`);
      assert.ok(!actions.map((a) => a.command).includes(CMD.startEngine), `${state}: no Start while running`);
    }
  });

  test("engine UP but we did NOT start it ⇒ no Stop offered (never kill an engine we don't own)", () => {
    const c = cmds(link("ok"), CONTROL({ canControl: true, weStartedIt: false }));
    assert.ok(!c.includes(CMD.stopEngine), "we must not offer to stop an engine started elsewhere");
    assert.ok(!c.includes(CMD.startEngine), "it is already up");
  });

  test("no lifecycle action carries data, and every command is a known CMD id", () => {
    const ctxs = [
      CONTROL({ canControl: true, hasStore: true }),
      CONTROL({ canControl: true, hasStore: false }),
      CONTROL({ weStartedIt: true, canControl: true }),
    ];
    const known = Object.values(CMD) as string[];
    for (const state of ["unreachable", "ok", "signedOut"] as LinkState[]) {
      for (const ctx of ctxs) {
        for (const a of planActions(link(state), NOW, ctx)) {
          assert.ok(known.includes(a.command), `${a.command} is not a known engine command`);
          for (const arg of a.args ?? []) {
            assert.strictEqual(typeof arg, "string", "an action argument may only be a path string");
          }
        }
      }
    }
  });
});

// ADR 0183 Amendment A, Wave 5 (BACKLOG #1136, ASVS 6.3.2). The engine creates no account on its own, so
// a `serve` the IDE starts would come up with nobody able to sign in. Start therefore provisions an
// Administrator first, with `provision-admin` in its OWN terminal (the password is typed there, never
// passed), and treats "an enabled Administrator already exists" as go-ahead.

/** What `provision-admin --json` prints for its two answers, copied from `messagefoundry/__main__.py`. */
const ENGINE_ADMIN_EXISTS = JSON.stringify({
  error:
    "this store already has an enabled Administrator, so there is nothing to provision " +
    "-- create further accounts from the web console, and use `admin-unlock` if the " +
    "administrator is locked out",
});
const ENGINE_NO_TERMINAL = JSON.stringify({
  error:
    "refusing to provision without a terminal: the password is read interactively and " +
    "there is deliberately no --password or --password-file (either would put a standing " +
    "Administrator credential in argv or on disk). Run this from a console.",
});
const EXISTS: AdminProbeResult = { code: 1, stdout: ENGINE_ADMIN_EXISTS + "\n", stderr: "" };
const NEEDS: AdminProbeResult = { code: 1, stdout: ENGINE_NO_TERMINAL + "\n", stderr: "" };

suite("engine control — the provision-admin invocations carry no credential (Wave 5)", () => {
  test("provisioning runs provision-admin with the username only — no password, no store override", () => {
    const inv = buildProvisionInvocation({ python: "C:\\ws\\.venv\\Scripts\\python.exe", username: "alice" });
    assert.strictEqual(inv.command, "C:\\ws\\.venv\\Scripts\\python.exe");
    assert.deepStrictEqual(inv.args, ["-m", "messagefoundry", "provision-admin", "--username=alice"]);
    for (const a of inv.args) {
      assert.ok(!/password/i.test(a), `no password may ride in argv (${a})`);
      // The same resolution `serve` uses: same cwd, no store or service-config override.
      assert.ok(!a.startsWith("--db") && !a.startsWith("--service-config"), `no override (${a})`);
    }
  });

  test("a username that starts with a dash stays the value of --username, not a new flag", () => {
    const inv = buildProvisionInvocation({ python: "python", username: "--json" });
    assert.strictEqual(inv.args[inv.args.length - 1], "--username=--json");
    assert.ok(!inv.args.includes("--json"), "the username must not become a flag of its own");
  });

  test("a notification address rides as --email=, and a blank one is left out", () => {
    // The shipped posture refuses to start until some enabled Administrator has an address.
    const withEmail = buildProvisionInvocation({ python: "python", username: "alice", email: " a@b.test " });
    assert.strictEqual(withEmail.args[withEmail.args.length - 1], "--email=a@b.test");
    for (const blank of [undefined, "", "   "]) {
      const inv = buildProvisionInvocation({ python: "python", username: "alice", email: blank });
      assert.ok(!inv.args.some((a) => a.startsWith("--email")), `blank ${JSON.stringify(blank)}`);
    }
  });

  test("the provisioning terminal is held open after the command exits, with the same argv", () => {
    const inner = buildProvisionInvocation({ python: "py", username: "alice" });
    const held = buildHeldInvocation(inner);
    assert.strictEqual(held.command, "py");
    assert.deepStrictEqual(held.args, ["-c", HOLD_OPEN_SCRIPT, ...inner.args]);
    // It re-runs the SAME interpreter with the argv after -c, waits for Enter, and keeps the exit code.
    assert.ok(HOLD_OPEN_SCRIPT.includes("subprocess.call([sys.executable, *sys.argv[1:]])"));
    assert.ok(HOLD_OPEN_SCRIPT.includes("input(") && HOLD_OPEN_SCRIPT.includes("sys.exit(rc)"));
    // One line with no backslash or double quote, so Windows argv quoting cannot mangle it.
    assert.ok(!/[\n\\"]/.test(HOLD_OPEN_SCRIPT));
  });

  test("the probe asks provision-admin with --json and no password", () => {
    const inv = buildAdminProbeInvocation({ python: "python" });
    assert.deepStrictEqual(inv.args, [
      "-m",
      "messagefoundry",
      "provision-admin",
      `--username=${PROBE_USERNAME}`,
      "--json",
    ]);
    assert.ok(inv.args.every((a) => !/password/i.test(a)));
  });
});

suite("engine control — the probe classifier reads provision-admin's two answers (Wave 5)", () => {
  test('"an enabled Administrator already exists" is go-ahead', () => {
    assert.strictEqual(classifyAdminProbe(EXISTS).verdict, "adminExists");
  });

  test("the no-terminal refusal means the store needs an Administrator", () => {
    assert.strictEqual(classifyAdminProbe(NEEDS).verdict, "needsAdmin");
  });

  test("only the --json answer counts: the same words as free text on stderr are a refusal", () => {
    // A log line or a traceback that quotes the words must not read as go-ahead.
    const text = (j: string): AdminProbeResult => ({
      code: 1,
      stdout: "",
      stderr: `error: ${(JSON.parse(j) as { error: string }).error}\n`,
    });
    const exists = classifyAdminProbe(text(ENGINE_ADMIN_EXISTS));
    assert.strictEqual(exists.verdict, "refused");
    assert.ok(exists.detail.includes("already has an enabled Administrator"), "the text is kept as the reason");
    assert.strictEqual(classifyAdminProbe(text(ENGINE_NO_TERMINAL)).verdict, "refused");
  });

  test("the JSON answer is found after other lines on stdout", () => {
    const r = classifyAdminProbe({ code: 1, stdout: `WARNING: something\r\n${ENGINE_ADMIN_EXISTS}\r\n`, stderr: "" });
    assert.strictEqual(r.verdict, "adminExists");
  });

  test("any other refusal is refused, and its reason is kept for the user", () => {
    const keyless = { error: "no store key is set in this shell (MEFOR_STORE_ENCRYPTION_KEY, ...)" };
    const r = classifyAdminProbe({ code: 2, stdout: JSON.stringify(keyless), stderr: "" });
    assert.strictEqual(r.verdict, "refused");
    assert.ok(r.detail.includes("no store key is set"), "the engine's reason must reach the user");
  });

  test("an interpreter that cannot run, or an unexpected success, is never go-ahead", () => {
    assert.strictEqual(
      classifyAdminProbe({ code: -1, stdout: "", stderr: "", spawnError: "ENOENT" }).verdict,
      "refused",
    );
    assert.strictEqual(classifyAdminProbe({ code: 0, stdout: "", stderr: "" }).verdict, "refused");
  });

  test("a success that merely quotes the refusal is not go-ahead", () => {
    // Only a refusal (non-zero exit) can say an Administrator exists.
    assert.strictEqual(classifyAdminProbe({ ...EXISTS, code: 0 }).verdict, "refused");
  });
});

/** Fake effects that record the ORDER the plan calls them in. */
function fakeEffects(opts: {
  probes: AdminProbeResult[];
  choice?: "provision" | "skip";
  afterRefusal?: "provision" | "startAnyway";
  admin?: AdminDetails;
  provisionExit?: number;
}): { fx: StartPlanEffects; calls: string[]; reports: string[] } {
  const calls: string[] = [];
  const reports: string[] = [];
  const probes = [...opts.probes];
  const fx: StartPlanEffects = {
    probeAdmin: () => {
      calls.push("probe");
      const next = probes.shift();
      assert.ok(next, "the plan probed more often than the test expected");
      return Promise.resolve(next);
    },
    chooseToProvision: () => {
      calls.push("choose");
      return Promise.resolve(opts.choice);
    },
    chooseAfterRefusal: (detail: string) => {
      calls.push("afterRefusal");
      reports.push(detail);
      return Promise.resolve(opts.afterRefusal);
    },
    askAdmin: () => {
      calls.push("askAdmin");
      return Promise.resolve(opts.admin);
    },
    provisionInTerminal: (a: AdminDetails) => {
      calls.push(`provision:${a.username}`);
      return Promise.resolve(opts.provisionExit);
    },
    serve: () => {
      calls.push("serve");
    },
    report: (m: string) => {
      reports.push(m);
    },
  };
  return { fx, calls, reports };
}

const ALICE: AdminDetails = { username: "alice", email: "alice@example.test" };
const REFUSED: AdminProbeResult = {
  code: 2,
  stdout: JSON.stringify({ error: "no store key is set in this shell" }),
  stderr: "",
};
const PROVISIONED_THEN_SERVED = ["probe", "choose", "askAdmin", "provision:alice", "probe", "serve"];

suite("engine control — the Start plan provisions before it serves (Wave 5)", () => {
  test("no Administrator: probe, choose, ask, provision in a terminal, check again, THEN serve", async () => {
    const { fx, calls } = fakeEffects({
      probes: [NEEDS, EXISTS],
      choice: "provision",
      admin: ALICE,
      provisionExit: 0,
    });
    assert.strictEqual(await runStartPlan(fx), "served");
    assert.deepStrictEqual(calls, PROVISIONED_THEN_SERVED);
  });

  test('"an enabled Administrator already exists" is go-ahead: it serves with no prompt', async () => {
    const { fx, calls } = fakeEffects({ probes: [EXISTS] });
    assert.strictEqual(await runStartPlan(fx), "served");
    assert.deepStrictEqual(calls, ["probe", "serve"]);
  });

  test("a provision that exits non-zero because an Administrator now exists is still go-ahead", async () => {
    const { fx, calls } = fakeEffects({
      probes: [NEEDS, EXISTS],
      choice: "provision",
      admin: ALICE,
      provisionExit: 1,
    });
    assert.strictEqual(await runStartPlan(fx), "served");
    assert.deepStrictEqual(calls, PROVISIONED_THEN_SERVED);
  });

  test("exit 0 alone is not trusted: if the store still has no Administrator, nothing starts", async () => {
    // On macOS and Linux a Ctrl+C at the password prompt can surface as exit 0.
    const { fx, calls, reports } = fakeEffects({
      probes: [NEEDS, NEEDS],
      choice: "provision",
      admin: ALICE,
      provisionExit: 0,
    });
    assert.strictEqual(await runStartPlan(fx), "notProvisioned");
    assert.ok(!calls.includes("serve"));
    assert.strictEqual(reports.length, 1);
  });

  test("exit 0 with a check that cannot answer still serves, so the terminal's environment cannot strand it", async () => {
    const { fx, calls } = fakeEffects({
      probes: [NEEDS, REFUSED],
      choice: "provision",
      admin: ALICE,
      provisionExit: 0,
    });
    assert.strictEqual(await runStartPlan(fx), "served");
    assert.deepStrictEqual(calls, PROVISIONED_THEN_SERVED);
  });

  test("a failed provision that leaves no Administrator does NOT serve, whatever the check says", async () => {
    for (const second of [NEEDS, REFUSED]) {
      const { fx, calls, reports } = fakeEffects({
        probes: [NEEDS, second],
        choice: "provision",
        admin: ALICE,
        provisionExit: 1,
      });
      assert.strictEqual(await runStartPlan(fx), "notProvisioned");
      assert.ok(!calls.includes("serve"), "serve must not start after a failed provision");
      assert.strictEqual(reports.length, 1);
    }
  });

  test("a provisioning terminal closed by hand (no exit code) is re-checked, not trusted", async () => {
    const { fx, calls } = fakeEffects({ probes: [NEEDS, NEEDS], choice: "provision", admin: ALICE });
    assert.strictEqual(await runStartPlan(fx), "notProvisioned");
    assert.ok(!calls.includes("serve"));
  });

  test("dismissing the choice, or cancelling the details, starts nothing", async () => {
    const dismissed = fakeEffects({ probes: [NEEDS] });
    assert.strictEqual(await runStartPlan(dismissed.fx), "cancelled");
    assert.deepStrictEqual(dismissed.calls, ["probe", "choose"]);

    const cancelled = fakeEffects({ probes: [NEEDS], choice: "provision" });
    assert.strictEqual(await runStartPlan(cancelled.fx), "cancelled");
    assert.deepStrictEqual(cancelled.calls, ["probe", "choose", "askAdmin"]);
  });

  test("starting without an administrator is a deliberate choice, and provisions nothing", async () => {
    // A posture with sign-in off needs none; at the shipped posture serve refuses and names provision-admin.
    const { fx, calls } = fakeEffects({ probes: [NEEDS], choice: "skip" });
    assert.strictEqual(await runStartPlan(fx), "servedWithoutAdmin");
    assert.deepStrictEqual(calls, ["probe", "choose", "serve"]);
  });

  test("a probe the engine refused shows why, and starts nothing unless the user picks a way on", async () => {
    const no = fakeEffects({ probes: [REFUSED] });
    assert.strictEqual(await runStartPlan(no.fx), "refused");
    assert.deepStrictEqual(no.calls, ["probe", "afterRefusal"]);
    assert.ok(no.reports[0].includes("no store key is set"), "the engine's reason reaches the user");

    const anyway = fakeEffects({ probes: [REFUSED], afterRefusal: "startAnyway" });
    assert.strictEqual(await runStartPlan(anyway.fx), "servedDespiteRefusal");
    assert.deepStrictEqual(anyway.calls, ["probe", "afterRefusal", "serve"]);
  });

  test("after a refused probe the user can still provision, and it provisions before it serves", async () => {
    const { fx, calls } = fakeEffects({
      probes: [REFUSED, EXISTS],
      afterRefusal: "provision",
      admin: ALICE,
      provisionExit: 0,
    });
    assert.strictEqual(await runStartPlan(fx), "served");
    assert.deepStrictEqual(calls, ["probe", "afterRefusal", "askAdmin", "provision:alice", "probe", "serve"]);
  });
});

// The pure tests above cannot reach the terminal wiring in statusBar.ts, which needs `vscode`. So its
// shape is checked from the source: the serve terminal is reachable only through the Start plan, and the
// provisioning terminal is its own process that the plan waits on.
suite("engine control — statusBar.ts serves only through the Start plan (Wave 5b)", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "statusBar.ts"), "utf8");
  const code = src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");

  test("the serve terminal is created in exactly one place, and only the plan's serve effect calls it", () => {
    assert.strictEqual(
      (code.match(/buildServeInvocation\(/g) ?? []).length,
      1,
      "serve must be built in one place",
    );
    assert.strictEqual(
      (code.match(/this\.serveEngine\(/g) ?? []).length,
      1,
      "serveEngine must have exactly one caller",
    );
    assert.ok(
      /runStartPlan\(\{[\s\S]*?serve:\s*\(\)\s*=>\s*this\.serveEngine\(/.test(code),
      "that one caller must be the Start plan's serve effect",
    );
  });

  test("provisioning gets its own terminal, running provision-admin, awaited until it closes", () => {
    assert.ok(
      /buildHeldInvocation\(buildProvisionInvocation\(/.test(code),
      "the provisioning terminal must run the model's argv, held open after it exits",
    );
    assert.ok(/provisionInTerminal:/.test(code), "the plan's provision effect must be wired");
    assert.ok(/awaitExit\(/.test(code), "the plan must wait for the provisioning terminal to exit");
  });

  test("no password is ever put on a command line", () => {
    assert.ok(!/--password/.test(code), "statusBar.ts must not pass a password flag");
  });
});
