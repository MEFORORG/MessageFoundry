// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import {
  buildBootstrapPlan,
  buildServeInvocation,
  classifyPreflight,
  preflightArgs,
  runDirHasEngine,
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
