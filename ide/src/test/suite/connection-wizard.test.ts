// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  WIZARD_TRANSPORTS,
  buildConnObj,
  coerceSetting,
  connectionRemoveArgs,
  connectionServiceConfig,
  connectionUpsertArgs,
  planWizardSave,
  settingKeysFor,
  shouldSaveConnection,
  validateName,
  validatePort,
  validateRequired,
  type WizardState,
} from "../../connectionWizardModel";
import type { ConnObj } from "../../connectionMerge";

// Pure new-connection wizard model (#221e) — the answer→ConnObj mapping, per-step validators, and the
// upsert argv, exercised vscode-free (the QuickInput orchestration itself is Extension-Host-only).
suite("connectionWizardModel — validators", () => {
  test("name required + connection-name alphabet", () => {
    assert.ok(validateName("") !== undefined);
    assert.ok(validateName("   ") !== undefined);
    assert.ok(validateName("1BAD") !== undefined); // must start with a letter
    assert.ok(validateName("IB ACME") !== undefined); // no spaces
    assert.strictEqual(validateName("IB_ACME_ADT"), undefined);
  });

  test("port must be an integer in 1–65535", () => {
    assert.ok(validatePort("") !== undefined);
    assert.ok(validatePort("abc") !== undefined);
    assert.ok(validatePort("0") !== undefined);
    assert.ok(validatePort("70000") !== undefined);
    assert.strictEqual(validatePort("2575"), undefined);
  });

  test("required free-text rejects blank, names the field", () => {
    assert.ok((validateRequired("", "Host") ?? "").includes("Host"));
    assert.strictEqual(validateRequired("localhost", "Host"), undefined);
  });
});

suite("connectionWizardModel — offered transports (F4)", () => {
  test("the wizard offers ONLY the transports it can fully configure via QuickInput", () => {
    // The keyboard-first wizard must not list a transport it would leave unconfigured; every offered
    // transport therefore has host/port/directory hints in at least one direction.
    assert.deepStrictEqual(WIZARD_TRANSPORTS, ["mllp", "tcp", "file"]);
    for (const t of WIZARD_TRANSPORTS) {
      const hinted =
        settingKeysFor(t, "inbound").length > 0 || settingKeysFor(t, "outbound").length > 0;
      assert.ok(hinted, `${t} should have at least one hinted setting key`);
    }
  });
});

suite("connectionWizardModel — completion gate (F1)", () => {
  test("all required fields set but NOT completed → no save (a late-step cancel)", () => {
    // direction/transport/name are all populated by step 3, so a cancel on a later settings/router
    // step leaves them set. The gate must NOT infer completion from that — only the explicit flag.
    const state: WizardState = {
      direction: "inbound",
      transport: "mllp",
      name: "IB_ACME_ADT",
      port: "2575",
    };
    assert.strictEqual(shouldSaveConnection(state), false);
    assert.strictEqual(shouldSaveConnection({ ...state, completed: false }), false);
  });

  test("the explicit completion flag is what authorizes the save", () => {
    const state: WizardState = {
      direction: "inbound",
      transport: "mllp",
      name: "IB_ACME_ADT",
      port: "2575",
      completed: true,
    };
    assert.strictEqual(shouldSaveConnection(state), true);
  });

  test("an empty/dismissed-at-step-1 state does not save", () => {
    assert.strictEqual(shouldSaveConnection({}), false);
  });
});

suite("connectionWizardModel — setting keys + coercion", () => {
  test("per-transport/direction keys match the webview form's hints", () => {
    assert.deepStrictEqual(settingKeysFor("mllp", "inbound"), ["port"]);
    assert.deepStrictEqual(settingKeysFor("mllp", "outbound"), ["host", "port"]);
    assert.deepStrictEqual(settingKeysFor("file", "inbound"), ["directory"]);
    assert.deepStrictEqual(settingKeysFor("rest", "outbound"), []);
  });

  test("coerceSetting mirrors the form's booleans/ints/floats/strings", () => {
    assert.strictEqual(coerceSetting("true"), true);
    assert.strictEqual(coerceSetting("false"), false);
    assert.strictEqual(coerceSetting("2575"), 2575);
    assert.strictEqual(coerceSetting("1.5"), 1.5);
    assert.strictEqual(coerceSetting("acme"), "acme");
  });
});

suite("connectionWizardModel — buildConnObj", () => {
  test("inbound MLLP → port setting + router, no host", () => {
    const state: WizardState = {
      direction: "inbound",
      transport: "mllp",
      name: "IB_ACME_ADT",
      port: "2575",
      router: "acme_adt_router",
    };
    assert.deepStrictEqual(buildConnObj(state), {
      direction: "inbound",
      name: "IB_ACME_ADT",
      transport: "mllp",
      settings: { port: 2575 },
      router: "acme_adt_router",
    });
  });

  test("outbound MLLP → host + port, no router", () => {
    const state: WizardState = {
      direction: "outbound",
      transport: "mllp",
      name: "OB_ACME_ADT",
      host: "acme.example",
      port: "6000",
      router: "ignored_for_outbound",
    };
    assert.deepStrictEqual(buildConnObj(state), {
      direction: "outbound",
      name: "OB_ACME_ADT",
      transport: "mllp",
      settings: { host: "acme.example", port: 6000 },
    });
  });

  test("file inbound → directory setting", () => {
    const conn = buildConnObj({
      direction: "inbound",
      transport: "file",
      name: "IB_FILE",
      directory: "./in/adt",
      router: "r",
    });
    assert.deepStrictEqual(conn.settings, { directory: "./in/adt" });
  });

  test("transports without hinted keys carry no settings", () => {
    const conn = buildConnObj({ direction: "outbound", transport: "rest", name: "OB_REST" });
    assert.strictEqual(conn.settings, undefined);
    assert.strictEqual(conn.router, undefined);
  });

  test("blank optional settings are dropped, name is trimmed", () => {
    const conn = buildConnObj({
      direction: "inbound",
      transport: "mllp",
      name: "  IB_X  ",
      port: "  ",
      router: "  ",
    });
    assert.strictEqual(conn.name, "IB_X");
    assert.strictEqual(conn.settings, undefined);
    assert.strictEqual(conn.router, undefined);
  });
});

suite("connectionWizardModel — create-semantics collision gate (#240 c)", () => {
  // The keyboard wizard is always a CREATE, and `connection upsert` is a full REPLACE — so finishing
  // the wizard on an EXISTING connection name must REFUSE (not silently overwrite), exactly as the
  // webview form does. planWizardSave reuses connectionMerge.planSave under create semantics; it is the
  // node-testable seam behind saveConnection's pre-upsert gate (the QuickInput orchestration itself is
  // Extension-Host-only).
  function entries(): ConnObj[] {
    return [
      { direction: "inbound", name: "IB_ACME_ADT", transport: "mllp", settings: { port: 2575 }, router: "adt_router" },
      { direction: "outbound", name: "OB_ACME_ADT", transport: "mllp", settings: { host: "acme.example", port: 2575 } },
    ];
  }

  test("finishing the wizard on an existing name REFUSES (collision set, no upsert)", () => {
    const conn = buildConnObj({
      direction: "inbound",
      transport: "mllp",
      name: "IB_ACME_ADT", // collides with an existing connection
      port: "2600",
      router: "adt_router",
    });
    const plan = planWizardSave(entries(), conn);
    assert.strictEqual(plan.collision, "IB_ACME_ADT");
  });

  test("a fresh name PROCEEDS (no collision, the posted object stands)", () => {
    const conn = buildConnObj({
      direction: "inbound",
      transport: "mllp",
      name: "IB_NEW_ADT",
      port: "2600",
      router: "adt_router",
    });
    const plan = planWizardSave(entries(), conn);
    assert.strictEqual(plan.collision, undefined);
    assert.deepStrictEqual(plan.conn, conn);
  });

  test("an empty graph never collides", () => {
    const conn = buildConnObj({ direction: "inbound", transport: "mllp", name: "IB_FIRST", port: "1" });
    assert.strictEqual(planWizardSave([], conn).collision, undefined);
  });
});

// BACKLOG #2908: a connection upsert or remove names the settings file `messagefoundry.serviceConfig`
// points at, because the CLI checks the edit against that file's [egress] allowlist (deny by
// default). Without the flag the CLI reads ./messagefoundry.toml only if one sits in the working
// directory, so a workspace whose setting names another file would have its edit checked against the
// wrong settings, or none. connectionServiceConfig decides when the flag is left off.
suite("connectionWizardModel — upsert argv", () => {
  test("matches `connection upsert --config <dir> --service-config <toml> --data <json>` (runJson appends --json)", () => {
    const conn = buildConnObj({ direction: "inbound", transport: "mllp", name: "IB_X", port: "1", router: "r" });
    const args = connectionUpsertArgs("samples/config", "env/prod.toml", conn);
    assert.deepStrictEqual(args, [
      "connection",
      "upsert",
      "--config",
      "samples/config",
      "--service-config",
      "env/prod.toml",
      "--data",
      JSON.stringify(conn),
    ]);
    assert.ok(!args.includes("--json"));
  });

  test("leaves --service-config off when no file is to be named", () => {
    const conn = buildConnObj({ direction: "inbound", transport: "mllp", name: "IB_X", port: "1", router: "r" });
    assert.deepStrictEqual(connectionUpsertArgs("samples/config", undefined, conn), [
      "connection",
      "upsert",
      "--config",
      "samples/config",
      "--data",
      JSON.stringify(conn),
    ]);
  });
});

suite("connectionServiceConfig — which settings file a connection edit names", () => {
  const WS = path.resolve("ws-root");
  const FALLBACK = path.join(WS, "messagefoundry.toml");
  const PROD = path.join(WS, "env", "prod.toml");
  // An existence probe that reports only the listed absolute paths as present.
  const present =
    (...paths: string[]) =>
    (p: string): boolean =>
      paths.includes(p);

  test("the setting is passed when the file it names exists", () => {
    assert.strictEqual(connectionServiceConfig(WS, "messagefoundry.toml", present(FALLBACK)), "messagefoundry.toml");
    assert.strictEqual(connectionServiceConfig(WS, "env/prod.toml", present(PROD)), "env/prod.toml");
  });

  test("the flag is left off when no settings file exists at all (the CLI then reads none either)", () => {
    assert.strictEqual(connectionServiceConfig(WS, "messagefoundry.toml", present()), undefined);
    assert.strictEqual(connectionServiceConfig(WS, "env/prod.toml", present()), undefined);
    // An absolute or differently-spelt name for the default file needs no path comparison.
    assert.strictEqual(connectionServiceConfig(WS, FALLBACK.toUpperCase(), present()), undefined);
  });

  test("a missing named file is still passed when the CLI would fall back to another file", () => {
    // Leaving the flag off here would check the edit against ./messagefoundry.toml, a file the
    // setting does not name; passing it makes the CLI say the named file is missing.
    assert.strictEqual(connectionServiceConfig(WS, "env/prod.toml", present(FALLBACK)), "env/prod.toml");
  });

  test("the existence probes are asked about workspace-resolved paths", () => {
    const asked: string[] = [];
    connectionServiceConfig(WS, "env/prod.toml", (p) => {
      asked.push(p);
      return false;
    });
    assert.deepStrictEqual(asked, [PROD, FALLBACK]);
  });

  test("a blank setting names no file", () => {
    assert.strictEqual(connectionServiceConfig(WS, "", present(FALLBACK)), undefined);
    assert.strictEqual(connectionServiceConfig(WS, "   ", present(FALLBACK)), undefined);
  });

  test("a non-string setting from a hand-edited settings.json names no file and does not throw", () => {
    for (const bad of [null, undefined, 123]) {
      assert.strictEqual(connectionServiceConfig(WS, bad as unknown as string, present(FALLBACK)), undefined);
    }
  });
});

// The builders above pin the argv, but only if every writer uses them. Read the extension source and
// pin that (1) no file but the model spells a `connection upsert|remove` argv by hand, and (2) every
// call to a builder passes `serviceConfig()`, the workspace setting the alert, security and trust
// editors pass, through connectionServiceConfig. A source scan, because the callers import `vscode`
// and cannot run under plain mocha.
suite("connection writers — every upsert and remove names the service settings (BACKLOG #2908)", () => {
  const SRC = path.join(__dirname, "..", "..", "..", "src");
  // Every extension source file, subdirectories included, but not the test tree.
  const sources = (fs.readdirSync(SRC, { recursive: true }) as string[])
    .map((f) => f.split(path.sep).join("/"))
    .filter((f) => f.endsWith(".ts") && !f.startsWith("test/"))
    .map((f) => ({ file: f, text: fs.readFileSync(path.join(SRC, f), "utf8") }));

  test("only connectionWizardModel.ts spells the argv", () => {
    const literal = /["'`]connection["'`]\s*,\s*["'`](upsert|remove)["'`]/;
    const spellers = sources.filter((s) => literal.test(s.text)).map((s) => s.file);
    assert.deepStrictEqual(spellers, ["connectionWizardModel.ts"]);
  });

  test("every builder call passes serviceConfig() through connectionServiceConfig", () => {
    // Each call's opening text, long enough to hold its first two arguments over any line breaks.
    const call = /connection(?:Upsert|Remove)Args\(/g;
    const calls = sources
      .filter((s) => s.file !== "connectionWizardModel.ts")
      .flatMap((s) =>
        [...s.text.matchAll(call)].map((m) => ({ file: s.file, call: s.text.slice(m.index, m.index + 200) })),
      );
    // Positive control: the form, the custom editor and the wizard upsert; the form and the custom
    // editor remove. A scan that matched none would pass the check below vacuously.
    const callers = new Set(calls.map((c) => c.file));
    for (const f of ["connectionEditor.ts", "configEditors.ts", "connectionQuickInput.ts"]) {
      assert.ok(callers.has(f), `${f} no longer calls a connection argv builder`);
    }
    const flagged = /^connection(?:Upsert|Remove)Args\([^,]+,\s*connectionServiceConfig\(\s*\w+\s*,\s*serviceConfig\(\)\s*\)/;
    const unflagged = calls.filter((c) => !flagged.test(c.call));
    assert.deepStrictEqual(unflagged, []);
  });
});

suite("connectionWizardModel — remove argv", () => {
  test("matches `connection remove --config <dir> --service-config <toml> --name <name>` (runJson appends --json)", () => {
    const args = connectionRemoveArgs("samples/config", "env/prod.toml", "OB_ACME_ADT");
    assert.deepStrictEqual(args, [
      "connection",
      "remove",
      "--config",
      "samples/config",
      "--service-config",
      "env/prod.toml",
      "--name",
      "OB_ACME_ADT",
    ]);
    assert.ok(!args.includes("--json"));
  });
});
