import * as assert from "assert";

import {
  WIZARD_TRANSPORTS,
  buildConnObj,
  coerceSetting,
  connectionUpsertArgs,
  settingKeysFor,
  shouldSaveConnection,
  validateName,
  validatePort,
  validateRequired,
  type WizardState,
} from "../../connectionWizardModel";

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

suite("connectionWizardModel — upsert argv", () => {
  test("matches the form's `connection upsert --config <dir> --data <json>` (runJson appends --json)", () => {
    const conn = buildConnObj({ direction: "inbound", transport: "mllp", name: "IB_X", port: "1", router: "r" });
    const args = connectionUpsertArgs("samples/config", conn);
    assert.deepStrictEqual(args, [
      "connection",
      "upsert",
      "--config",
      "samples/config",
      "--data",
      JSON.stringify(conn),
    ]);
    assert.ok(!args.includes("--json"));
  });
});
