import * as assert from "assert";

import {
  ENGINE_PREDATES_SCHEMA,
  SUPPORTED_SCHEMA_VERSION,
  acceptsEnv,
  isSecret,
  isEnginePredatesSchema,
  loadConnectionSchema,
  parseConnectionSchema,
  paramsForDirection,
  resetConnectionSchemaCache,
  translateSchemaFailure,
  type ConnectionSchema,
  type ParamSchema,
  type TransportSchema,
} from "../../connectionSchemaModel";

// The pure half of the engine-derived connection catalogue (ADR 0007). Imported WITHOUT the CLI
// wrapper (connectionSchema.ts → cli.ts → vscode) so these run under plain-node mocha and never
// shell out to Python: the fetcher is injected.

/** One param, defaulted to the neutral flags the engine emits, overridden per case. */
function param(overrides: Partial<ParamSchema> = {}): ParamSchema {
  return {
    type: "str",
    choices: null,
    default: null,
    required: false,
    requiredHint: false,
    env: false,
    secret: false,
    direction: null,
    help: "",
    ...overrides,
  };
}

/** An MLLP-shaped transport, trimmed to the params that make the direction rules bite: `host` is
 *  outbound-only (the engine REJECTS it on an inbound), the TLS server cert is inbound-only, and
 *  `port`/`tls_key_password` apply to both. Section headings sit on the first param of a group. */
function mllp(): TransportSchema {
  return {
    doc: "An MLLP endpoint.",
    params: {
      host: param({ direction: "outbound", requiredHint: true, env: true, help: "the peer" }),
      port: param({ type: "int", required: true, env: true }),
      encoding: param({ default: "utf-8" }),
      timeout_seconds: param({ type: "float", default: 30, direction: "outbound" }),
      tls: param({ type: "bool", default: false, section: "TLS" }),
      tls_cert_file: param({ direction: "inbound", requiredHint: true }),
      tls_key_password: param({ env: true, secret: true }),
    },
  };
}

function schemaBody(overrides: Partial<ConnectionSchema> = {}): Record<string, unknown> {
  return {
    schemaVersion: SUPPORTED_SCHEMA_VERSION,
    transports: { mllp: mllp() },
    directionKeys: {
      inbound: ["name", "transport", "settings", "router"],
      outbound: ["name", "transport", "settings", "retry"],
    },
    ...overrides,
  };
}

suite("connectionSchema — version guard (the extension refuses a shape it cannot round-trip)", () => {
  test("accepts the supported version and returns the body typed", () => {
    const parsed = parseConnectionSchema(schemaBody());
    assert.strictEqual(parsed.schemaVersion, 1);
    assert.deepStrictEqual(Object.keys(parsed.transports), ["mllp"]);
    assert.ok(parsed.directionKeys.inbound.includes("router"));
  });

  test("rejects a NEWER schema and tells the user to update the extension", () => {
    assert.throws(
      () => parseConnectionSchema(schemaBody({ schemaVersion: SUPPORTED_SCHEMA_VERSION + 1 })),
      (err: Error) =>
        /update the MessageFoundry extension/i.test(err.message) && /version 2/.test(err.message),
    );
  });

  test("rejects a body with no schemaVersion at all", () => {
    const body = schemaBody();
    delete body.schemaVersion;
    assert.throws(() => parseConnectionSchema(body), /update the MessageFoundry extension/i);
  });

  test("rejects a non-object body and one missing its tables", () => {
    assert.throws(() => parseConnectionSchema(null), /did not return a connection schema/i);
    assert.throws(() => parseConnectionSchema([1, 2]), /did not return a connection schema/i);
    const body = schemaBody();
    delete body.transports;
    assert.throws(() => parseConnectionSchema(body), /missing its transports/i);
  });

  test("params are NOT second-guessed — a setting or flag this extension never heard of survives", () => {
    // The engine is the single source of truth; rejecting an unknown key here would recreate the
    // stale-mirror problem the derived catalogue exists to kill.
    const body = schemaBody();
    (body.transports as Record<string, TransportSchema>).future = {
      doc: "a transport added after this extension shipped",
      params: { knob: param({ type: "unknown" }) },
    };
    const parsed = parseConnectionSchema(body);
    assert.ok(parsed.transports.future.params.knob);
  });
});

suite("connectionSchema — per-direction params", () => {
  test("an outbound-only setting is absent for inbound (the engine rejects it there)", () => {
    const names = paramsForDirection(mllp(), "inbound").map((p) => p.name);
    assert.ok(!names.includes("host"), "host is outbound-only — an inbound form must not offer it");
    assert.ok(!names.includes("timeout_seconds"));
    assert.ok(names.includes("port"), "a direction-neutral setting applies to both");
    assert.ok(names.includes("tls_cert_file"));
  });

  test("an inbound-only setting is absent for outbound", () => {
    const names = paramsForDirection(mllp(), "outbound").map((p) => p.name);
    assert.ok(names.includes("host"));
    assert.ok(names.includes("timeout_seconds"));
    assert.ok(!names.includes("tls_cert_file"), "the server cert is meaningless outbound");
    assert.ok(names.includes("port"));
  });

  test("order is the engine's declaration order — section headings group what FOLLOWS them", () => {
    assert.deepStrictEqual(
      paramsForDirection(mllp(), "outbound").map((p) => p.name),
      ["host", "port", "encoding", "timeout_seconds", "tls", "tls_key_password"],
    );
    // Stable across calls, and the heading still leads its group after filtering.
    const twice = paramsForDirection(mllp(), "inbound").map((p) => p.name);
    assert.deepStrictEqual(twice, paramsForDirection(mllp(), "inbound").map((p) => p.name));
    const tls = twice.indexOf("tls");
    assert.ok(tls >= 0 && twice.indexOf("tls_cert_file") === tls + 1);
  });

  test("each row carries its key and its metadata (help/section/requiredHint)", () => {
    const host = paramsForDirection(mllp(), "outbound").find((p) => p.name === "host");
    assert.ok(host);
    assert.strictEqual(host.help, "the peer");
    assert.strictEqual(host.requiredHint, true, "required-only-outbound must reach the form");
    assert.strictEqual(host.required, false, "…and is NOT the same as having no default");
    const tls = paramsForDirection(mllp(), "outbound").find((p) => p.name === "tls");
    assert.strictEqual(tls?.section, "TLS");
  });

  test("a transport with no params yields no rows", () => {
    assert.deepStrictEqual(paramsForDirection({ doc: "", params: {} }, "inbound"), []);
  });
});

suite("connectionSchema — secret / env helpers", () => {
  test("a credential-bearing setting reads as secret; an ordinary one does not", () => {
    const params = mllp().params;
    assert.strictEqual(isSecret(params.tls_key_password), true);
    assert.strictEqual(isSecret(params.host), false);
    assert.strictEqual(isSecret(params.port), false);
  });

  test("env() applicability follows the flag, independently of secrecy", () => {
    const params = mllp().params;
    assert.strictEqual(acceptsEnv(params.tls_key_password), true);
    assert.strictEqual(acceptsEnv(params.host), true, "a non-secret setting may still be env()");
    assert.strictEqual(acceptsEnv(params.encoding), false);
  });

  test("a body that omits the flags reads false rather than undefined", () => {
    const bare = { type: "str", help: "" } as unknown as ParamSchema;
    assert.strictEqual(isSecret(bare), false);
    assert.strictEqual(acceptsEnv(bare), false);
  });
});

suite("connectionSchema — memoisation (the editor opens often; the engine is fixed)", () => {
  setup(() => {
    resetConnectionSchemaCache();
  });

  teardown(() => {
    resetConnectionSchemaCache();
  });

  /** A fetcher that counts its calls, so "did we shell out again?" is directly assertable. */
  function counting() {
    const calls = { n: 0 };
    return {
      calls,
      fetch: async () => {
        calls.n += 1;
        return schemaBody();
      },
    };
  }

  test("a second call does NOT re-invoke the fetcher", async () => {
    const { calls, fetch } = counting();
    const first = await loadConnectionSchema(fetch);
    const second = await loadConnectionSchema(fetch);
    assert.strictEqual(calls.n, 1, "the catalogue must be fetched once per engine");
    assert.strictEqual(first, second, "…and the same object handed out");
  });

  test("concurrent callers share ONE in-flight fetch", async () => {
    const { calls, fetch } = counting();
    const [a, b] = await Promise.all([loadConnectionSchema(fetch), loadConnectionSchema(fetch)]);
    assert.strictEqual(calls.n, 1);
    assert.strictEqual(a, b);
  });

  test("resetConnectionSchemaCache() forces the next call to re-fetch", async () => {
    const { calls, fetch } = counting();
    await loadConnectionSchema(fetch);
    resetConnectionSchemaCache();
    await loadConnectionSchema(fetch);
    assert.strictEqual(calls.n, 2);
  });

  test("a FAILED fetch is not memoised — the next open retries", async () => {
    let attempts = 0;
    const fetch = async () => {
      attempts += 1;
      if (attempts === 1) {
        throw new Error("workspace not trusted — MessageFoundry CLI disabled");
      }
      return schemaBody();
    };
    await assert.rejects(loadConnectionSchema(fetch), /not trusted/);
    const parsed = await loadConnectionSchema(fetch);
    assert.strictEqual(attempts, 2, "a transient failure must not poison the session");
    assert.strictEqual(parsed.schemaVersion, 1);
  });

  test("a rejected VERSION guard is not memoised either", async () => {
    let version = SUPPORTED_SCHEMA_VERSION + 1;
    const fetch = async () => schemaBody({ schemaVersion: version });
    await assert.rejects(loadConnectionSchema(fetch), /update the MessageFoundry extension/i);
    version = SUPPORTED_SCHEMA_VERSION;
    assert.strictEqual((await loadConnectionSchema(fetch)).schemaVersion, 1);
  });

  test("different cwds are cached separately (the cwd decides which engine answers)", async () => {
    const { calls, fetch } = counting();
    await loadConnectionSchema(fetch, "/one");
    await loadConnectionSchema(fetch, "/two");
    await loadConnectionSchema(fetch, "/one");
    assert.strictEqual(calls.n, 2);
  });
});

suite("connectionSchema — an engine that predates the verb", () => {
  setup(() => {
    resetConnectionSchemaCache();
  });

  /** What cli.ts's parseJsonResult throws when argparse rejects the action: stdout is empty, so the
   *  stderr usage blob becomes the message. Verbatim shape, trimmed. */
  const ARGPARSE_STDERR =
    "usage: messagefoundry connection [-h] [--config CONFIG] [--name NAME] [--data DATA] [--json]\n" +
    "                                 {list,upsert,remove}\n" +
    "messagefoundry connection: error: argument action: invalid choice: 'schema' " +
    "(choose from 'list', 'upsert', 'remove')";

  test("the argparse blob becomes an actionable 'update the engine' message", () => {
    const translated = translateSchemaFailure(new Error(ARGPARSE_STDERR));
    assert.strictEqual(translated.message, ENGINE_PREDATES_SCHEMA);
    assert.ok(/update the engine/i.test(translated.message));
    assert.ok(!/invalid choice/.test(translated.message), "the raw blob must not reach the user");
  });

  test("an engine with no `connection` command at all is the same failure", () => {
    const err = new Error("messagefoundry: error: argument command: invalid choice: 'connection'");
    assert.ok(isEnginePredatesSchema(err));
  });

  test("usage printed to STDOUT (a JSON.parse SyntaxError) is classified too", () => {
    // V8 truncates the quoted input, so the classifier must match the fragment, not the full line.
    const err = new SyntaxError(`Unexpected token 'u', "usage: mes"... is not valid JSON`);
    assert.strictEqual(translateSchemaFailure(err).message, ENGINE_PREDATES_SCHEMA);
  });

  test("an unrelated failure keeps its own message", () => {
    const trust = new Error("workspace not trusted — MessageFoundry CLI disabled until you trust it");
    assert.strictEqual(translateSchemaFailure(trust), trust);
    const wiring = new Error("WiringError: connections.toml: unknown transport 'mlpp'");
    assert.strictEqual(translateSchemaFailure(wiring).message, wiring.message);
    // Malformed JSON that is NOT a usage blob is a real bug — do not mislabel it as an old engine.
    assert.ok(!isEnginePredatesSchema(new SyntaxError("Unexpected end of JSON input")));
  });

  test("loadConnectionSchema surfaces the translated error, not the blob", async () => {
    await assert.rejects(
      loadConnectionSchema(async () => {
        throw new Error(ARGPARSE_STDERR);
      }),
      (err: Error) => err.message === ENGINE_PREDATES_SCHEMA,
    );
  });
});
