// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import {
  ESSENTIAL_GROUP,
  OTHER_GROUP,
  UNKNOWN_GROUP,
  buildForm,
  coerce,
  isSupportedSchemaVersion,
  type ConnectionSchema,
  type FieldDescriptor,
  type FieldGroup,
  type SchemaParam,
} from "../../connectionForm";

// The pure schema→form model behind the schema-driven connection editor. Exercised vscode-free
// against an INLINE fixture (never `connection schema --json` — a unit test must not shell out to
// the engine), which mirrors the contract shape: a transport whose parameters cover every axis the
// form branches on (required, direction-scoped requiredHint, section headings, choices, table, bool,
// secret). The load-bearing assertions: a key on the record is NEVER dropped, and a schema default
// is a placeholder, never a value.

/** One parameter, stated as the engine states it — a fixture entry overrides only what it varies. */
function param(overrides: Partial<SchemaParam>): SchemaParam {
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

const DOS_SECTION = "Inbound DoS guards (defaults mirror the transport DEFAULT_*; pass None/0 to disable)";
const TLS_SECTION = "--- TLS (ADR 0002) — per-connection transport TLS ---";

/** A hand-written schema matching `connection schema --json` (schemaVersion 1). */
function schemaFixture(): ConnectionSchema {
  return {
    schemaVersion: 1,
    transports: {
      demo: {
        doc: "A demonstration transport.",
        params: {
          // requiredHint on one direction only — mandatory outbound, rejected inbound.
          host: param({
            requiredHint: true,
            env: true,
            direction: "outbound",
            help: "the downstream peer (required; may be env()).",
          }),
          port: param({ type: "int", required: true, env: true }),
          encoding: param({ type: "str", default: "utf-8" }),
          pattern: param({ direction: "inbound", default: "*.hl7", help: "files to pick up" }),
          mode: param({ choices: ["fifo", "unordered"], default: "fifo" }),
          headers: param({ type: "table", default: null }),
          // Types as "unknown" yet is authored as a table -- the `soap.body_secrets` shape. Trusting
          // the tag gave it a text control and stringified the table on save.
          opaque: param({ type: "unknown", help: "an opaque table the schema cannot classify" }),
          // First parameter of a block: carries the heading for the ones that follow.
          max_connections: param({ type: "int", default: 256, section: DOS_SECTION }),
          receive_timeout: param({ type: "float", default: 60.0 }),
          tls: param({ type: "bool", default: false, section: TLS_SECTION }),
          // The declared shape deliberately FIGHTS the secret forcing, so the assertions about it
          // are not vacuous: `type: "table"` would otherwise produce a table control, and
          // `env: false` would otherwise produce envAllowed false. Mirrors the engine, where
          // `file.credential_password` genuinely is not a plain env-capable string.
          tls_key_password: param({
            type: "table",
            choices: ["a", "b"],
            env: false,
            secret: true,
            help: "passphrase for the key file",
          }),
        },
      },
    },
    directionKeys: {
      inbound: ["name", "transport", "settings", "router"],
      outbound: ["name", "transport", "settings", "retry"],
    },
  };
}

function group(groups: FieldGroup[], title: string): FieldGroup {
  const found = groups.find((each) => each.title === title);
  assert.ok(found, `expected a "${title}" group, got: ${groups.map((g) => g.title).join(" | ")}`);
  return found;
}

function field(groups: FieldGroup[], key: string): FieldDescriptor | undefined {
  return groups.flatMap((each) => each.fields).find((each) => each.key === key);
}

function keysOf(groups: FieldGroup[]): string[] {
  return groups.flatMap((each) => each.fields.map((each2) => each2.key));
}

suite("connectionForm — grouping and ordering", () => {
  test("Essential comes first, holds the required fields for the direction, and never collapses", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {});
    assert.strictEqual(groups[0].title, ESSENTIAL_GROUP);
    assert.strictEqual(groups[0].collapsed, false);
    // host (requiredHint, outbound) + port (no default at all) — in the schema's own order.
    assert.deepStrictEqual(
      groups[0].fields.map((each) => each.key),
      ["host", "port"],
    );
    // Both are hoisted, but only `port` BLOCKS: `host` is requiredHint, which the engine also uses
    // for value- and sibling-conditional settings, so it must never gate a save.
    assert.deepStrictEqual(
      groups[0].fields.map((each) => [each.key, each.required, each.conditionallyRequired]),
      [
        ["host", false, true],
        ["port", true, false],
      ],
    );
  });

  test("inbound Essential drops the outbound-only requiredHint field", () => {
    const groups = buildForm(schemaFixture(), "demo", "inbound", {});
    assert.deepStrictEqual(
      group(groups, ESSENTIAL_GROUP).fields.map((each) => each.key),
      ["port"],
    );
  });

  test("a section heading carries forward to the block that follows it, collapsed", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {});
    const dos = group(groups, "Inbound DoS guards");
    assert.strictEqual(dos.collapsed, true);
    assert.deepStrictEqual(
      dos.fields.map((each) => each.key),
      ["max_connections", "receive_timeout"],
    );
    // The heading is prose: the title is shortened for rendering, the full text is preserved.
    assert.strictEqual(dos.description, DOS_SECTION);

    const tls = group(groups, "TLS (ADR 0002) — per-connection transport TLS");
    assert.deepStrictEqual(
      tls.fields.map((each) => each.key),
      ["tls", "tls_key_password"],
    );
    assert.strictEqual(tls.description, undefined); // short enough to render whole
  });

  test("un-sectioned, non-required settings land in a collapsed Other settings, and groups are ordered", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {});
    const other = group(groups, OTHER_GROUP);
    assert.strictEqual(other.collapsed, true);
    assert.deepStrictEqual(
      other.fields.map((each) => each.key),
      ["encoding", "mode", "headers", "opaque"],
    );
    assert.deepStrictEqual(
      groups.map((each) => each.title),
      [
        ESSENTIAL_GROUP,
        "Inbound DoS guards",
        "TLS (ADR 0002) — per-connection transport TLS",
        OTHER_GROUP,
      ],
    );
  });

  test("controls follow the declared type", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {});
    assert.strictEqual(field(groups, "port")?.control, "number");
    assert.strictEqual(field(groups, "receive_timeout")?.control, "number");
    assert.strictEqual(field(groups, "tls")?.control, "checkbox");
    assert.strictEqual(field(groups, "mode")?.control, "select");
    assert.deepStrictEqual(field(groups, "mode")?.choices, ["fifo", "unordered"]);
    assert.strictEqual(field(groups, "headers")?.control, "table");
    assert.strictEqual(field(groups, "encoding")?.control, "text");
  });
});

suite("connectionForm — direction filtering", () => {
  test("a setting scoped to the other direction is not rendered", () => {
    const outbound = buildForm(schemaFixture(), "demo", "outbound", {});
    assert.strictEqual(field(outbound, "pattern"), undefined);
    const inbound = buildForm(schemaFixture(), "demo", "inbound", {});
    assert.strictEqual(field(inbound, "host"), undefined);
    assert.ok(field(inbound, "pattern"));
  });

  test("…unless the record sets it: then it is rendered, flagged, and not treated as required", () => {
    const groups = buildForm(schemaFixture(), "demo", "inbound", { host: "peer.example" });
    const host = field(groups, "host");
    assert.ok(host, "an outbound-only key present on an inbound record must still be rendered");
    assert.strictEqual(host.value, "peer.example");
    assert.strictEqual(host.offDirection, true);
    assert.strictEqual(host.required, false); // required OUTBOUND — not here
    assert.strictEqual(host.group, OTHER_GROUP);
    assert.ok(host.help.includes("outbound-only"));
  });
});

suite("connectionForm — nothing on the record is ever dropped", () => {
  test("a key the schema does not describe gets its own LAST group, expanded, value preserved", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {
      port: 2575,
      future_setting: "keep me",
    });
    const last = groups[groups.length - 1];
    assert.strictEqual(last.title, UNKNOWN_GROUP);
    assert.strictEqual(last.collapsed, false); // an undescribed key wants eyes on it
    assert.deepStrictEqual(
      last.fields.map((each) => each.key),
      ["future_setting"],
    );
    const unknown = last.fields[0];
    assert.strictEqual(unknown.known, false);
    assert.strictEqual(unknown.value, "keep me");
    assert.strictEqual(unknown.control, "text");
  });

  test("every settings key on the record appears exactly once across the groups", () => {
    const settings = {
      port: 2575,
      host: "peer.example", // schema says outbound-only; this is an INBOUND form
      pattern: "*.hl7",
      hand_written: 7, // not in the schema at all
      also_missing: { env: "SOME_KEY" }, // …and an env reference at that
    };
    const groups = buildForm(schemaFixture(), "demo", "inbound", settings);
    const rendered = keysOf(groups);
    for (const key of Object.keys(settings)) {
      assert.strictEqual(
        rendered.filter((each) => each === key).length,
        1,
        `${key} must be rendered exactly once (upsert is a full replace — unrendered = deleted)`,
      );
    }
    assert.strictEqual(field(groups, "hand_written")?.type, "int");
    assert.strictEqual(field(groups, "also_missing")?.isEnvRef, true);
    assert.strictEqual(field(groups, "also_missing")?.envKey, "SOME_KEY");
  });

  test("a transport this engine does not know still renders the whole record", () => {
    const groups = buildForm(schemaFixture(), "not_in_this_engine", "outbound", {
      alpha: 1,
      beta: true,
    });
    assert.deepStrictEqual(
      groups.map((each) => each.title),
      [UNKNOWN_GROUP],
    );
    assert.deepStrictEqual(keysOf(groups), ["alpha", "beta"]);
    assert.strictEqual(field(groups, "beta")?.control, "checkbox");
  });

  test("an env reference round-trips its key, cast and default", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {
      port: { env: "PEER_PORT", cast: "int", default: 2575 },
    });
    const port = field(groups, "port");
    assert.strictEqual(port?.isEnvRef, true);
    assert.strictEqual(port?.envKey, "PEER_PORT");
    assert.strictEqual(port?.cast, "int");
    assert.strictEqual(port?.envDefault, 2575);
    assert.strictEqual(port?.value, undefined); // the literal slot stays empty for a reference
  });

  test("a plain table that happens to carry an env key is a literal, not a reference", () => {
    // Mirrors the engine's parse_env_setting: an inline table is a reference only when its keys are
    // a subset of {env, default, cast}. A headers map with an "env" header is a value.
    const groups = buildForm(schemaFixture(), "demo", "outbound", {
      headers: { env: "prod", "x-trace": "1" },
    });
    assert.strictEqual(field(groups, "headers")?.isEnvRef, false);
    assert.deepStrictEqual(field(groups, "headers")?.value, { env: "prod", "x-trace": "1" });
  });
});

suite("connectionForm — a credential is env-only", () => {
  test("a secret offers no plaintext control: its text box collects the ENV KEY", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {});
    const secret = field(groups, "tls_key_password");
    assert.ok(secret);
    assert.strictEqual(secret.secret, true);
    assert.strictEqual(secret.secretOnlyEnv, true);
    assert.strictEqual(secret.envAllowed, true);
    assert.strictEqual(secret.control, "text");
    assert.strictEqual(secret.value, undefined);
    assert.ok(secret.label.includes("env key"));
  });

  test("a secret already stored as a reference shows the key it references", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {
      tls_key_password: { env: "TLS_KEY_PASSPHRASE" },
    });
    const secret = field(groups, "tls_key_password");
    assert.strictEqual(secret?.isEnvRef, true);
    assert.strictEqual(secret?.envKey, "TLS_KEY_PASSPHRASE");
    assert.strictEqual(secret?.value, undefined);
    assert.strictEqual(secret?.preserveValue, undefined);
  });

  test("an inline credential already in the file is never displayed, but is not destroyed either", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {
      tls_key_password: "already-in-the-file",
    });
    const secret = field(groups, "tls_key_password");
    assert.strictEqual(secret?.value, undefined, "a credential is never rendered as a value");
    assert.strictEqual(secret?.isEnvRef, false, "a literal must not be mistaken for an env key");
    assert.strictEqual(secret?.preserveValue, "already-in-the-file");
  });
});

suite("connectionForm — a default is a placeholder, never a value", () => {
  test("an untouched form carries no values at all, only placeholders", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {});
    const all = groups.flatMap((each) => each.fields);
    assert.ok(all.length > 0);
    assert.deepStrictEqual(
      all.filter((each) => each.value !== undefined).map((each) => each.key),
      [],
      "saving an untouched form must not write every engine default into connections.toml",
    );
    assert.strictEqual(field(groups, "encoding")?.placeholder, "utf-8");
    assert.strictEqual(field(groups, "max_connections")?.placeholder, "256");
    assert.strictEqual(field(groups, "receive_timeout")?.placeholder, "60");
    assert.strictEqual(field(groups, "tls")?.placeholder, "false");
    assert.strictEqual(field(groups, "tls")?.defaultValue, false);
    assert.strictEqual(field(groups, "port")?.placeholder, ""); // no default at all
  });

  test("only what the record sets becomes a value", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", { encoding: "iso-8859-1" });
    assert.strictEqual(field(groups, "encoding")?.value, "iso-8859-1");
    assert.strictEqual(field(groups, "encoding")?.placeholder, "utf-8");
    assert.strictEqual(field(groups, "max_connections")?.value, undefined);
  });
});

suite("connectionForm — coerce", () => {
  const groups = buildForm(schemaFixture(), "demo", "outbound", {});
  const of = (key: string): FieldDescriptor => {
    const found = field(groups, key);
    assert.ok(found, `${key} must be rendered`);
    return found;
  };

  test("a number control yields a number; unparseable text passes through verbatim", () => {
    assert.strictEqual(coerce(of("port"), " 2575 "), 2575);
    assert.strictEqual(coerce(of("receive_timeout"), "60.5"), 60.5);
    assert.strictEqual(coerce(of("port"), "not-a-port"), "not-a-port");
  });

  test("a checkbox yields a boolean; still-at-the-default yields undefined", () => {
    // `tls` defaults to false and the fixture record does not carry it, so a checkbox sitting in its
    // default position is "untouched" and must write nothing — a checkbox cannot report that itself,
    // it always posts a boolean. Ticking it is a real change and does write. See invariant 2.
    assert.strictEqual(coerce(of("tls"), true), true);
    assert.strictEqual(coerce(of("tls"), false), undefined);
    assert.strictEqual(coerce(of("tls"), "true"), true);
    assert.strictEqual(coerce(of("tls"), undefined), undefined);
    assert.strictEqual(coerce(of("tls"), ""), undefined);
  });

  test("a select yields the choice, a table parses as JSON, text stays text", () => {
    assert.strictEqual(coerce(of("mode"), "unordered"), "unordered");
    assert.deepStrictEqual(coerce(of("headers"), '{"x-trace":"1"}'), { "x-trace": "1" });
    assert.strictEqual(coerce(of("headers"), "{not json"), "{not json");
    assert.strictEqual(coerce(of("encoding"), " utf-8 "), "utf-8");
  });

  test("an emptied field yields undefined so the caller omits the key entirely", () => {
    assert.strictEqual(coerce(of("encoding"), ""), undefined);
    assert.strictEqual(coerce(of("encoding"), "   "), undefined);
    assert.strictEqual(coerce(of("headers"), ""), undefined);
    assert.strictEqual(coerce(of("port"), ""), undefined, "even required: absent beats wrong-typed");
  });
});

suite("connectionForm — schema version", () => {
  test("only the understood schemaVersion is accepted", () => {
    assert.strictEqual(isSupportedSchemaVersion(schemaFixture()), true);
    assert.strictEqual(isSupportedSchemaVersion({ ...schemaFixture(), schemaVersion: 2 }), false);
    assert.strictEqual(isSupportedSchemaVersion(undefined), false);
  });
});

suite("connectionForm — a conditional 'required' never blocks a save", () => {
  // The engine overloads `requiredHint` three ways: direction-conditional (mllp.host, required
  // outbound), value-conditional (mllp.tls_cert_file, "required when tls") and sibling-conditional
  // (database.database, "required for dialect='sqlserver'"). Collapsing them into a blocking
  // `required` made a plain non-TLS inbound MLLP listener unsavable -- the commonest connection
  // there is. Only a param the factory declares WITHOUT a default may block.
  test("a value-conditional hint marks and hoists the field, but does not block", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {});
    const hinted = field(groups, "host");
    assert.ok(hinted);
    assert.strictEqual(hinted.conditionallyRequired, true, "keeps the marker");
    assert.strictEqual(hinted.required, false, "but must not gate the save");
    assert.strictEqual(groups[0].fields.some((each) => each.key === "host"), true, "still Essential");
  });

  test("only a defaultless param is blocking", () => {
    const groups = buildForm(schemaFixture(), "demo", "outbound", {});
    const blocking = groups.flatMap((g) => g.fields).filter((f) => f.required);
    for (const f of blocking) {
      // The engine emits `default: null` for a parameter that has no default at all.
      assert.ok(
        f.defaultValue === undefined || f.defaultValue === null,
        `${f.key} blocks a save yet declares a default (${JSON.stringify(f.defaultValue)})`,
      );
    }
  });
});

suite("connectionForm — an unclassified param keeps the shape the record gave it", () => {
  // `soap.body_secrets` types as "unknown" but is authored as a table. Trusting the tag gave it a
  // text control, which rendered "[object Object]" and wrote that string back on save -- the exact
  // data loss the unknown-key rule exists to prevent, arriving via the type tag instead of omission.
  test("an unknown-typed param holding a table gets a table control, not text", () => {
    const record = { opaque: { token: { env: "SECRET_KEY" } } };
    const groups = buildForm(schemaFixture(), "demo", "outbound", record);
    const opaque = field(groups, "opaque");
    assert.ok(opaque, "the param must appear");
    assert.strictEqual(opaque.control, "table", "a table value must not get a text box");
    assert.deepStrictEqual(opaque.value, record.opaque, "and its value survives verbatim");
  });

  test("round-tripping an unknown-typed table does not stringify it", () => {
    const record = { opaque: { token: { env: "SECRET_KEY" } } };
    const groups = buildForm(schemaFixture(), "demo", "outbound", record);
    const opaque = field(groups, "opaque");
    assert.ok(opaque);
    const posted = coerce(opaque, JSON.stringify(opaque.value));
    assert.deepStrictEqual(posted, record.opaque);
    assert.notStrictEqual(posted, "[object Object]");
  });
});

suite("connectionForm — an untouched form writes nothing", () => {
  test("a checkbox left at its schema default is omitted, not written out", () => {
    const groups = buildForm(schemaFixture(), "demo", "inbound", {});
    const flag = field(groups, "tls");
    assert.ok(flag);
    assert.strictEqual(flag.value, undefined, "the record did not carry it");
    assert.strictEqual(flag.defaultValue, false);
    // An <input type=checkbox> always posts a boolean; posting the default must still omit the key.
    assert.strictEqual(coerce(flag, false), undefined, "default-positioned checkbox writes nothing");
    assert.strictEqual(coerce(flag, true), true, "a real change still writes");
  });

  test("a value the record already carried stays explicit even when it equals the default", () => {
    const groups = buildForm(schemaFixture(), "demo", "inbound", { tls: false });
    const flag = field(groups, "tls");
    assert.ok(flag);
    assert.strictEqual(flag.value, false);
    assert.strictEqual(coerce(flag, false), false, "an authored value is not silently dropped");
  });
});
