// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { alertEditorScript } from "../../alertEditorWebview";
import { codeSetEditorScript } from "../../codeSetEditorWebview";
import { buildForm, type ConnectionSchema, type SchemaParam } from "../../connectionForm";
import { connectionEditorScript } from "../../connectionEditorWebview";
import type { Graph } from "../../graphModel";
import { homeScript } from "../../homeWebview";
import { FIELDS, securityEditorScript } from "../../securityEditorWebview";
import { sourceControlScript } from "../../sourceControlWebview";
import { CHANNEL_FIELD } from "../../webviewMessaging";
import { wiringMapPayload } from "../../wiringMapModel";
import { wiringMapScript } from "../../wiringMapWebview";

// ASVS 3.5.5 (BACKLOG #1123), the syntax half at the seven receivers other than Test Bench.
//
// mfTrusted() decides WHO sent a message. This suite pins the next step at each receiver: a message
// that is correctly stamped and carries a known discriminator, but whose payload is missing a
// required field or has one of the wrong JS type, is DISCARDED. Nothing on the page changes and
// nothing throws. Value ranges are a different requirement and are not tested here.
//
// Each panel's REAL script is evaluated in a jsdom page, so what runs here is what ships. Each
// well-formed fixture is built by the host's own pure function where there is one (buildForm,
// wiringMapPayload), and is otherwise output recorded once from the CLI command the host runs. A
// recorded fixture does NOT follow later changes to that CLI's output; nothing here would notice one.
// Each must be accepted, and accepted means the page visibly changed. That is the control: a
// receiver that discarded everything would pass every malformed case and prove nothing.
//
// Node-side only, like webview-guard.test.ts: no `vscode` import, so this runs on the unit leg.

// jsdom through a narrow local shape, for the reason webview-guard.test.ts gives: the base tsconfig
// has no DOM lib, and @types/jsdom would pull it in.
interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib.
  [key: string]: any;
}
interface JsdomWindow {
  document: DomNode;
  origin: string;
  MessageEvent: new (type: string, init?: Record<string, unknown>) => unknown;
  dispatchEvent(event: unknown): boolean;
  close(): void;
  [key: string]: unknown;
}
interface JsdomVirtualConsole {
  on(event: string, handler: (...args: unknown[]) => void): void;
}
interface JsdomModule {
  JSDOM: new (html: string, options?: Record<string, unknown>) => { window: JsdomWindow };
  VirtualConsole: new () => JsdomVirtualConsole;
}
const { JSDOM, VirtualConsole } = require("jsdom") as JsdomModule;

type Payload = Record<string, any>;

const TOKEN = "RECVtokenRECVtokenRECV00";
/** Seeded into every element a message writes text into, so writing an empty string still shows. */
const SENTINEL = "before";

interface Page {
  readonly window: JsdomWindow;
  /** Every exception the page raised, loading or handling a message. */
  readonly errors: unknown[];
  /** Every console.warn the page wrote. A discard names itself there. */
  readonly warnings: string[];
  deliver(data: Payload): void;
  /** Markup plus every form control's live value, which markup does not show. */
  snapshot(): string;
}

/** Every window a page opened. Closed after each test so the realms do not pile up. */
const openWindows: JsdomWindow[] = [];
function closeWindows(): void {
  for (const w of openWindows.splice(0)) {
    w.close();
  }
}

function page(script: string, body: string): Page {
  const errors: unknown[] = [];
  const warnings: string[] = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e: unknown) => errors.push(e));
  virtualConsole.on("warn", (...args: unknown[]) => warnings.push(args.map(String).join(" ")));
  const dom = new JSDOM(`<!DOCTYPE html><body>${body}</body>`, {
    runScripts: "dangerously",
    virtualConsole,
    url: "https://localhost/",
  });
  const window = dom.window;
  openWindows.push(window);
  window.acquireVsCodeApi = () => ({
    getState: () => null,
    setState: () => undefined,
    postMessage: () => undefined,
  });
  const el = window.document.createElement("script");
  el.textContent = script;
  window.document.body.appendChild(el);
  assert.deepStrictEqual(errors.map(String), [], "the panel script threw while loading");
  return {
    window,
    errors,
    warnings,
    deliver(data): void {
      window.dispatchEvent(
        new window.MessageEvent("message", {
          origin: window.origin,
          source: null,
          data: { ...data, [CHANNEL_FIELD]: TOKEN },
        }),
      );
    },
    snapshot(): string {
      const controls = [...window.document.querySelectorAll("input, select, textarea")].map(
        (c: DomNode) => [c.id || c.name, c.value, c.checked, c.disabled],
      );
      return window.document.body.innerHTML + "\n" + JSON.stringify(controls);
    },
  };
}

function clone(p: Payload): Payload {
  return JSON.parse(JSON.stringify(p)) as Payload;
}

/** A copy of `p` with ONE change applied, so each malformed case differs from its fixture once. */
function variant(p: Payload, change: (copy: Payload) => void): Payload {
  const copy = clone(p);
  change(copy);
  return copy;
}

interface Receiver {
  /** The panel, as its discard warning names it. */
  readonly panel: string;
  /** The discriminator field this receiver dispatches on. */
  readonly key: "command" | "type";
  load(): Page;
  /** One fixture per message type the host posts, each built from what the host posts. */
  readonly wellFormed: Record<string, Payload[]>;
  /** Per message type: malformed payloads with the discriminator intact. */
  readonly malformed: Record<string, [string, Payload][]>;
}

// --- Alert Rules --------------------------------------------------------------------------------

/** Recorded 2026-09-29 from `messagefoundry alert list --json` over three rules added through the
 *  same CLI, which is exactly what alertEditor.ts refresh() posts as `rules`. */
const ALERT_RULES = [
  {
    event_type: "queue_buildup",
    connection: "OB_*",
    min_depth: 500,
    min_oldest_seconds: 120.5,
    severity: "critical",
    transports: ["webhook"],
    index: 0,
  },
  { event_type: "connection_stopped", cooldown_seconds: 300, index: 1 },
  { event_type: "cert_expiry", transports: [], index: 2 },
];

/** Recorded the same day from `alert list --json` over a HAND-EDITED file with `min_depth = "500"`.
 *  The row is the raw TOML table, and the engine's lax model loads that quoted number. */
const ALERT_RULES_QUOTED = [{ event_type: "queue_buildup", min_depth: "500", index: 0 }];

/** alertEditor.ts posts `String(e)` for a thrown CLI error; this is a recorded CLI refusal. */
const CLI_ERROR = String(
  new Error(
    "alert rule routes to unconfigured transport(s) ['webhook']; this instance configures none. " +
      "Configure [alerts].webhook_url, or email_smtp_host + email_from + email_to (all three), " +
      "before adding the rule — otherwise the engine refuses to start.",
  ),
);

const ALERT_OK = { command: "rules", rules: ALERT_RULES };
const ERROR_OK = { command: "error", message: CLI_ERROR };

/** The message-string cases every `error` receiver that reads `message` must discard. */
function badMessages(ok: Payload): [string, Payload][] {
  return [
    ["no message", variant(ok, (c) => delete c.message)],
    ["message is a number", variant(ok, (c) => (c.message = 42))],
    ["message is an object", variant(ok, (c) => (c.message = { text: "x" }))],
    ["message is null", variant(ok, (c) => (c.message = null))],
  ];
}

const alertRules: Receiver = {
  panel: "Alert Rules",
  key: "command",
  load: () =>
    page(
      alertEditorScript(TOKEN, ["any", "queue_buildup"], ["info", "warning", "critical"]),
      `<table id="rules"><tbody id="rows"><tr><td>${SENTINEL}</td></tr></tbody></table>
       <div id="empty"></div>
       <select id="event_type"></select><input id="connection" value="*" />
       <select id="severity"></select><select id="transports"></select>
       <div id="error">${SENTINEL}</div><button id="add"></button><button id="close"></button>`,
    ),
  wellFormed: {
    rules: [ALERT_OK, { command: "rules", rules: ALERT_RULES_QUOTED }, { command: "rules", rules: [] }],
    error: [ERROR_OK],
  },
  malformed: {
    rules: [
      ["no rules", variant(ALERT_OK, (c) => delete c.rules)],
      ["rules is an object", variant(ALERT_OK, (c) => (c.rules = { 0: ALERT_RULES[0] }))],
      ["a rule is a string", variant(ALERT_OK, (c) => (c.rules[1] = "connection_stopped"))],
      ["a rule has no index", variant(ALERT_OK, (c) => delete c.rules[1].index)],
      ["index is a string", variant(ALERT_OK, (c) => (c.rules[0].index = "0"))],
      ["transports is a string", variant(ALERT_OK, (c) => (c.rules[0].transports = "webhook"))],
      ["a transport is a number", variant(ALERT_OK, (c) => (c.rules[0].transports = [1]))],
      ["min_depth is an array", variant(ALERT_OK, (c) => (c.rules[0].min_depth = [500]))],
      ["cooldown_seconds is a table", variant(ALERT_OK, (c) => (c.rules[1].cooldown_seconds = { s: 300 }))],
      ["a rule is null", variant(ALERT_OK, (c) => (c.rules[1] = null))],
      // Holes, which Array.prototype.every() would skip. Made after the clone, so they survive.
      ["the rules array has holes", variant(ALERT_OK, (c) => (c.rules.length = 5))],
      ["connection is a number", variant(ALERT_OK, (c) => (c.rules[0].connection = 7))],
      ["severity is an array", variant(ALERT_OK, (c) => (c.rules[0].severity = ["critical"]))],
    ],
    error: badMessages(ERROR_OK),
  },
};

// --- Code Set editor -----------------------------------------------------------------------------

const codeSet: Receiver = {
  panel: "Code Set editor",
  key: "command",
  load: () =>
    page(
      codeSetEditorScript(TOKEN, null, false, ["LAB_CODES"]),
      `<h2 id="title"></h2><div id="ro-banner"></div><input id="name" /><div id="policy"></div>
       <input id="search" /><span id="searchcount"></span>
       <table><thead><tr id="headrow"></tr></thead><tbody id="body"></tbody></table>
       <button id="addRow"></button><button id="addCol"></button>
       <div id="warn"></div><div id="error">${SENTINEL}</div>
       <button id="save"></button><button id="cancel"></button><button id="delete"></button>`,
    ),
  wellFormed: { error: [ERROR_OK] },
  malformed: { error: badMessages(ERROR_OK) },
};

// --- Connection editor ---------------------------------------------------------------------------

/** One schema parameter, stated as `connection schema --json` states it (connection-form.test.ts). */
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

const SCHEMA: ConnectionSchema = {
  schemaVersion: 1,
  transports: {
    mllp: {
      doc: "MLLP over TCP.",
      params: {
        host: param({ requiredHint: true, env: true, direction: "outbound", help: "the peer" }),
        port: param({ type: "int", required: true, env: true }),
        mode: param({ choices: ["fifo", "unordered"], default: "fifo" }),
        tls: param({ type: "bool", default: false, section: "--- TLS ---" }),
        tls_key_password: param({ secret: true, help: "passphrase for the key file" }),
      },
    },
  },
  directionKeys: {
    inbound: ["name", "transport", "settings", "router"],
    outbound: ["name", "transport", "settings", "retry"],
  },
};

/** What connectionEditor.ts posts after a transport change: buildForm() output, as `groups`. Built
 *  over a record that exercises an env reference, a literal, and a key the schema does not know. */
const FIELDS_OK = {
  command: "fields",
  groups: buildForm(SCHEMA, "mllp", "outbound", {
    host: { env: "PEER_HOST", cast: "str" },
    port: 6661,
    legacy_key: "kept",
  }),
};

const connection: Receiver = {
  panel: "connection editor",
  key: "command",
  load: () =>
    page(
      connectionEditorScript(TOKEN, {
        initial: undefined,
        routers: ["route_adt"],
        transports: ["mllp", "file"],
        fieldGroups: buildForm(SCHEMA, "mllp", "inbound", {}),
        siblings: undefined,
        clone: undefined,
      }),
      `<div id="conn-picker-row"><select id="connPicker"></select></div><h2 id="title"></h2>
       <select id="direction"><option value="inbound">in</option><option value="outbound">out</option></select>
       <select id="transport"></select><input id="name" />
       <div id="router-row"><select id="router"></select></div>
       <div id="settings"></div><button id="addSetting"></button>
       <div id="inbound-opts"><select id="ackMode"><option value="">o</option></select>
         <input type="checkbox" id="strict" /></div>
       <div id="outbound-opts"><select id="ordering"><option value="">f</option></select>
         <input id="maxAttempts" /></div>
       <div id="error">${SENTINEL}</div>
       <button id="save"></button><button id="cancel"></button><button id="delete"></button>`,
    ),
  wellFormed: { error: [ERROR_OK], fields: [FIELDS_OK] },
  malformed: {
    error: badMessages(ERROR_OK),
    fields: [
      ["no groups", variant(FIELDS_OK, (c) => delete c.groups)],
      ["groups is an object", variant(FIELDS_OK, (c) => (c.groups = { 0: c.groups[0] }))],
      ["a group has no title", variant(FIELDS_OK, (c) => delete c.groups[0].title)],
      ["collapsed is a string", variant(FIELDS_OK, (c) => (c.groups[0].collapsed = "no"))],
      ["fields is not an array", variant(FIELDS_OK, (c) => (c.groups[0].fields = c.groups[0].fields[0]))],
      ["a field has no key", variant(FIELDS_OK, (c) => delete c.groups[0].fields[0].key)],
      ["a field's label is a number", variant(FIELDS_OK, (c) => (c.groups[0].fields[0].label = 3))],
      ["required is a string", variant(FIELDS_OK, (c) => (c.groups[0].fields[0].required = "yes"))],
      ["choices is a string", variant(FIELDS_OK, (c) => (c.groups[0].fields[0].choices = "a,b"))],
      ["envKey is a number", variant(FIELDS_OK, (c) => (c.groups[0].fields[0].envKey = 5))],
    ],
  },
};

// --- Home ------------------------------------------------------------------------------------------

/** home.ts posts the Connections tree's filter text, a string, as `text`. */
const FILTER_OK = { command: "setFilter", text: "IB_ACME" };

const home: Receiver = {
  panel: "Home",
  key: "command",
  load: () => page(homeScript(TOKEN), `<input id="search" type="search" value="${SENTINEL}" />`),
  wellFormed: { setFilter: [FILTER_OK, { command: "setFilter", text: "" }] },
  malformed: {
    setFilter: [
      ["no text", variant(FILTER_OK, (c) => delete c.text)],
      ["text is a number", variant(FILTER_OK, (c) => (c.text = 5))],
      ["text is null", variant(FILTER_OK, (c) => (c.text = null))],
      ["text is an array", variant(FILTER_OK, (c) => (c.text = ["IB_ACME"]))],
    ],
  },
};

// --- Security Settings ---------------------------------------------------------------------------

/** Recorded 2026-09-29 from `messagefoundry security show --json` over a settings file with one
 *  loosened switch (require_mfa = false), which is what securityEditor.ts refresh() posts. */
const SECURITY_SHOW: Payload = {
  "values": {
    "local_access_only": true,
    "listen_address": "127.0.0.1",
    "require_encryption_for_remote": true,
    "serve_web_console": true,
    "web_console_public_address": "",
    "allowed_client_networks": [],
    "enforcement": "enforce",
    "encrypt_stored_data": true,
    "allow_unencrypted_phi": false,
    "allow_unencrypted_phi_under_strict_enforcement": false,
    "memory_encryption_operator_declared": false,
    "require_memory_encryption_declaration": false,
    "allow_unverified_alert_smtp_tls": false,
    "allow_over_granted_store_principal": false,
    "require_nonstatic_credentials": false,
    "static_credential_accepted": {},
    "require_sign_in": true,
    "require_mfa": false,
    "require_mfa_scope": "every_local_account",
    "allow_single_factor_admin_when_exposed": false,
    "sign_out_after_idle_minutes": 30,
    "max_session_hours": 12,
    "block_unlisted_outbound": true,
    "delete_message_bodies_after_days": 30,
    "allow_keeping_phi_indefinitely": false,
    "allow_keeping_transform_state_indefinitely": false,
    "allow_keeping_search_presets_indefinitely": false,
    "allow_keeping_app_logs_indefinitely": false,
    "allow_keeping_backup_archives_indefinitely": false,
    "audit_all_authorization_decisions": true,
    "production_instance": null,
    "organization_domains": [],
    "external_link_interstitial": true,
    "external_link_allowlist": []
  },
  "set": [
    "require_mfa"
  ],
  "defaults": {
    "local_access_only": true,
    "listen_address": "127.0.0.1",
    "require_encryption_for_remote": true,
    "serve_web_console": true,
    "web_console_public_address": "",
    "allowed_client_networks": [],
    "enforcement": "enforce",
    "encrypt_stored_data": true,
    "allow_unencrypted_phi": false,
    "allow_unencrypted_phi_under_strict_enforcement": false,
    "memory_encryption_operator_declared": false,
    "require_memory_encryption_declaration": false,
    "allow_unverified_alert_smtp_tls": false,
    "allow_over_granted_store_principal": false,
    "require_nonstatic_credentials": false,
    "static_credential_accepted": {},
    "require_sign_in": true,
    "require_mfa": true,
    "require_mfa_scope": "every_local_account",
    "allow_single_factor_admin_when_exposed": false,
    "sign_out_after_idle_minutes": 30,
    "max_session_hours": 12,
    "block_unlisted_outbound": true,
    "delete_message_bodies_after_days": 30,
    "allow_keeping_phi_indefinitely": false,
    "allow_keeping_transform_state_indefinitely": false,
    "allow_keeping_search_presets_indefinitely": false,
    "allow_keeping_app_logs_indefinitely": false,
    "allow_keeping_backup_archives_indefinitely": false,
    "audit_all_authorization_decisions": true,
    "production_instance": null,
    "organization_domains": [],
    "external_link_interstitial": true,
    "external_link_allowlist": []
  },
  "loosenings": [
    {
      "switch": "require_mfa",
      "risk": "every account is single-factor \u2014 no engine second factor is required, and a directory session is admitted on a ticket that asserts no strength"
    }
  ],
  "loosenings_partial": false,
  "loosenings_scope": "settings only ([security]/[store]/[auth]/[alerts]/[secret_rotation]/[api]); the per-connection cleartext_accepted, tls_allow_expired, generic-ODBC database TLS, tls_hop_attested and tls_revocation_attested declarations are NOT included, and neither are the store-principal privilege and audit-chain keying observations (#1008, #1905 \u2014 this command opens no store, and neither does `check`; GET /security/posture reports both). These are the AUTHORED values, so a `serve --host` bind override on a running engine is not reflected here either \u2014 see `messagefoundry check` or GET /security/posture"
};

const STATE_OK = { command: "state", state: SECURITY_SHOW };

const security: Receiver = {
  panel: "Security Settings",
  key: "command",
  load: () =>
    page(
      securityEditorScript(TOKEN, FIELDS),
      `<div id="form"></div><div id="error">${SENTINEL}</div>
       <button id="save"></button><button id="close"></button>`,
    ),
  wellFormed: { state: [STATE_OK], error: [ERROR_OK] },
  malformed: {
    state: [
      ["no state", variant(STATE_OK, (c) => delete c.state)],
      ["state is an array", variant(STATE_OK, (c) => (c.state = [c.state]))],
      ["no values", variant(STATE_OK, (c) => delete c.state.values)],
      ["defaults is a string", variant(STATE_OK, (c) => (c.state.defaults = "secure"))],
      ["set is a string", variant(STATE_OK, (c) => (c.state.set = "require_mfa"))],
      ["a loosening has no risk", variant(STATE_OK, (c) => delete c.state.loosenings[0].risk)],
      ["loosenings is an object", variant(STATE_OK, (c) => (c.state.loosenings = c.state.loosenings[0]))],
    ],
    error: badMessages(ERROR_OK),
  },
};

// --- Config repo storage -------------------------------------------------------------------------

/** sourceControl.ts posts its errors as `text`, not `message`, e.g. after a failed `git remote`. */
const SC_ERROR_OK = { command: "error", text: "Could not set remote — fatal: remote origin already exists." };

const sourceControl: Receiver = {
  panel: "config repo storage",
  key: "command",
  load: () =>
    page(
      sourceControlScript(TOKEN),
      `<input type="radio" name="mode" value="local" checked /><input type="radio" name="mode" value="remote" />
       <input id="url" /><div id="err">${SENTINEL}</div>
       <button id="save"></button><button id="cancel"></button>`,
    ),
  wellFormed: { error: [SC_ERROR_OK] },
  malformed: {
    error: [
      ["no text", variant(SC_ERROR_OK, (c) => delete c.text)],
      ["text is a number", variant(SC_ERROR_OK, (c) => (c.text = 7))],
      ["text is an object", variant(SC_ERROR_OK, (c) => (c.text = { stderr: "x" }))],
      // The field the OTHER panels use. Right type, wrong name, so it is missing here.
      ["message instead of text", variant(SC_ERROR_OK, (c) => ((c.message = c.text), delete c.text))],
    ],
  },
};

// --- Wiring Map ----------------------------------------------------------------------------------

/** A small wiring graph: an inbound, a router with a literal and a heuristic edge, a dynamic
 *  handler (so the map carries a "?" stub), and an outbound. */
const GRAPH: Graph = {
  version: 2,
  inbound: [
    { name: "IB_A", type: "mllp", router: "route_a", settings: { port: 6661 }, file: "/c/a.py", line: 3, receives_from: [] },
  ],
  outbound: [{ name: "OB_Main", type: "mllp", file: "/c/a.py", line: 6, receives_from: ["xform_main"] }],
  routers: [
    {
      name: "route_a",
      file: "/c/a.py",
      line: 10,
      handlers: ["xform_main", "relay_dyn"],
      edges: [
        { target: "xform_main", target_kind: "handler", provenance: "literal" },
        { target: "relay_dyn", target_kind: "handler", provenance: "heuristic" },
      ],
      fed_by: ["IB_A"],
      dynamic: false,
    },
  ],
  handlers: [
    {
      name: "xform_main",
      file: "/c/a.py",
      line: 30,
      sends: ["OB_Main"],
      edges: [{ target: "OB_Main", target_kind: "outbound", provenance: "literal" }],
      fed_by: ["route_a"],
      dynamic: false,
    },
    { name: "relay_dyn", file: "/c/a.py", line: 40, sends: [], edges: [], fed_by: ["route_a"], dynamic: true },
  ],
};

/** What wiringMap.ts post() sends: wiringMapPayload() over the provider's graph and focus. */
const MAP_OK: Payload = wiringMapPayload(GRAPH, { kind: "router", name: "route_a" });

const wiringMap: Receiver = {
  panel: "Wiring Map",
  key: "type",
  load: () =>
    page(
      wiringMapScript(TOKEN),
      `<span id="focusLbl"></span><input id="search" /><datalist id="elementNames"></datalist>
       <button id="refresh"></button><button id="reveal"></button>
       <div id="note">${SENTINEL}</div><div id="canvas"></div>`,
    ),
  wellFormed: {
    // With a graph, and before one is loaded (map and focus both null), which the host also posts.
    map: [MAP_OK, { ...wiringMapPayload(undefined, null) }],
  },
  malformed: {
    map: [
      ["no names", variant(MAP_OK, (c) => delete c.names)],
      ["a name has no kind", variant(MAP_OK, (c) => delete c.names[0].kind)],
      ["no focus field", variant(MAP_OK, (c) => delete c.focus)],
      ["focus is a string", variant(MAP_OK, (c) => (c.focus = "route_a"))],
      ["no map field", variant(MAP_OK, (c) => delete c.map)],
      ["three columns", variant(MAP_OK, (c) => c.map.columns.pop())],
      ["a column is not an array", variant(MAP_OK, (c) => (c.map.columns[1] = c.map.columns[1][0]))],
      ["a node's row is a string", variant(MAP_OK, (c) => (c.map.columns[1][0].row = "0"))],
      ["a node has no name", variant(MAP_OK, (c) => delete c.map.columns[0][0].name)],
      ["a node's open.line is a string", variant(MAP_OK, (c) => (c.map.columns[0][0].open.line = "3"))],
      ["an edge's provenance is a number", variant(MAP_OK, (c) => (c.map.edges[0].provenance = 1))],
      ["edges is missing", variant(MAP_OK, (c) => delete c.map.edges)],
      ["truncated is a string", variant(MAP_OK, (c) => (c.map.truncated = "no"))],
    ],
  },
};

const RECEIVERS: Receiver[] = [alertRules, codeSet, connection, home, security, sourceControl, wiringMap];

suite("webview receivers discard a malformed payload and render a well-formed one", () => {
  teardown(closeWindows);

  test("the suite covers seven receivers, and each covers every type it has a fixture for", () => {
    // Test Bench is the eighth receiver and has its own suite (test-bench-webview.test.ts).
    assert.strictEqual(RECEIVERS.length, 7);
    for (const r of RECEIVERS) {
      assert.deepStrictEqual(
        Object.keys(r.malformed).sort(),
        Object.keys(r.wellFormed).sort(),
        `${r.panel}: every handled type needs both a well-formed fixture and malformed cases`,
      );
    }
  });

  test("the fixtures the host builds are the shape the malformed cases assume", () => {
    // The malformed cases index into these; if the host's output drifted, a case would be testing
    // a shape that no longer exists rather than the one change it names.
    assert.ok(MAP_OK.map.columns[0][0].open, "the inbound node carries an open location");
    assert.ok(MAP_OK.map.edges.length > 0 && MAP_OK.names.length > 0);
    assert.ok(MAP_OK.map.columns.flat().some((n: Payload) => n.stub), "the dynamic handler yields a stub");
    assert.ok(FIELDS_OK.groups[0].fields.length > 0);
    assert.ok(FIELDS_OK.groups.flatMap((g) => g.fields).some((f) => f.envKey === "PEER_HOST"));
    assert.ok(SECURITY_SHOW.loosenings.length > 0);
  });

  test("Security Settings: Save stays off until a state renders, and a discarded state leaves it off", () => {
    // Before a state renders, the form holds placeholders, and saving them would write them as
    // explicit values. A discard must not leave the form looking loaded AND saveable.
    const p = security.load();
    const save = p.window.document.getElementById("save");
    assert.strictEqual(save.disabled, true, "Save was on before any state arrived");
    p.deliver(variant(STATE_OK, (c) => delete c.state.defaults));
    assert.strictEqual(save.disabled, true, "a discarded state turned Save on");
    p.deliver(STATE_OK);
    assert.strictEqual(save.disabled, false, "a well-formed state did not turn Save on");
  });

  for (const r of RECEIVERS) {
    for (const [type, fixtures] of Object.entries(r.wellFormed)) {
      test(`${r.panel}: ACCEPTS a well-formed "${type}"`, () => {
        // THE VACUITY CONTROL for every discard below on this receiver.
        for (const fixture of fixtures) {
          const p = r.load();
          const before = p.snapshot();
          p.deliver(fixture);
          assert.deepStrictEqual(p.errors.map(String), [], `${r.panel} "${type}": the page threw`);
          assert.notStrictEqual(p.snapshot(), before, `${r.panel} "${type}": a well-formed message changed nothing`);
          assert.deepStrictEqual(p.warnings, [], `${r.panel} "${type}": a well-formed message was named as discarded`);
        }
      });
    }

    for (const [type, cases] of Object.entries(r.malformed)) {
      // One test per case, so a failure names the case and the mutation control counts cases.
      for (const [why, payload] of cases) {
        test(`${r.panel}: DISCARDS "${type}" when ${why}`, () => {
          assert.strictEqual(payload[r.key], type, `${why}: the discriminator must stay intact`);
          const p = r.load();
          const before = p.snapshot();
          p.deliver(payload);
          // No-throw is half the discard: a receiver that crashed partway would also leave the page
          // alone, and would read here as a discard it is not. These two come BEFORE the console
          // check, so a switched-off discard fails on what the page did, not on a missing warning.
          assert.deepStrictEqual(p.errors.map(String), [], `${r.panel} "${type}", ${why}: the page threw`);
          assert.strictEqual(p.snapshot(), before, `${r.panel} "${type}", ${why}: the page changed`);
          assert.ok(
            p.warnings.some((w) => w.includes(`MessageFoundry ${r.panel}: discarded a malformed "${type}"`)),
            `${r.panel} "${type}", ${why}: the discard was not named in the console`,
          );
        });
      }
    }

    test(`${r.panel}: discards a message type it does not handle`, () => {
      const p = r.load();
      const before = p.snapshot();
      p.deliver({ [r.key]: "notAType", message: "x", text: "x" });
      assert.deepStrictEqual(p.errors.map(String), []);
      assert.strictEqual(p.snapshot(), before);
      assert.ok(
        p.warnings.some((w) => w.includes(`MessageFoundry ${r.panel}: discarded a malformed "notAType"`)),
        `${r.panel}: an unhandled type was not named in the console`,
      );
    });
  }
});
