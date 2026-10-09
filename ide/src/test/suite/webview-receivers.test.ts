// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { alertEditorScript } from "../../alertEditorWebview";
import { codeSetEditorScript } from "../../codeSetEditorWebview";
import { buildForm, type ConnectionSchema, type SchemaParam } from "../../connectionForm";
import { connectionEditorScript } from "../../connectionEditorWebview";
import type { Graph } from "../../graphModel";
import { homeScript } from "../../homeWebview";
import { FIELDS, securityEditorScript } from "../../securityEditorWebview";
import { sourceControlScript } from "../../sourceControlWebview";
import { CHANNEL_FIELD, SHAPE_HELPERS } from "../../webviewMessaging";
import { wiringMapPayload } from "../../wiringMapModel";
import { wiringMapScript } from "../../wiringMapWebview";

// ASVS 3.5.5 (BACKLOG #1123), the syntax half at the seven receivers other than Test Bench.
//
// mfTrusted() decides WHO sent a message. This suite pins the next step at each receiver: a message
// that is correctly stamped and carries a known discriminator, but whose payload is missing a
// required field or has one of the wrong JS type, is DISCARDED. Nothing on the page changes and
// nothing throws. Value ranges are a different requirement and are not tested here.
//
// One receiver SHOWS the discard: Security Settings, for a `state` (see its `shownDiscard`). An
// empty settings form with no reason given reads as a broken panel.
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
  /** Every message the page posted to the host. */
  readonly posted: Payload[];
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
  const posted: Payload[] = [];
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
    postMessage: (m: Payload) => void posted.push(m),
  });
  const el = window.document.createElement("script");
  el.textContent = script;
  window.document.body.appendChild(el);
  assert.deepStrictEqual(errors.map(String), [], "the panel script threw while loading");
  return {
    window,
    errors,
    warnings,
    posted,
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
  /** Per message type, for a receiver that SHOWS a discard, so the page does change. Called before
   *  the message is delivered; the check it returns runs after, in place of "the page is unchanged". */
  readonly shownDiscard?: Record<string, (p: Page) => () => void>;
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
 *  The row is the raw TOML table, and the engine's lax model loads that quoted number. The host's
 *  type for the field is `number | null`, so this is DISCARDED now (Manager ruling on MR2,
 *  2026-10-08): a present field has its declared type. It was a well-formed fixture before. */
const ALERT_RULES_QUOTED = [{ event_type: "queue_buildup", min_depth: "500", index: 0 }];

/** A rule with every optional field absent. `alert list` adds only the ordinal to the TOML table,
 *  so a bare `[[alerts.rules]]` arrives as this. */
const ALERT_RULES_BARE = [{ index: 0 }];

/** A rule carrying AlertRule keys the host's Rule does not name: recipients, id, mute and an
 *  escalate tier (AlertRule and EscalationTier, config/settings.py). Written by hand here, not
 *  recorded; the rule minus its index was checked once against AlertRule.model_validate. The
 *  receiver reads none of these keys and must not refuse a list for having them. */
const ALERT_RULES_EXTRA_KEYS = [
  {
    event_type: "queue_buildup",
    min_depth: 10,
    recipients: ["oncall@example.org"],
    id: "depth-page",
    mute: false,
    escalate: [{ after_count: 3, severity: "critical" }],
    index: 0,
  },
];

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
    rules: [
      ALERT_OK,
      { command: "rules", rules: ALERT_RULES_BARE },
      { command: "rules", rules: ALERT_RULES_EXTRA_KEYS },
      { command: "rules", rules: [] },
    ],
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
      // The host types the three numerics as number. A present one is a number or the list is discarded.
      ["min_depth is a quoted number", { command: "rules", rules: ALERT_RULES_QUOTED }],
      ["min_depth is a word", variant(ALERT_OK, (c) => (c.rules[0].min_depth = "abc"))],
      ["min_oldest_seconds is a boolean", variant(ALERT_OK, (c) => (c.rules[0].min_oldest_seconds = true))],
      ["cooldown_seconds is a quoted number", variant(ALERT_OK, (c) => (c.rules[1].cooldown_seconds = "300"))],
      // null is a value, not an absence. TOML has none, so "alert list" never prints one.
      ["min_depth is null", variant(ALERT_OK, (c) => (c.rules[0].min_depth = null))],
      ["min_oldest_seconds is null", variant(ALERT_OK, (c) => (c.rules[0].min_oldest_seconds = null))],
      ["cooldown_seconds is null", variant(ALERT_OK, (c) => (c.rules[1].cooldown_seconds = null))],
      ["transports is null", variant(ALERT_OK, (c) => (c.rules[0].transports = null))],
      ["event_type is null", variant(ALERT_OK, (c) => (c.rules[0].event_type = null))],
      ["connection is null", variant(ALERT_OK, (c) => (c.rules[0].connection = null))],
      ["severity is null", variant(ALERT_OK, (c) => (c.rules[0].severity = null))],
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
        // A heading too long for a title, so its group carries the full text as `description`.
        max_frame_bytes: param({
          type: "int",
          default: 1048576,
          section: "Inbound DoS guards: bounds on what one peer may make this listener hold in memory at once",
        }),
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
      ["cast is a number", variant(FIELDS_OK, (c) => (c.groups[0].fields[0].cast = 1))],
      ["description is a number", variant(FIELDS_OK, (c) => (c.groups[0].description = 1))],
      // FieldDescriptor.envKey and .cast, and FieldGroup.description, are `?: string`: absent or a
      // string. buildForm() sets each only when it has one, so null is never sent.
      ["envKey is null", variant(FIELDS_OK, (c) => (c.groups[0].fields[0].envKey = null))],
      ["cast is null", variant(FIELDS_OK, (c) => (c.groups[0].fields[0].cast = null))],
      ["description is null", variant(FIELDS_OK, (c) => (c.groups[0].description = null))],
      ["no choices", variant(FIELDS_OK, (c) => delete c.groups[0].fields[0].choices)],
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
 *  loosened switch (require_mfa = false), which is what securityEditor.ts refresh() posts. The
 *  require_mfa risk string was edited by hand on 2026-10-02 to the engine's corrected text (vault
 *  BACKLOG 1133); the rest is as recorded. */
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
      "risk": "an account with no second factor enrolled is single-factor, so a Kerberos session enters on a ticket that asserts no strength. An enrolled account owes its factor only while it keeps one, and its holder may remove the last. Where an OIDC sign-in carries an amr/acr claim checked while [auth].oidc_require_mfa_claim is on, that claim counts as the second factor, whether or not one is enrolled"
    }
  ],
  "loosenings_partial": false,
  "loosenings_scope": "settings only ([security]/[store]/[auth]/[alerts]/[secret_rotation]/[api]); the per-connection cleartext_accepted, tls_allow_expired, generic-ODBC database TLS, tls_hop_attested and tls_revocation_attested declarations are NOT included, and neither are the store-principal privilege and audit-chain keying observations (#1008, #1905 \u2014 this command opens no store, and neither does `check`; GET /security/posture reports both). These are the AUTHORED values, so a `serve --host` bind override on a running engine is not reflected here either \u2014 see `messagefoundry check` or GET /security/posture"
};

const STATE_OK = { command: "state", state: SECURITY_SHOW };

/** One switch of each FIELDS type. The absent-switch cases remove each from values and from defaults. */
const ONE_PER_TYPE: [string, string][] = [
  ["bool", "serve_web_console"],
  ["int", "max_session_hours"],
  ["string", "listen_address"],
  ["tristate", "production_instance"],
];

/** The live value of every control in the form, which is what Save would send. */
function formValues(p: Page): string {
  const controls = [...p.window.document.querySelectorAll("#form input, #form select")];
  return JSON.stringify(controls.map((c: DomNode) => [c.id, c.value]));
}

/** The text the panel is SHOWING in its error element, or "" while that element is hidden. Read
 *  through the computed style, because the page's own stylesheet hides `.error` (securityEditor.ts). */
function refusalShown(p: Page): string {
  const el = p.window.document.getElementById("error");
  const computed = (p.window.getComputedStyle as (e: DomNode) => { display: string })(el);
  return computed.display === "none" ? "" : String(el.textContent);
}

/** The rule securityEditor.ts formHtml() ships for the error element, and the element as it ships.
 *  That file imports `vscode`, so it cannot be loaded here; a test below reads its text instead and
 *  fails if this rule or that element is no longer in it. */
const SECURITY_ERROR_RULE = ".error { display: none;";
const SECURITY_ERROR_ELEMENT = '<div id="error" class="error">';
const SECURITY_ERROR_CSS = `<style>${SECURITY_ERROR_RULE} }</style>`;
function securityBody(seed: string): string {
  return `${SECURITY_ERROR_CSS}<div id="form"></div>${SECURITY_ERROR_ELEMENT}${seed}</div>
       <button id="save"></button><button id="close"></button>`;
}
const REFUSAL = "These settings cannot be shown.";

const security: Receiver = {
  panel: "Security Settings",
  key: "command",
  load: () =>
    page(securityEditorScript(TOKEN, FIELDS), securityBody(SENTINEL)),
  wellFormed: { state: [STATE_OK], error: [ERROR_OK] },
  shownDiscard: {
    // A discarded state is SHOWN (BACKLOG #1123), so the page changes. What must hold instead: no
    // control took a value from the message, the form is hidden, the refusal is up, Save is off.
    state: (p) => {
      const before = formValues(p);
      return () => {
        const doc = p.window.document;
        assert.strictEqual(formValues(p), before, "a control took a value from a discarded state");
        assert.strictEqual(doc.getElementById("form").style.display, "none", "the form stayed up");
        assert.ok(refusalShown(p).startsWith(REFUSAL), `no refusal on the page: "${refusalShown(p)}"`);
        assert.strictEqual(doc.getElementById("save").disabled, true, "Save is on after a discard");
      };
    },
  },
  malformed: {
    state: [
      ["no state", variant(STATE_OK, (c) => delete c.state)],
      ["state is an array", variant(STATE_OK, (c) => (c.state = [c.state]))],
      ["no values", variant(STATE_OK, (c) => delete c.state.values)],
      ["defaults is a string", variant(STATE_OK, (c) => (c.state.defaults = "secure"))],
      ["set is a string", variant(STATE_OK, (c) => (c.state.set = "require_mfa"))],
      ["a loosening has no risk", variant(STATE_OK, (c) => delete c.state.loosenings[0].risk)],
      ["loosenings is an object", variant(STATE_OK, (c) => (c.state.loosenings = c.state.loosenings[0]))],
      // ShowResult.set and .loosenings are required, and "security show" always prints both. The
      // page reads neither, and a state without one is still not the message the host declares.
      ["no set", variant(STATE_OK, (c) => delete c.state.set)],
      ["no loosenings", variant(STATE_OK, (c) => delete c.state.loosenings)],
      ["set is null", variant(STATE_OK, (c) => (c.state.set = null))],
      ["loosenings is null", variant(STATE_OK, (c) => (c.state.loosenings = null))],
      // One per FIELDS type, on values and on defaults (BACKLOG #2447). Types only, never ranges.
      ["a bool value is a string", variant(STATE_OK, (c) => (c.state.values.require_mfa = "false"))],
      ["a bool value is null", variant(STATE_OK, (c) => (c.state.values.local_access_only = null))],
      ["an int value is a string", variant(STATE_OK, (c) => (c.state.values.max_session_hours = "12"))],
      ["an int value is fractional", variant(STATE_OK, (c) => (c.state.values.max_session_hours = 1.5))],
      // null is not "absent": an empty number control reads back as 0, which here means keep forever.
      ["an int value is null", variant(STATE_OK, (c) => (c.state.values.delete_message_bodies_after_days = null))],
      ["a string value is null", variant(STATE_OK, (c) => (c.state.values.listen_address = null))],
      ["a string value is a number", variant(STATE_OK, (c) => (c.state.values.listen_address = 127))],
      ["a tristate value is a string", variant(STATE_OK, (c) => (c.state.values.production_instance = "true"))],
      ["a bool default is a number", variant(STATE_OK, (c) => (c.state.defaults.require_mfa = 1))],
      ["an int default is a string", variant(STATE_OK, (c) => (c.state.defaults.delete_message_bodies_after_days = "30"))],
      ["a string default is an array", variant(STATE_OK, (c) => (c.state.defaults.listen_address = ["127.0.0.1"]))],
      ["a tristate default is a number", variant(STATE_OK, (c) => (c.state.defaults.production_instance = 0))],
      // An ABSENT switch, one per FIELDS type, in each object (BACKLOG #1123). "security show" dumps
      // the whole settings model twice, so no switch is ever legitimately missing from either.
      ...ONE_PER_TYPE.flatMap(([type, key]): [string, Payload][] => [
        [`values has no ${type} switch`, variant(STATE_OK, (c) => delete c.state.values[key])],
        [`defaults has no ${type} switch`, variant(STATE_OK, (c) => delete c.state.defaults[key])],
      ]),
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
      // MapNode.port, .open and .stub are `?:` with no null. buildWiringMap() sets each only when it
      // has one, so null is never sent.
      ["a node's port is null", variant(MAP_OK, (c) => (c.map.columns[0][0].port = null))],
      ["a node's open is null", variant(MAP_OK, (c) => (c.map.columns[0][0].open = null))],
      ["a node's stub is null", variant(MAP_OK, (c) => (c.map.columns[0][0].stub = null))],
      ["a node's port is a number", variant(MAP_OK, (c) => (c.map.columns[0][0].port = 6661))],
      ["a node's stub is a string", variant(MAP_OK, (c) => (c.map.columns[0][0].stub = "yes"))],
      // map and focus are the other way round: required, and null is declared. Absent is refused
      // above ("no map field", "no focus field"); null renders (the second well-formed fixture).
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

  test("absent-ok and null-ok are separate declarations, and a field may be both", () => {
    // SHAPE_HELPERS is the source every receiver embeds, so this runs the shipped helpers.
    type Check = (x: unknown) => boolean;
    const h = new Function(`${SHAPE_HELPERS}; return { mfOpt, mfNullable, mfStr };`)() as {
      mfOpt(x: unknown, f: Check): boolean;
      mfNullable(x: unknown, f: Check): boolean;
      mfStr: Check;
    };
    const modes: [string, Check, boolean[]][] = [
      // What each accepts of: a string, undefined, null, a number.
      ["neither", h.mfStr, [true, false, false, false]],
      ["absent-ok", (x) => h.mfOpt(x, h.mfStr), [true, true, false, false]],
      ["null-ok", (x) => h.mfNullable(x, h.mfStr), [true, false, true, false]],
      ["both", (x) => h.mfOpt(x, (v) => h.mfNullable(v, h.mfStr)), [true, true, true, false]],
    ];
    for (const [mode, check, want] of modes) {
      assert.deepStrictEqual(["s", undefined, null, 7].map(check), want, mode);
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
    // The really-sent controls for the optional fields: each ACCEPTS fixture must carry the field
    // present AND absent, or a check that refused one of the two would go unseen.
    const fields = FIELDS_OK.groups.flatMap((g) => g.fields);
    assert.ok(fields.some((f) => typeof f.envKey === "string" && typeof f.cast === "string"));
    assert.ok(fields.some((f) => !("envKey" in f) && !("cast" in f)));
    assert.ok(FIELDS_OK.groups.some((g) => typeof g.description === "string"), "no group has a description");
    assert.ok(FIELDS_OK.groups.some((g) => !("description" in g)));
    assert.ok(fields.some((f) => f.choices === null) && fields.some((f) => Array.isArray(f.choices)));
    const nodes: Payload[] = MAP_OK.map.columns.flat();
    assert.ok(nodes.some((n) => typeof n.port === "string") && nodes.some((n) => !("port" in n)));
    assert.ok(nodes.some((n) => n.open) && nodes.some((n) => !("open" in n)));
    assert.ok(nodes.some((n) => n.stub === true) && nodes.some((n) => !("stub" in n)));
    assert.strictEqual(typeof MAP_OK.map.columns[0][0].port, "string", "the inbound node carries a port");
    assert.ok(ALERT_RULES.some((r) => "min_depth" in r) && ALERT_RULES.some((r) => !("min_depth" in r)));
    assert.ok(Array.isArray(SECURITY_SHOW.set));
  });

  test("Security Settings: Save stays off until a state renders, and a discarded state turns it off again", () => {
    // Before a state renders, the form holds placeholders, and saving them would write them as
    // explicit values. A discard must not leave the form looking loaded AND saveable.
    const p = security.load();
    const doc = p.window.document;
    const save = doc.getElementById("save");
    assert.strictEqual(save.disabled, true, "Save was on before any state arrived");
    p.deliver(variant(STATE_OK, (c) => delete c.state.defaults));
    assert.strictEqual(save.disabled, true, "a discarded state turned Save on");
    p.deliver(STATE_OK);
    assert.strictEqual(save.disabled, false, "a well-formed state did not turn Save on");
    // A state discarded AFTER one rendered: the form now holds values nobody can vouch for.
    p.deliver(variant(STATE_OK, (c) => delete c.state.values.require_mfa));
    assert.strictEqual(save.disabled, true, "Save stayed on over a stale form");
    assert.strictEqual(doc.getElementById("form").style.display, "none", "the stale form stayed up");
    // And the next well-formed state brings all of it back.
    p.deliver(STATE_OK);
    assert.strictEqual(save.disabled, false);
    assert.strictEqual(doc.getElementById("form").style.display, "");
    assert.strictEqual(refusalShown(p), "", "the refusal outlived the state that replaced it");
  });

  test("Security Settings: a discarded state names the switch and what was wrong with it", () => {
    // BACKLOG #1123. The operator sees why the panel is empty, not only the webview console.
    // Every case that can carry text sends this marker as the bad value. None may echo it.
    const SENT = "SENT_IN_THE_MESSAGE";
    const cases: [string, (c: Payload) => void, string][] = [
      ...ONE_PER_TYPE.flatMap(([, key]): [string, (c: Payload) => void, string][] => [
        [`values.${key} absent`, (c) => delete c.state.values[key], `values.${key} is missing`],
        [`defaults.${key} absent`, (c) => delete c.state.defaults[key], `defaults.${key} is missing`],
      ]),
      ["a bool that is a string", (c) => (c.state.values.require_mfa = SENT), "values.require_mfa must be true or false, got string"],
      ["an int that is a string", (c) => (c.state.values.max_session_hours = SENT), "values.max_session_hours must be a whole number, got string"],
      ["an int that is a fraction", (c) => (c.state.defaults.max_session_hours = 12.5), "defaults.max_session_hours must be a whole number, got a fraction"],
      ["an int past 2^53", (c) => (c.state.defaults.max_session_hours = 2 ** 60), "defaults.max_session_hours must be a whole number, got a number too large"],
      ["an int that is null", (c) => (c.state.defaults.max_session_hours = null), "defaults.max_session_hours must be a whole number, got null"],
      ["a string that is a list", (c) => (c.state.values.listen_address = [SENT]), "values.listen_address must be text, got list"],
      ["a string that is an object", (c) => (c.state.defaults.listen_address = { [SENT]: SENT }), "defaults.listen_address must be text, got object"],
      ["a tristate that is a string", (c) => (c.state.values.production_instance = SENT), "values.production_instance must be true, false or null, got string"],
      ["a tristate that is a number", (c) => (c.state.values.production_instance = 0), "values.production_instance must be true, false or null, got number"],
      ["no values object", (c) => delete c.state.values, "values is missing or is not an object"],
      ["no set", (c) => delete c.state.set, "set is missing or is not a list of text"],
      ["loosenings is null", (c) => (c.state.loosenings = null), "loosenings is missing or is not a list of switch and risk entries"],
      ["no state", (c) => delete c.state, "state is missing or is not an object"],
    ];
    for (const [why, change, problem] of cases) {
      const p = security.load();
      p.deliver(variant(STATE_OK, change));
      assert.deepStrictEqual(p.errors.map(String), [], `${why}: the page threw`);
      const shown = refusalShown(p);
      assert.ok(shown.startsWith(REFUSAL), `${why}: no refusal, got "${shown}"`);
      assert.ok(shown.includes(problem), `${why}: the refusal does not say "${problem}": "${shown}"`);
      assert.ok(p.warnings.some((w) => w.includes('discarded a malformed "state"')), `${why}: console.warn was dropped`);
      // The message's own values are never echoed: the refusal names a kind, not what was sent.
      assert.ok(!shown.includes(SENT), `${why}: the refusal echoed a value from the message`);
    }
  });

  test("Security Settings: the test page hides its error element by the rule the panel ships", () => {
    // refusalShown() reads a computed style under a COPY of the panel's rule. This ties the copy to
    // the source: if formHtml() changes how it hides the element, this fails and the copy is redone.
    const host = fs.readFileSync(path.resolve(__dirname, "../../../src/securityEditor.ts"), "utf8");
    assert.ok(host.includes(SECURITY_ERROR_RULE), "securityEditor.ts no longer hides .error this way");
    assert.ok(host.includes(SECURITY_ERROR_ELEMENT), "securityEditor.ts no longer ships this error element");
  });

  test("Security Settings: an error that follows a refusal keeps the reason on the page", () => {
    const p = security.load();
    p.deliver(variant(STATE_OK, (c) => delete c.state.values.require_mfa));
    p.deliver(ERROR_OK);
    const shown = refusalShown(p);
    assert.ok(shown.startsWith(REFUSAL) && shown.includes("values.require_mfa is missing"), shown);
    assert.ok(shown.includes(CLI_ERROR), "the new error was dropped");
    // The control: once a state renders, an error shows alone.
    p.deliver(STATE_OK);
    p.deliver(ERROR_OK);
    assert.strictEqual(refusalShown(p), CLI_ERROR);
  });

  test("Security Settings: a switch name with markup in it reaches the refusal as text", () => {
    // The refusal is built with textContent. A name that would be an element if it were parsed as
    // HTML must arrive as characters, and must add no element to the page.
    const key = '<img src=x onerror="window.pwned=1"><b id="planted">';
    const p = page(
      securityEditorScript(TOKEN, [{ key, label: "A switch", desc: "", type: "bool", group: "G" }]),
      securityBody(""),
    );
    const doc = p.window.document;
    // The control: with the switch present this form renders, so the refusal below is about its absence.
    p.deliver({ command: "state", state: { values: { [key]: true }, defaults: { [key]: true }, set: [], loosenings: [] } });
    assert.strictEqual(doc.getElementById("save").disabled, false, "the control state did not render");
    assert.strictEqual(refusalShown(p), "", "the error element is showing before any refusal");
    p.deliver({ command: "state", state: { values: {}, defaults: { [key]: true }, set: [], loosenings: [] } });
    const error = doc.getElementById("error");
    assert.ok(refusalShown(p).includes(`values.${key} is missing`), `shown: "${refusalShown(p)}"`);
    assert.strictEqual(error.children.length, 0, "the switch name was parsed as markup");
    assert.strictEqual(doc.getElementById("planted"), null);
    assert.strictEqual(p.window.pwned, undefined);
    assert.deepStrictEqual(p.errors.map(String), []);
  });

  test("Security Settings: Save posts nothing after a discard, and posts the form after a complete state", () => {
    const p = security.load();
    const doc = p.window.document;
    const save = doc.getElementById("save");
    p.deliver(variant(STATE_OK, (c) => delete c.state.values.serve_web_console));
    save.click();
    assert.strictEqual(p.posted.length, 0, "Save posted from a form no state had rendered");
    // THE CONTROL: the complete recording renders, and Save sends one entry per switch. Only the
    // switch that differs from its default (require_mfa) is an explicit set; the rest are removals.
    p.deliver(STATE_OK);
    assert.strictEqual(refusalShown(p), "");
    save.click();
    assert.strictEqual(p.posted.length, 1, "Save did not post after a complete state");
    assert.strictEqual(p.posted[0].command, "save");
    assert.deepStrictEqual(Object.keys(p.posted[0].updates).sort(), FIELDS.map((f) => f.key).sort());
    const sets = Object.entries(p.posted[0].updates).filter(([, v]) => v !== null);
    assert.deepStrictEqual(sets, [["require_mfa", false]]);
    // A discard after that: Save is off again, and a click sends nothing more.
    p.deliver(variant(STATE_OK, (c) => delete c.state.defaults.max_session_hours));
    save.click();
    assert.strictEqual(p.posted.length, 1, "Save posted from a stale form");
  });

  test("Security Settings: a key this form has no switch for, and a tristate that is set, still render", () => {
    // Extra keys are never read, so they are never checked: the recording itself carries a dozen
    // (enforcement, organization_domains, ...). This is also the control for the absent-switch
    // cases: what they refuse is a MISSING switch, not any state that differs from the recording.
    for (const [why, change] of [
      ["an unknown key of another type", (c: Payload) => { c.state.values.a_future_switch = { nested: [1] }; c.state.defaults.a_future_switch = 7; }],
      ["a tristate that is set", (c: Payload) => { c.state.values.production_instance = true; }],
      ["an empty set and no loosening, which a file with no [security] table prints", (c: Payload) => { c.state.set = []; c.state.loosenings = []; }],
    ] as [string, (c: Payload) => void][]) {
      const p = security.load();
      p.deliver(variant(STATE_OK, change));
      assert.deepStrictEqual(p.errors.map(String), [], `${why}: the page threw`);
      assert.deepStrictEqual(p.warnings, [], `${why}: discarded`);
      assert.strictEqual(p.window.document.getElementById("save").disabled, false, `${why}: did not render`);
    }
  });

  test("Security Settings: every retention acknowledgement the engine reports has its own switch", () => {
    // Vault BACKLOG #2280. The keys come from the recorded "security show", not from FIELDS, so a
    // switch in that recording with no editor entry fails here. The recording does not follow the
    // engine; tests/test_security_config.py is what reds when the engine gains a switch.
    const keys = Object.keys(SECURITY_SHOW.values).filter((k) => /^allow_keeping_.+_indefinitely$/.test(k));
    assert.ok(keys.length >= 5, "the fixture lost a retention acknowledgement");
    const p = security.load();
    const doc = p.window.document;
    p.deliver(variant(STATE_OK, (c) => { for (const k of keys) { c.state.values[k] = true; } }));
    for (const k of keys) {
      const field = FIELDS.find((f) => f.key === k);
      assert.ok(field, `${k}: no FIELDS entry`);
      assert.strictEqual(field.insecure, true, `${k}: true must read as a loosening`);
      assert.ok(field.risk, `${k}: a loosening needs its risk text`);
      assert.strictEqual(doc.getElementById("in-" + k).value, "true", `${k}: the state did not reach its control`);
      assert.ok(doc.getElementById("field-" + k).classList.contains("loosened"), `${k}: not marked loosened`);
    }
    // The control: at the recorded values (all false) none is marked.
    p.deliver(STATE_OK);
    for (const k of keys) {
      assert.ok(!doc.getElementById("field-" + k).classList.contains("loosened"), `${k}: marked while off`);
    }
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
          const shown = r.shownDiscard?.[type]?.(p);
          const before = p.snapshot();
          p.deliver(payload);
          // No-throw is half the discard: a receiver that crashed partway would also leave the page
          // alone, and would read here as a discard it is not. These two come BEFORE the console
          // check, so a switched-off discard fails on what the page did, not on a missing warning.
          assert.deepStrictEqual(p.errors.map(String), [], `${r.panel} "${type}", ${why}: the page threw`);
          if (shown) {
            shown();
          } else {
            assert.strictEqual(p.snapshot(), before, `${r.panel} "${type}", ${why}: the page changed`);
          }
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
