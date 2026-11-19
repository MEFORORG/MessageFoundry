// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { buildForm, type ConnectionSchema, type SchemaParam } from "../../connectionForm";
import { connectionEditorScript } from "../../connectionEditorWebview";
import { CHANNEL_FIELD, openChannel, postToSameRender, requestToken } from "../../webviewMessaging";

// BACKLOG #5565. Editing or cloning a connection drew the settings as legacy free-text rows from the
// raw record, even when the engine had described itself. So an inline credential showed in a
// cleartext input, and a table-valued setting showed and saved as "[object Object]". Edit and clone
// now draw the same schema-driven controls create does, and the legacy rows (an engine that cannot
// describe itself) show a table as JSON and parse it back.
//
// The connection editor's REAL script runs in a jsdom page, as in webview-receivers.test.ts, so
// what runs here is what ships. Node-side only: no `vscode` import, so this runs on the unit leg.
// All values are synthetic.

interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib (see webview-receivers.test.ts).
  [key: string]: any;
}
interface JsdomWindow {
  document: DomNode;
  origin: string;
  MessageEvent: new (type: string, init?: Record<string, unknown>) => unknown;
  Event: new (type: string) => unknown;
  dispatchEvent(event: unknown): boolean;
  close(): void;
  [key: string]: unknown;
}
interface JsdomModule {
  JSDOM: new (html: string, options?: Record<string, unknown>) => { window: JsdomWindow };
  VirtualConsole: new () => { on(event: string, handler: (...args: unknown[]) => void): void };
}
const { JSDOM, VirtualConsole } = require("jsdom") as JsdomModule;

type Payload = Record<string, any>;

const TOKEN = "PREFILLtokenPREFILLtok0";
const SECRET = "synthetic-inline-credential-5565";
const INLINE_DEFAULT = "synthetic-env-default-5565";
const OFFDIR_VALUE = "synthetic-off-direction-5565";

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
        host: param({ env: true }),
        port: param({ type: "int", env: true }),
        tls_key_password: param({ secret: true }),
        headers: param({ type: "table" }),
        // Not on the record: an untouched save must not write the default.
        tls: param({ type: "bool", default: false }),
        mode: param({ choices: ["fifo", "unordered"], default: "fifo" }),
        facility: param({}),
        suffix: param({ default: "x" }),
        verify: param({ type: "bool", default: true }),
        db_password: param({ secret: true }),
        // Applies inbound only: on this outbound record it is drawn off-direction.
        listen_secret: param({ secret: true, direction: "inbound" }),
        poll_statement: param({}),
        keepalive: param({ type: "bool", default: false }),
      },
    },
    file: {
      doc: "Files on disk.",
      params: { path: param({}) },
    },
  },
  directionKeys: {
    inbound: ["name", "transport", "settings", "router"],
    outbound: ["name", "transport", "settings", "retry"],
  },
};

/** An outbound record with an inline credential, a table setting, an env reference with a default,
 *  a table the schema does not describe that happens to carry an "env" key, a value outside a
 *  select's choices, a str of digits, and a str set to empty on purpose. */
const RECORD = {
  direction: "outbound",
  name: "OB_SYNTH_ADT",
  transport: "mllp",
  settings: {
    host: { env: "PEER_HOST", default: "localhost" },
    port: 6661,
    tls_key_password: SECRET,
    headers: { "X-Feed": "adt", "X-Tier": "test" },
    routing: { env: "PROD", weight: 2 },
    mode: "FIFO",
    facility: "0042",
    suffix: "",
    // Not a boolean: the engine refuses it at load, and an untouched save must not turn it into one.
    verify: "yes",
    // A secret env reference whose default is itself an inline credential.
    db_password: { env: "DB_PW", default: INLINE_DEFAULT },
    listen_secret: OFFDIR_VALUE,
    // A text input strips line breaks from what it is given; an untouched save must keep them.
    poll_statement: "-- new rows\nSELECT id, payload\nFROM mf_inbox",
    // A recorded bool: a checkbox has no empty state, so only a remove control can drop the key.
    keepalive: true,
  },
};

interface Page {
  readonly window: JsdomWindow;
  readonly posted: Payload[];
  /** Deliver a message from the host, stamped as webview-receivers.test.ts stamps one. */
  deliver(data: Payload): void;
}

const openWindows: JsdomWindow[] = [];
function closeWindows(): void {
  for (const w of openWindows.splice(0)) {
    w.close();
  }
}

function load(opts: {
  clone?: boolean;
  groups: unknown;
  initial?: unknown;
  transports?: string[];
  fieldGroupsFor?: { transport: string; direction: string };
}): Page {
  const errors: unknown[] = [];
  const posted: Payload[] = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e: unknown) => errors.push(e));
  const dom = new JSDOM(
    `<!DOCTYPE html><body>
     <div id="conn-picker-row"><select id="connPicker"></select></div><h2 id="title"></h2>
     <select id="direction"><option value="inbound">in</option><option value="outbound">out</option></select>
     <select id="transport"></select><input id="name" />
     <div id="router-row"><select id="router"></select></div>
     <div id="settings"></div><button id="addSetting"></button>
     <div id="inbound-opts"><select id="ackMode"><option value="">o</option></select>
       <input type="checkbox" id="strict" /></div>
     <div id="outbound-opts"><select id="ordering"><option value="">f</option></select>
       <input id="maxAttempts" /></div>
     <div id="error"></div>
     <button id="save"></button><button id="cancel"></button><button id="delete"></button></body>`,
    { runScripts: "dangerously", virtualConsole, url: "https://localhost/" },
  );
  const window = dom.window;
  openWindows.push(window);
  window.acquireVsCodeApi = () => ({
    getState: () => null,
    setState: () => undefined,
    postMessage: (m: Payload) => void posted.push(m),
  });
  const el = window.document.createElement("script");
  el.textContent = connectionEditorScript(TOKEN, {
    // null is create mode; absent is RECORD.
    initial: opts.initial === undefined ? RECORD : opts.initial,
    routers: ["route_adt"],
    transports: opts.transports ?? ["mllp", "file"],
    fieldGroups: opts.groups,
    fieldGroupsFor: opts.fieldGroupsFor ?? null,
    siblings: undefined,
    clone: opts.clone,
  });
  window.document.body.appendChild(el);
  assert.deepStrictEqual(errors.map(String), [], "the editor script threw while loading");
  return {
    window,
    posted,
    deliver(data): void {
      window.dispatchEvent(
        new window.MessageEvent("message", {
          origin: window.origin,
          source: null,
          data: { ...data, [CHANNEL_FIELD]: TOKEN },
        }),
      );
      assert.deepStrictEqual(errors.map(String), [], "the editor script threw handling a message");
    },
  };
}

/** Every text-bearing control in the settings area, as the user sees it. */
function shownValues(p: Page): string[] {
  return [...p.window.document.querySelectorAll("#settings input, #settings select")].map(
    (c: DomNode) => String(c.value),
  );
}

/** Click Save (giving a clone its new name first) and return the settings it posted. */
function saved(p: Page, clone: boolean): Payload {
  if (clone) {
    p.window.document.getElementById("name").value = "OB_SYNTH_ADT_COPY";
  }
  p.window.document.getElementById("save").click();
  const save = p.posted.filter((m) => m.command === "save");
  assert.strictEqual(save.length, 1, `expected one save post: ${JSON.stringify(p.posted)}`);
  // Through JSON, as the post crosses to the host: the page's objects belong to jsdom's realm, and
  // deepStrictEqual compares prototypes as well as values.
  return JSON.parse(JSON.stringify(save[0].conn.settings)) as Payload;
}

/** Pick another outbound transport and deliver the host's rebuild of what the request sent. */
function switchTransport(p: Page, to: string): void {
  const transport = p.window.document.getElementById("transport");
  transport.value = to;
  transport.dispatchEvent(new p.window.Event("change"));
  const asked = p.posted.filter((m) => m.command === "fields");
  p.deliver({ command: "fields", groups: buildForm(SCHEMA, to, "outbound", asked[asked.length - 1].settings) });
}

suite("connection editor — edit and clone use the schema-driven fields (BACKLOG #5565)", () => {
  teardown(closeWindows);

  const groups = buildForm(SCHEMA, "mllp", "outbound", RECORD.settings);

  for (const clone of [false, true]) {
    const mode = clone ? "clone" : "edit";

    test(`${mode}: the inline credential is not shown in any input`, () => {
      const p = load({ clone, groups });
      const shown = shownValues(p);
      assert.ok(shown.length > 0, "the settings area drew no controls at all");
      for (const v of shown) {
        assert.ok(!v.includes(SECRET), `the credential is shown in cleartext: ${v}`);
      }
      assert.ok(
        !p.window.document.getElementById("settings").innerHTML.includes(SECRET),
        "the credential is written into the settings markup",
      );
    });

    test(`${mode}: the settings are the schema-driven controls, not legacy free-text rows`, () => {
      const p = load({ clone, groups });
      const doc = p.window.document;
      assert.strictEqual(doc.querySelectorAll("#settings .setting").length, 0, "legacy rows were drawn");
      const keys = [...doc.querySelectorAll("#settings [data-key]")].map((c: DomNode) => c.dataset.key);
      for (const key of Object.keys(RECORD.settings)) {
        assert.ok(keys.includes(key), `no control for ${key}: ${keys.join(", ")}`);
      }
    });

    test(`${mode}: an untouched save writes every recorded setting back as it was, and nothing more`, () => {
      const p = load({ clone, groups });
      const settings = saved(p, clone);
      // The table survives as a table, never "[object Object]" or a JSON string. The env
      // reference keeps its default; the select keeps a value outside its choices; the str of
      // digits stays a str; the explicit empty string stays.
      // The multi-line str keeps its line breaks.
      const { tls_key_password: _s, db_password: _r, listen_secret: _o, ...rest } = RECORD.settings;
      const { tls_key_password: written, db_password: ref, listen_secret: offDirection, ...others } = settings;
      assert.deepStrictEqual(others, rest);
      // An edit keeps the credentials the form never showed. A clone does not copy them, nor a
      // secret env reference's inline default: the GUI must not be what writes a new inline credential.
      assert.strictEqual(written, clone ? undefined : SECRET);
      assert.strictEqual(offDirection, clone ? undefined : OFFDIR_VALUE);
      assert.deepStrictEqual(ref, clone ? { env: "DB_PW" } : RECORD.settings.db_password);
    });
  }

  test("edit: an inline credential can be removed, and kept again", () => {
    const p = load({ groups });
    const remove = p.window.document.querySelector('#settings [data-remove-secret="tls_key_password"]');
    assert.ok(remove, "no way to remove the held inline credential");
    remove.click();
    assert.ok(!("tls_key_password" in saved(p, false)), "a removed credential must not be written back");
    // And the toggle undoes it.
    const q = load({ groups });
    const button = q.window.document.querySelector('#settings [data-remove-secret="tls_key_password"]');
    button.click();
    button.click();
    assert.strictEqual(saved(q, false).tls_key_password, SECRET);
  });

  test("clone: no remove button, since a clone never copies the credential", () => {
    const p = load({ clone: true, groups });
    assert.strictEqual(p.window.document.querySelectorAll("[data-remove-secret]").length, 0);
  });

  test("edit: typing an environment key replaces the held credential", () => {
    const p = load({ groups });
    const box = p.window.document.querySelector('#settings [data-key="tls_key_password"]');
    box.value = "TLS_KEY_PASSWORD";
    assert.deepStrictEqual(saved(p, false).tls_key_password, { env: "TLS_KEY_PASSWORD" });
  });

  test("edit: an edited field is read by its declared type", () => {
    const p = load({ groups });
    const doc = p.window.document;
    doc.querySelector('#settings [data-key="facility"]').value = "007";
    doc.querySelector('#settings [data-key="port"]').value = "6662";
    doc.querySelector('#settings [data-key="headers"]').value = '{"X-Feed":"orm"}';
    const settings = saved(p, false);
    assert.strictEqual(settings.facility, "007", "a str stays text");
    assert.strictEqual(settings.port, 6662);
    assert.deepStrictEqual(settings.headers, { "X-Feed": "orm" });
  });

  test("edit: text typed into a number field that is not a number is posted, never read as a removal", () => {
    // A number input sanitizes text it cannot parse to "", which the save read as an emptied box,
    // so the recorded key was silently dropped instead of the typed text reaching the engine's
    // validator.
    const p = load({ groups });
    const port = p.window.document.querySelector('#settings [data-key="port"]');
    assert.strictEqual(port.type, "text", "a number field must not be a number box");
    port.value = "66x2";
    assert.strictEqual(saved(p, false).port, "66x2", "the typed text must be posted for the engine to refuse");
    // Text a number box would have refused is not converted either: the engine sees what was typed.
    for (const typed of ["0x1F90", "0b1", "0o17", "+6662", "Infinity", "1e400", "-1e309", "12345678901234567891"]) {
      const h = load({ groups });
      h.window.document.querySelector('#settings [data-key="port"]').value = typed;
      assert.strictEqual(saved(h, false).port, typed, `${typed} must be posted as typed`);
    }
    // A number still reads back as a number.
    const q = load({ groups });
    q.window.document.querySelector('#settings [data-key="port"]').value = " 6663 ";
    assert.strictEqual(saved(q, false).port, 6663);
    // The explicit Remove still removes.
    const r = load({ groups });
    r.window.document.querySelector('#settings [data-key="port"]').value = "66x2";
    r.window.document.querySelector('#settings [data-remove-key="port"]').click();
    assert.ok(!("port" in saved(r, false)), "Remove must still remove");
  });

  test("edit: an inline credential removed during a transport round trip is not written back", () => {
    const p = load({ groups });
    const transport = p.window.document.getElementById("transport");
    const switchTo = (to: string): void => {
      transport.value = to;
      transport.dispatchEvent(new p.window.Event("change"));
      const asked = p.posted.filter((m) => m.command === "fields");
      p.deliver({ command: "fields", groups: buildForm(SCHEMA, to, "outbound", asked[asked.length - 1].settings) });
    };
    switchTo("file");
    const remove = p.window.document.querySelector('#settings [data-remove-key="tls_key_password"]');
    assert.ok(remove, "the held credential has no remove control on the file transport");
    remove.click();
    switchTo("mllp");
    assert.ok(!("tls_key_password" in saved(p, false)), "the removed credential came back on save");
  });

  test("edit: a secret env reference given another key does not take its inline default", () => {
    for (const typed of ["DB_PW2", " DB_PW3 "]) {
      const p = load({ groups });
      p.window.document.querySelector('#settings [data-key="db_password"]').value = typed;
      assert.deepStrictEqual(saved(p, false).db_password, { env: typed.trim() }, `a replaced key kept the old default: ${typed}`);
    }
  });

  test("edit: a removed setting kept again while its rebuild is pending never writes the raw credential", () => {
    for (const clone of [false, true]) {
      const p = load({ clone, groups });
      const doc = p.window.document;
      const drop = doc.querySelector('#settings [data-remove-key="db_password"]');
      drop.click();
      const transport = doc.getElementById("transport");
      transport.value = "file";
      transport.dispatchEvent(new p.window.Event("change"));
      // No reply arrives; the user keeps the setting again and saves.
      drop.click();
      if (!clone) {
        doc.querySelector('#settings [data-key="db_password"]').value = "DB_PW2";
      }
      const written = saved(p, clone).db_password;
      assert.ok(!JSON.stringify(written).includes(INLINE_DEFAULT), `${clone ? "clone" : "edit"} wrote the raw credential`);
    }
  });

  test("edit: an untouched save keeps an inline default recorded under a key with surrounding whitespace", () => {
    // A text box keeps spaces but strips line breaks, so both shapes are what an untouched box shows.
    for (const env of [" DB_PW ", "DB_\r\nPW"]) {
      const initial = { ...RECORD, settings: { ...RECORD.settings, db_password: { env, default: INLINE_DEFAULT } } };
      const p = load({ groups: buildForm(SCHEMA, "mllp", "outbound", initial.settings), initial });
      assert.strictEqual(saved(p, false).db_password.default, INLINE_DEFAULT, `an untouched save dropped the credential: ${JSON.stringify(env)}`);
    }
  });

  test("edit: the original key typed back after a transport round trip keeps the inline default", () => {
    const p = load({ groups });
    const doc = p.window.document;
    const box = (): DomNode => doc.querySelector('#settings [data-key="db_password"]');
    box().value = "DB_PW2";
    const transport = doc.getElementById("transport");
    for (const to of ["file", "mllp"]) {
      transport.value = to;
      transport.dispatchEvent(new p.window.Event("change"));
      const asked = p.posted.filter((m) => m.command === "fields");
      p.deliver({ command: "fields", groups: buildForm(SCHEMA, to, "outbound", asked[asked.length - 1].settings) });
    }
    box().value = "DB_PW";
    assert.deepStrictEqual(saved(p, false).db_password, RECORD.settings.db_password, "the restored key lost its default");
  });

  test("edit: a setting removed before a round trip does not get its inline default back with its old key", () => {
    const p = load({ groups });
    const doc = p.window.document;
    doc.querySelector('#settings [data-remove-key="db_password"]').click();
    const transport = doc.getElementById("transport");
    for (const to of ["file", "mllp"]) {
      transport.value = to;
      transport.dispatchEvent(new p.window.Event("change"));
      const asked = p.posted.filter((m) => m.command === "fields");
      p.deliver({ command: "fields", groups: buildForm(SCHEMA, to, "outbound", asked[asked.length - 1].settings) });
    }
    doc.querySelector('#settings [data-key="db_password"]').value = "DB_PW";
    assert.deepStrictEqual(saved(p, false).db_password, { env: "DB_PW" }, "a removed credential came back");
  });

  test("edit: a secret env reference's key emptied and then restored keeps its inline default", () => {
    const p = load({ groups });
    const box = p.window.document.querySelector('#settings [data-key="db_password"]');
    for (const text of ["", "DB_PW"]) {
      box.value = text;
      box.dispatchEvent(new p.window.Event("input"));
    }
    assert.deepStrictEqual(saved(p, false).db_password, RECORD.settings.db_password, "a kept credential was dropped");
  });

  test("edit: a setting removed and kept again before its rebuild's reply keeps its inline default (BACKLOG #8243 item 18)", () => {
    const p = load({ groups });
    const doc = p.window.document;
    const drop = doc.querySelector('#settings [data-remove-key="db_password"]');
    drop.click();
    const transport = doc.getElementById("transport");
    transport.value = "file";
    transport.dispatchEvent(new p.window.Event("change"));
    // Kept again before any reply arrives, then saved with the key untouched.
    drop.click();
    assert.deepStrictEqual(saved(p, false).db_password, RECORD.settings.db_password, "the kept setting lost its default");
  });

  test("edit: an untouched env key is saved as recorded, not trimmed (BACKLOG #8243 item 19)", () => {
    {
      const env = " DB_PW ";
      const initial = { ...RECORD, settings: { ...RECORD.settings, db_password: { env, default: INLINE_DEFAULT } } };
      const p = load({ groups: buildForm(SCHEMA, "mllp", "outbound", initial.settings), initial });
      assert.deepStrictEqual(saved(p, false).db_password, { env, default: INLINE_DEFAULT }, "the key was rewritten");
    }
    // A non-secret env reference too, and the key survives a transport round trip untouched.
    const initial = { ...RECORD, settings: { ...RECORD.settings, host: { env: " PEER_HOST ", default: "localhost" } } };
    const p = load({ groups: buildForm(SCHEMA, "mllp", "outbound", initial.settings), initial });
    switchTransport(p, "file");
    switchTransport(p, "mllp");
    assert.deepStrictEqual(saved(p, false).host, initial.settings.host, "a round trip rewrote the key");
  });

  test("edit: a recorded env key holding a line break is saved trimmed, as before, so it can be repaired", () => {
    // The box cannot show a CR or LF, so leaving it and retyping what it shows look the same; the
    // trimmed text is written, as origin/main wrote it, and the inline default stays with it.
    const initial = { ...RECORD, settings: { ...RECORD.settings, db_password: { env: "DB_\r\nPW", default: INLINE_DEFAULT } } };
    const p = load({ groups: buildForm(SCHEMA, "mllp", "outbound", initial.settings), initial });
    assert.deepStrictEqual(saved(p, false).db_password, { env: "DB_PW", default: INLINE_DEFAULT }, "the line break was written back");
  });

  test("edit: a default dropped by switching to a literal on another transport does not come back (BACKLOG #8243 item 20)", () => {
    const p = load({ groups });
    const doc = p.window.document;
    // The file transport does not declare db_password, so it draws it as an unknown setting, with
    // a literal/env() switch a secret does not get.
    switchTransport(p, "file");
    const toggle = doc.querySelector('#settings [data-env-toggle="db_password"]');
    assert.ok(toggle, "the file transport drew db_password with no env() switch");
    toggle.checked = false;
    toggle.dispatchEvent(new p.window.Event("change"));
    switchTransport(p, "mllp");
    doc.querySelector('#settings [data-key="db_password"]').value = "DB_PW";
    assert.deepStrictEqual(saved(p, false).db_password, { env: "DB_PW" }, "the dropped inline default came back");
  });

  test("edit: a picked choice keeps its own type when the recorded value was a table (BACKLOG #8243 item 31)", () => {
    const schema: ConnectionSchema = {
      ...SCHEMA,
      transports: { mllp: { doc: "MLLP.", params: { level: param({ choices: ["1", "2"] }) } } },
    };
    const initial = { ...RECORD, settings: { level: { tier: 1 } } };
    const p = load({ groups: buildForm(schema, "mllp", "outbound", initial.settings), initial, transports: ["mllp"] });
    const select = p.window.document.querySelector('#settings [data-key="level"]');
    assert.strictEqual(select.tagName, "SELECT", "level is not drawn as a select");
    select.value = "2";
    assert.strictEqual(saved(p, false).level, "2", "the picked choice was JSON-parsed");
  });

  test("edit: a select with a table among its choices parses the picked choice, as before", () => {
    const schema: ConnectionSchema = {
      ...SCHEMA,
      transports: { mllp: { doc: "MLLP.", params: { level: param({ choices: [{ a: 1 }, { b: 2 }] }) } } },
    };
    const initial = { ...RECORD, settings: { level: { tier: 1 } } };
    const p = load({ groups: buildForm(schema, "mllp", "outbound", initial.settings), initial, transports: ["mllp"] });
    const select = p.window.document.querySelector('#settings [data-key="level"]');
    assert.strictEqual(select.tagName, "SELECT", "level is not drawn as a select");
    select.value = '{"b":2}';
    assert.deepStrictEqual(saved(p, false).level, { b: 2 }, "the picked table was posted as text");
  });

  for (const how of ["removed", "cleared"]) {
    test(`edit: a secret env reference's inline default ${how} before a transport round trip is not written back`, () => {
      const p = load({ groups });
      const doc = p.window.document;
      if (how === "removed") {
        doc.querySelector('#settings [data-remove-key="db_password"]').click();
      } else {
        doc.querySelector('#settings [data-key="db_password"]').value = "";
      }
      const transport = doc.getElementById("transport");
      for (const to of ["file", "mllp"]) {
        transport.value = to;
        transport.dispatchEvent(new p.window.Event("change"));
        const asked = p.posted.filter((m) => m.command === "fields");
        p.deliver({ command: "fields", groups: buildForm(SCHEMA, to, "outbound", asked[asked.length - 1].settings) });
      }
      // The original key: only removing or emptying the setting can drop the default here.
      doc.querySelector('#settings [data-key="db_password"]').value = "DB_PW";
      assert.deepStrictEqual(saved(p, false).db_password, { env: "DB_PW" }, `the ${how} inline default came back`);
    });
  }

  test("edit: a transport round trip never sends a held credential, and the save keeps every one", () => {
    const p = load({ groups });
    const transport = p.window.document.getElementById("transport");
    const roundTrip = (to: string): Payload => {
      transport.value = to;
      transport.dispatchEvent(new p.window.Event("change"));
      const asked = p.posted.filter((m) => m.command === "fields");
      const last = asked[asked.length - 1];
      for (const value of [SECRET, INLINE_DEFAULT, OFFDIR_VALUE]) {
        assert.ok(!JSON.stringify(last).includes(value), `a held credential went to the field rebuild: ${value}`);
      }
      // The host rebuilds from what it was sent.
      p.deliver({ command: "fields", groups: buildForm(SCHEMA, to, "outbound", last.settings) });
      return last;
    };
    roundTrip("file");
    roundTrip("mllp");
    for (const value of [SECRET, INLINE_DEFAULT, OFFDIR_VALUE]) {
      assert.ok(!shownValues(p).some((v) => v.includes(value)), `a credential is shown after the rebuild: ${value}`);
    }
    const settings = saved(p, false);
    assert.strictEqual(settings.tls_key_password, SECRET);
    assert.strictEqual(settings.listen_secret, OFFDIR_VALUE, "the off-direction secret survives");
    assert.deepStrictEqual(settings.db_password, RECORD.settings.db_password, "the env default survives");
  });

  test("edit: a recorded setting can be removed, a bool included, and kept again", () => {
    const p = load({ groups });
    const doc = p.window.document;
    for (const key of ["keepalive", "port"]) {
      const remove = doc.querySelector(`#settings [data-remove-key="${key}"]`);
      assert.ok(remove, `no way to remove the recorded ${key}`);
      remove.click();
    }
    const settings = saved(p, false);
    assert.ok(!("keepalive" in settings), "a removed bool must not be written back");
    assert.ok(!("port" in settings), "a removed setting must not be written back");
    assert.strictEqual(settings.facility, "0042", "removing one setting keeps the others");
    // The toggle undoes it.
    const q = load({ groups });
    const button = q.window.document.querySelector('#settings [data-remove-key="keepalive"]');
    button.click();
    button.click();
    assert.strictEqual(saved(q, false).keepalive, true);
  });

  test("edit: a literal can be switched to env(), with the cast its type needs", () => {
    const p = load({ groups });
    const doc = p.window.document;
    const toggle = doc.querySelector('#settings [data-env-toggle="port"]');
    assert.ok(toggle, "no way to switch port to an environment reference");
    toggle.checked = true;
    toggle.dispatchEvent(new p.window.Event("change"));
    const box = doc.querySelector('#settings [data-key="port"]');
    assert.strictEqual(box.dataset.env, "1", "the control is not an env-key box");
    assert.strictEqual(box.value, "", "the literal is not offered as an env key");
    box.value = "MLLP_PORT";
    assert.deepStrictEqual(saved(p, false).port, { env: "MLLP_PORT", cast: "int" });
  });

  test("edit: an env() reference can be switched to a literal, and back unchanged", () => {
    const p = load({ groups });
    const doc = p.window.document;
    const flip = (on: boolean): void => {
      const toggle = doc.querySelector('#settings [data-env-toggle="host"]');
      assert.ok(toggle, "no way to switch host between env() and a literal");
      toggle.checked = on;
      toggle.dispatchEvent(new p.window.Event("change"));
    };
    flip(false);
    const box = doc.querySelector('#settings [data-key="host"]');
    assert.notStrictEqual(box.dataset.env, "1", "the control is still an env-key box");
    box.value = "peer.example.test";
    assert.strictEqual(saved(p, false).host, "peer.example.test");
    // Switching back restores the recorded reference, its default included.
    const q = load({ groups });
    const qDoc = q.window.document;
    for (const on of [false, true]) {
      const toggle = qDoc.querySelector('#settings [data-env-toggle="host"]');
      toggle.checked = on;
      toggle.dispatchEvent(new q.window.Event("change"));
    }
    assert.deepStrictEqual(saved(q, false).host, RECORD.settings.host);
  });

  test("edit: a secret has no literal switch, so the form cannot write a new inline credential", () => {
    const p = load({ groups });
    const doc = p.window.document;
    for (const key of ["tls_key_password", "db_password", "listen_secret"]) {
      assert.strictEqual(doc.querySelector(`#settings [data-env-toggle="${key}"]`), null, key);
    }
  });

  test("the fields request carries the token of the page that sent it", () => {
    const p = load({ groups });
    const transport = p.window.document.getElementById("transport");
    transport.value = "file";
    transport.dispatchEvent(new p.window.Event("change"));
    const asked = p.posted.filter((m) => m.command === "fields");
    assert.strictEqual(asked.length, 1);
    assert.strictEqual(asked[0][CHANNEL_FIELD], TOKEN, "the request does not name its render");
  });
});

suite("connection editor: create mode shows the transport whose fields are drawn (BACKLOG #5565)", () => {
  teardown(closeWindows);

  const keys = (p: Page): string[] =>
    [...p.window.document.querySelectorAll("#settings [data-key]")].map((c: DomNode) => c.dataset.key);

  test("the picker shows the transport the host built the fields for, not the list's first", () => {
    // The hosts build the create form for mllp, while the engine's sorted list starts elsewhere.
    const p = load({
      initial: null,
      groups: buildForm(SCHEMA, "mllp", "inbound", {}),
      fieldGroupsFor: { transport: "mllp", direction: "inbound" },
      transports: ["file", "mllp"],
    });
    const doc = p.window.document;
    assert.strictEqual(doc.getElementById("transport").value, "mllp", "the picker and the drawn fields disagree");
    assert.strictEqual(doc.getElementById("direction").value, "inbound");
    assert.ok(keys(p).includes("host"), `mllp's fields are not drawn: ${keys(p).join(", ")}`);
    doc.getElementById("name").value = "IB_SYNTH_MLLP";
    doc.getElementById("router").value = "route_adt";
    doc.querySelector('#settings [data-key="port"]').value = "6661";
    doc.getElementById("save").click();
    const save = p.posted.filter((m) => m.command === "save");
    assert.strictEqual(save.length, 1);
    assert.strictEqual(save[0].conn.transport, "mllp");
    assert.strictEqual(save[0].conn.settings.port, 6661);
    assert.strictEqual(p.posted.filter((m) => m.command === "fields").length, 0, "no load-time rebuild");
  });

  test("an outbound create form selects the outbound direction", () => {
    const p = load({
      initial: null,
      groups: buildForm(SCHEMA, "mllp", "outbound", {}),
      fieldGroupsFor: { transport: "mllp", direction: "outbound" },
      transports: ["file", "mllp"],
    });
    assert.strictEqual(p.window.document.getElementById("direction").value, "outbound");
  });

  test("no create path leaves the settings area empty", () => {
    const cases: Array<[string, Parameters<typeof load>[0]]> = [
      ["fields for a listed transport", {
        initial: null,
        groups: buildForm(SCHEMA, "mllp", "inbound", {}),
        fieldGroupsFor: { transport: "mllp", direction: "inbound" },
      }],
      ["fields for a transport the picker does not list", {
        initial: null,
        groups: buildForm(SCHEMA, "mllp", "inbound", {}),
        fieldGroupsFor: { transport: "mllp", direction: "inbound" },
        transports: ["file"],
      }],
      ["fields with no record of what they were built for", {
        initial: null,
        groups: buildForm(SCHEMA, "mllp", "inbound", {}),
        transports: ["file", "mllp"],
      }],
      ["no fields: an engine that cannot describe itself", { initial: null, groups: null }],
      ["fields built for a transport that declares none", {
        initial: null,
        groups: [],
        fieldGroupsFor: { transport: "mllp", direction: "inbound" },
      }],
    ];
    for (const [label, opts] of cases) {
      const p = load(opts);
      const controls = p.window.document.querySelectorAll("#settings input, #settings select");
      assert.ok(controls.length > 0, `the settings area is empty: ${label}`);
      if (keys(p).length > 0) {
        // Schema fields are drawn only under the picker that names their transport.
        assert.strictEqual(p.window.document.getElementById("transport").value, opts.fieldGroupsFor?.transport, label);
      }
    }
  });

  test("no edit or clone load, and no fields reply, leaves the settings area empty", () => {
    const filled = (p: Page): number => p.window.document.querySelectorAll("#settings input, #settings select").length;
    for (const clone of [false, true]) {
      const p = load({ clone, groups: [] });
      assert.ok(filled(p) > 0, `the settings area is empty: ${clone ? "clone" : "edit"} with no fields`);
    }
    // A rebuild that draws nothing, for a create and an edit page.
    const pages: Array<Parameters<typeof load>[0]> = [
      { initial: null, groups: buildForm(SCHEMA, "mllp", "inbound", {}), fieldGroupsFor: { transport: "mllp", direction: "inbound" } },
      { groups: buildForm(SCHEMA, "mllp", "outbound", RECORD.settings) },
    ];
    for (const opts of pages) {
      const p = load(opts);
      const transport = p.window.document.getElementById("transport");
      transport.value = "file";
      transport.dispatchEvent(new p.window.Event("change"));
      p.deliver({ command: "fields", groups: [] });
      assert.ok(filled(p) > 0, `an empty fields reply emptied the settings area: ${opts.initial === null ? "create" : "edit"}`);
    }
  });
});

suite("webviewMessaging.postToSameRender (BACKLOG #5565)", () => {
  test("a reply to a request from a replaced render is dropped, even if handled after the re-render", () => {
    const sent: Payload[] = [];
    const webview = { postMessage: (m: Payload) => Promise.resolve(sent.push(m) > 0) };
    const first = openChannel(webview).token;
    const request = { command: "fields", [CHANNEL_FIELD]: first };
    // The panel re-renders BEFORE the host handles the old page's request.
    const second = openChannel(webview).token;
    assert.strictEqual(postToSameRender(webview, requestToken(request), { command: "fields" }), undefined);
    // A request from the current page is answered, stamped with its token.
    const current = { command: "fields", [CHANNEL_FIELD]: second };
    assert.notStrictEqual(postToSameRender(webview, requestToken(current), { command: "fields" }), undefined);
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0][CHANNEL_FIELD], second);
    // A request that names no render is never answered.
    assert.strictEqual(requestToken({ command: "fields" }), undefined);
    assert.strictEqual(requestToken({ command: "fields", [CHANNEL_FIELD]: 7 }), undefined);
  });

  test("both hosts answer the render the request names, not the one current when it arrives", () => {
    for (const file of ["connectionEditor.ts", "configEditors.ts"]) {
      const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", file), "utf8");
      assert.ok(/const asked = requestToken\(m\);/.test(src), `${file} does not read the request's token`);
      assert.ok(!/channelToken\(/.test(src), `${file} still reads the token current on arrival`);
    }
  });
});

suite("connection editor — the legacy rows, when the engine cannot describe itself (BACKLOG #5565)", () => {
  teardown(closeWindows);

  test("create: a transport or direction change keeps the rows typed so far", () => {
    const p = load({ initial: null, groups: null });
    const doc = p.window.document;
    const row = doc.querySelector("#settings .setting");
    const [k, v] = row.querySelectorAll("input[type=text]");
    k.value = "port";
    v.value = "6661";
    for (const id of ["transport", "direction"]) {
      const sel = doc.getElementById(id);
      sel.value = sel.options[sel.options.length - 1].value;
      sel.dispatchEvent(new p.window.Event("change"));
    }
    const rows = doc.querySelectorAll("#settings .setting");
    assert.strictEqual(rows.length, 1);
    assert.deepStrictEqual(
      [...rows[0].querySelectorAll("input[type=text]")].map((i: DomNode) => i.value),
      ["port", "6661"],
      "a picker change wiped the typed row",
    );
  });

  test("a table is shown as JSON and saved back as the same table", () => {
    const p = load({ groups: null });
    const shown = shownValues(p);
    assert.ok(!shown.includes("[object Object]"), `a table was stringified: ${shown.join(" | ")}`);
    const settings = saved(p, false);
    assert.deepStrictEqual(settings.headers, RECORD.settings.headers);
  });

  test("a table carrying an env key is a table, not an env reference", () => {
    const p = load({ groups: null });
    assert.deepStrictEqual(saved(p, false).routing, RECORD.settings.routing);
  });

  test("an untouched env reference is saved as it was, its default included", () => {
    const p = load({ groups: null });
    assert.deepStrictEqual(saved(p, false).host, RECORD.settings.host);
  });

  test("an untouched row keeps its recorded type: a str of digits stays a str", () => {
    const p = load({ groups: null });
    assert.strictEqual(saved(p, false).facility, "0042");
  });

  test("an untouched env reference keeps a cast outside the cast list, for the engine to refuse", () => {
    const initial = { ...RECORD, settings: { host: { env: "PEER_HOST", cast: "INT" } } };
    const p = load({ groups: null, initial });
    assert.deepStrictEqual(saved(p, false).host, { env: "PEER_HOST", cast: "INT" });
  });

  test("an untouched row keeps a multi-line value's line breaks", () => {
    const p = load({ groups: null });
    assert.strictEqual(saved(p, false).poll_statement, RECORD.settings.poll_statement);
  });
});

suite("connection editor — a non-finite float tag round-trips (BACKLOG #5778)", () => {
  teardown(closeWindows);

  const mllp = SCHEMA.transports.mllp;
  const schema: ConnectionSchema = {
    ...SCHEMA,
    transports: {
      ...SCHEMA.transports,
      mllp: {
        ...mllp,
        params: {
          ...mllp.params,
          receive_timeout: param({ type: "float", env: true }),
          connect_timeout: param({ type: "float", env: true }),
        },
      },
    },
  };
  const record = {
    ...RECORD,
    settings: {
      host: "peer.example",
      port: 6661,
      receive_timeout: { $toml: "inf" },
      connect_timeout: { env: "CT", cast: "float", default: { $toml: "-inf" } },
      undescribed: { $toml: "-nan" },
    },
  };
  const groups = buildForm(schema, "mllp", "outbound", record.settings);

  for (const clone of [false, true]) {
    test(`${clone ? "clone" : "edit"}: untouched tags show their spelling and save back exactly`, () => {
      const p = load({ clone, groups, initial: record });
      const box = p.window.document.querySelector('#settings [data-key="receive_timeout"]');
      assert.strictEqual(box.value, "inf");
      const settings = saved(p, clone);
      assert.deepStrictEqual(settings.receive_timeout, { $toml: "inf" });
      assert.deepStrictEqual(settings.connect_timeout, {
        env: "CT",
        cast: "float",
        default: { $toml: "-inf" },
      });
      assert.deepStrictEqual(settings.undescribed, { $toml: "-nan" });
    });
  }

  test("edit: inf / -inf typed into a float field post the tag; nan and Infinity post as typed", () => {
    const cases: Array<[string, unknown]> = [
      ["inf", { $toml: "inf" }],
      ["-inf", { $toml: "-inf" }],
      ["nan", "nan"],
      ["Infinity", "Infinity"],
      ["30", 30],
    ];
    for (const [typed, expected] of cases) {
      const p = load({ groups, initial: record });
      p.window.document.querySelector('#settings [data-key="receive_timeout"]').value = typed;
      assert.deepStrictEqual(saved(p, false).receive_timeout, expected, typed);
    }
  });
});
