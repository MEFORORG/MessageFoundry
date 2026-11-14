// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { buildForm, type ConnectionSchema, type SchemaParam } from "../../connectionForm";
import { connectionEditorScript } from "../../connectionEditorWebview";
import { CHANNEL_FIELD } from "../../webviewMessaging";

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

function load(opts: { clone?: boolean; groups: unknown }): Page {
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
    initial: RECORD,
    routers: ["route_adt"],
    transports: ["mllp", "file"],
    fieldGroups: opts.groups,
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
      const { tls_key_password: _secret, ...rest } = RECORD.settings;
      const { tls_key_password: written, ...others } = settings;
      assert.deepStrictEqual(others, rest);
      // An edit keeps the credential the form never showed. A clone does not copy it: the GUI must
      // not be what writes a new inline credential into the file.
      assert.strictEqual(written, clone ? undefined : SECRET);
    });
  }

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

  test("edit: a transport change never sends the held credential, and the save still keeps it", () => {
    const p = load({ groups });
    const transport = p.window.document.getElementById("transport");
    transport.value = "file";
    transport.dispatchEvent(new p.window.Event("change"));
    const asked = p.posted.filter((m) => m.command === "fields");
    assert.strictEqual(asked.length, 1, "the change asks the host for the new fields");
    assert.ok(!JSON.stringify(asked[0]).includes(SECRET), "the credential went to the host's field rebuild");
    // The host rebuilds from what it was sent; back on a transport whose schema declares the key a
    // secret, the save writes the credential held from the first render.
    transport.value = "mllp";
    p.deliver({ command: "fields", groups: buildForm(SCHEMA, "mllp", "outbound", asked[0].settings) });
    assert.ok(!shownValues(p).some((v) => v.includes(SECRET)), "the credential is shown after the rebuild");
    assert.strictEqual(saved(p, false).tls_key_password, SECRET);
  });
});

suite("connection editor — the legacy rows, when the engine cannot describe itself (BACKLOG #5565)", () => {
  teardown(closeWindows);

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
});
