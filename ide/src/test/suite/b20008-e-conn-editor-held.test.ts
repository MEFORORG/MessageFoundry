// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { buildForm, type ConnectionSchema, type SchemaParam } from "../../connectionForm";
import { connectionEditorScript } from "../../connectionEditorWebview";
import { CHANNEL_FIELD } from "../../webviewMessaging";

// BACKLOG #5565, remainder #8243 items 18, 19, 20 and 31: what engine PR 3065 shipped open.
//  - Item 18: a setting removed, its transport changed, and kept again lost its value once the
//    rebuild's reply was drawn, and a reply to an older request could prune an inline default a
//    newer request still carried.
//  - Item 19: an untouched env key holding a line break, or only spaces, was not written back as
//    recorded.
//  - Item 20: a setting removed while a rebuild was in flight came back, its inline default
//    included, when that rebuild's reply was drawn.
//  - Item 31: a select matched its choices by String(c), so a table choice never matched, and a
//    select mixing scalar and table choices JSON-parsed a picked scalar.
//
// The connection editor's REAL script runs in a jsdom page, as in connection-editor-prefill.test.ts,
// whose harness this file copies rather than shares (each branch of the wave owns its own file).
// The host's replies are built with the same buildForm the hosts call. All values are synthetic.

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

const TOKEN = "B20008EtokenB20008Etok0";
const INLINE_DEFAULT = "synthetic-env-default-b20008e";
const SECRET = "synthetic-inline-credential-b20008e";

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
        db_password: param({ secret: true }),
        headers: param({ type: "table" }),
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

const RECORD = {
  direction: "outbound",
  name: "OB_SYNTH_B20008E",
  transport: "mllp",
  settings: {
    host: { env: "PEER_HOST", default: "localhost" },
    port: 6661,
    tls_key_password: SECRET,
    // A secret env reference whose default is itself an inline credential.
    db_password: { env: "DB_PW", default: INLINE_DEFAULT },
  },
};

interface Page {
  readonly window: JsdomWindow;
  readonly posted: Payload[];
  deliver(data: Payload): void;
}

const openWindows: JsdomWindow[] = [];
function closeWindows(): void {
  for (const w of openWindows.splice(0)) {
    w.close();
  }
}

function load(opts: { schema?: ConnectionSchema; initial?: typeof RECORD | Payload; transports?: string[] } = {}): Page {
  const schema = opts.schema ?? SCHEMA;
  const initial = (opts.initial ?? RECORD) as Payload;
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
    initial,
    routers: ["route_adt"],
    transports: opts.transports ?? ["mllp", "file"],
    fieldGroups: buildForm(schema, initial.transport, "outbound", initial.settings),
    fieldGroupsFor: null,
    siblings: undefined,
    clone: false,
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

function saved(p: Page): Payload {
  p.window.document.getElementById("save").click();
  const save = p.posted.filter((m) => m.command === "save");
  assert.strictEqual(save.length, 1, `expected one save post: ${JSON.stringify(p.posted)}`);
  return JSON.parse(JSON.stringify(save[0].conn.settings)) as Payload;
}

function fieldsRequests(p: Page): Payload[] {
  return p.posted.filter((m) => m.command === "fields");
}

/** The host's reply to one fields request: the form rebuilt from what that request sent. */
function replyTo(p: Page, request: Payload): void {
  p.deliver({ command: "fields", groups: buildForm(SCHEMA, request.transport, request.direction, request.settings) });
}

/** Answer every fields request from index `from` on, oldest first; returns the next index. */
function answerFrom(p: Page, from: number): number {
  const asked = fieldsRequests(p);
  for (const request of asked.slice(from)) {
    replyTo(p, request);
  }
  return asked.length;
}

/** Pick a transport, posting its fields request, with no reply. */
function pick(p: Page, to: string): void {
  const transport = p.window.document.getElementById("transport");
  transport.value = to;
  transport.dispatchEvent(new p.window.Event("change"));
}

function control(p: Page, key: string): DomNode {
  return p.window.document.querySelector(`#settings [data-key="${key}"]`);
}

function removeButton(p: Page, key: string): DomNode {
  const button = p.window.document.querySelector(`#settings [data-remove-key="${key}"]`);
  assert.ok(button, `no remove control for ${key}`);
  return button;
}

suite("connection editor: a removal and a keep survive a rebuild's reply (BACKLOG #8243 items 18 and 20)", () => {
  teardown(closeWindows);

  test("item 18: a setting removed, its transport changed, and kept again keeps its value after the reply is drawn", () => {
    const p = load();
    for (const key of ["db_password", "port"]) {
      removeButton(p, key).click();
    }
    pick(p, "file");
    // Kept again while the rebuild is in flight.
    for (const key of ["db_password", "port"]) {
      removeButton(p, key).click();
    }
    let next = answerFrom(p, 0);
    pick(p, "mllp");
    next = answerFrom(p, next);
    const settings = saved(p);
    assert.deepStrictEqual(settings.db_password, RECORD.settings.db_password, "the kept setting lost its inline default");
    assert.strictEqual(settings.port, 6661, "the kept literal setting disappeared");
  });

  test("item 18: a reply to an older request does not prune an inline default a newer request carries", () => {
    const p = load();
    removeButton(p, "db_password").click();
    pick(p, "file");
    removeButton(p, "db_password").click();
    pick(p, "mllp");
    // The host answers every request, oldest first.
    answerFrom(p, 0);
    assert.deepStrictEqual(saved(p).db_password, RECORD.settings.db_password, "an older reply pruned the default");
  });

  test("item 20: a setting removed while its rebuild is in flight stays removed after the reply", () => {
    for (const key of ["db_password", "port"]) {
      const p = load();
      pick(p, "file");
      // Removed before the reply arrives.
      removeButton(p, key).click();
      let next = answerFrom(p, 0);
      pick(p, "mllp");
      next = answerFrom(p, next);
      const settings = saved(p);
      assert.ok(!(key in settings), `the removed ${key} came back: ${JSON.stringify(settings[key])}`);
    }
  });

  test("item 20: the removed secret's original key typed back after the reply does not take its inline default", () => {
    const p = load();
    pick(p, "file");
    removeButton(p, "db_password").click();
    let next = answerFrom(p, 0);
    pick(p, "mllp");
    next = answerFrom(p, next);
    control(p, "db_password").value = "DB_PW";
    assert.deepStrictEqual(saved(p).db_password, { env: "DB_PW" }, "the removed inline default came back");
  });

  test("item 18: an older reply with the same keys, drawing the key as a literal, does not prune a default the newer request carries", () => {
    const p = load();
    pick(p, "file");
    let next = answerFrom(p, 0);
    // On the file transport db_password is an unknown setting, so it has a literal/env() switch.
    const toggle = (on: boolean): void => {
      const box = p.window.document.querySelector('#settings [data-env-toggle="db_password"]');
      assert.ok(box, "the file transport drew db_password with no env() switch");
      box.checked = on;
      box.dispatchEvent(new p.window.Event("change"));
    };
    toggle(false);
    control(p, "db_password").value = "synthetic-literal";
    pick(p, "mllp"); // asks with db_password as a literal
    toggle(true); // switched back to the recorded reference before the reply
    pick(p, "file"); // asks with db_password as the reference again: the same keys
    next = answerFrom(p, next);
    pick(p, "mllp");
    answerFrom(p, next);
    assert.deepStrictEqual(saved(p).db_password, RECORD.settings.db_password, "the older reply pruned the default");
  });

  test("an edit made while a rebuild is in flight survives its reply: a value, a replaced env key, a switch to a literal", () => {
    // A value typed in flight.
    {
      const p = load();
      pick(p, "file");
      control(p, "port").value = "7000";
      let next = answerFrom(p, 0);
      pick(p, "mllp");
      next = answerFrom(p, next);
      assert.strictEqual(saved(p).port, 7000, "the value typed in flight was undone by the reply");
    }
    // A secret env key replaced in flight does not get the old key's inline default back.
    {
      const p = load();
      pick(p, "file");
      control(p, "db_password").value = "NEW_KEY";
      let next = answerFrom(p, 0);
      pick(p, "mllp");
      next = answerFrom(p, next);
      assert.deepStrictEqual(saved(p).db_password, { env: "NEW_KEY" }, "the replaced key was undone by the reply");
    }
    // A reference switched to a literal in flight does not come back with its inline default.
    {
      const p = load();
      pick(p, "file");
      let next = answerFrom(p, 0);
      pick(p, "mllp");
      const toggle = p.window.document.querySelector('#settings [data-env-toggle="db_password"]');
      assert.ok(toggle, "the file transport drew db_password with no env() switch");
      toggle.checked = false;
      toggle.dispatchEvent(new p.window.Event("change"));
      control(p, "db_password").value = "synthetic-literal";
      next = answerFrom(p, next);
      answerFrom(p, next);
      const written = saved(p).db_password;
      assert.ok(!JSON.stringify(written ?? null).includes(INLINE_DEFAULT), `the inline default came back: ${JSON.stringify(written)}`);
      assert.notDeepStrictEqual(written, { env: "DB_PW" }, "the switch to a literal was undone by the reply");
    }
  });

  test("a plain transport round trip still draws each reply, and never sends a held value", () => {
    const p = load();
    let next = 0;
    for (const to of ["file", "mllp"]) {
      pick(p, to);
      next = answerFrom(p, next);
    }
    assert.strictEqual(fieldsRequests(p).length, 2, "a round trip with no edits sent extra requests");
    for (const request of fieldsRequests(p)) {
      for (const value of [SECRET, INLINE_DEFAULT]) {
        assert.ok(!JSON.stringify(request).includes(value), `a held value went to the field rebuild: ${value}`);
      }
    }
    assert.ok(control(p, "port"), "the mllp reply was not drawn");
    assert.deepStrictEqual(saved(p), RECORD.settings);
    // Each reply is drawn: the file reply draws the file transport's own setting.
    const q = load();
    pick(q, "file");
    answerFrom(q, 0);
    assert.ok(control(q, "path"), "the file reply was not drawn");
  });

  test("a reply whose settings the host normalized is still drawn", () => {
    // buildForm drops an env reference's cast that is not a string, so this reply matches no
    // request's settings exactly; it is the latest request's answer and must be drawn.
    const p = load();
    control(p, "headers").value = '{"env":"X","cast":5}';
    pick(p, "file");
    answerFrom(p, 0);
    assert.ok(control(p, "path"), "the reply to the latest request was dropped");
    assert.strictEqual(fieldsRequests(p).length, 1, "a normalized reply sent another request");
  });

  test("a kept setting's re-request never sends a held value", () => {
    const p = load();
    removeButton(p, "db_password").click();
    pick(p, "file");
    removeButton(p, "db_password").click();
    answerFrom(p, 0);
    assert.ok(fieldsRequests(p).length >= 2, "keeping a setting while its rebuild was in flight sent no new request");
    for (const request of fieldsRequests(p)) {
      for (const value of [SECRET, INLINE_DEFAULT]) {
        assert.ok(!JSON.stringify(request).includes(value), `a held value went to the field rebuild: ${value}`);
      }
    }
    for (const c of p.window.document.querySelectorAll("#settings input, #settings select")) {
      for (const value of [SECRET, INLINE_DEFAULT]) {
        assert.ok(!String(c.value).includes(value), `a credential is shown: ${value}`);
      }
    }
  });
});

suite("connection editor: an untouched env key is written back exactly (BACKLOG #8243 item 19)", () => {
  teardown(closeWindows);

  function withDbPassword(env: string): Page {
    return load({ initial: { ...RECORD, settings: { ...RECORD.settings, db_password: { env, default: INLINE_DEFAULT } } } });
  }

  for (const env of ["DB_\r\nPW", "DB_PW\n", "   "]) {
    test(`an untouched key ${JSON.stringify(env)} is saved as recorded, its inline default included`, () => {
      assert.deepStrictEqual(saved(withDbPassword(env)).db_password, { env, default: INLINE_DEFAULT }, "the key was rewritten");
    });
  }

  test("an untouched non-secret key of only spaces is saved as recorded", () => {
    const initial = { ...RECORD, settings: { ...RECORD.settings, host: { env: "  ", default: "localhost" } } };
    assert.deepStrictEqual(saved(load({ initial })).host, initial.settings.host);
  });

  test("a key with surrounding spaces typed in and put back as it was is saved as recorded", () => {
    const initial = { ...RECORD, settings: { ...RECORD.settings, host: { env: "  PEER_HOST ", default: "localhost" } } };
    const p = load({ initial });
    const box = control(p, "host");
    for (const text of ["  PEER_HOSTX ", "  PEER_HOST "]) {
      box.value = text;
      box.dispatchEvent(new p.window.Event("input"));
    }
    assert.deepStrictEqual(saved(p).host, initial.settings.host, "the key was trimmed");
  });

  test("a key holding a line break, retyped as the box shows it, is saved as typed and keeps its default", () => {
    const p = withDbPassword("DB_\r\nPW");
    const box = control(p, "db_password");
    assert.strictEqual(box.value, "DB_PW", "the box does not show the key with its line break stripped");
    box.value = "DB_PW";
    box.dispatchEvent(new p.window.Event("input"));
    assert.deepStrictEqual(saved(p).db_password, { env: "DB_PW", default: INLINE_DEFAULT });
  });
});

suite("connection editor: a select takes the picked choice itself (BACKLOG #8243 item 31)", () => {
  teardown(closeWindows);

  function selectPage(choices: unknown[], recorded: unknown): Page {
    const schema: ConnectionSchema = {
      ...SCHEMA,
      transports: { mllp: { doc: "MLLP.", params: { level: param({ choices }) } } },
    };
    const p = load({ schema, initial: { ...RECORD, settings: { level: recorded } }, transports: ["mllp"] });
    assert.strictEqual(control(p, "level").tagName, "SELECT", "level is not drawn as a select");
    return p;
  }

  test("a scalar picked from choices that mix scalars and tables keeps its own type", () => {
    const p = selectPage(["1", { tier: 2 }], { tier: 1 });
    control(p, "level").value = "1";
    assert.strictEqual(saved(p).level, "1", "the picked choice was JSON-parsed");
  });

  test("a table choice picked where the recorded value was not a table posts the table", () => {
    const p = selectPage([{ a: 1 }, { b: 2 }], "x");
    control(p, "level").value = '{"b":2}';
    assert.deepStrictEqual(saved(p).level, { b: 2 }, "the picked table was posted as text");
  });

  test("a recorded value equal to a table choice is that choice, not an extra option", () => {
    const p = selectPage([{ a: 1 }, { b: 2 }], { b: 2 });
    const options = [...control(p, "level").options].map((o: DomNode) => String(o.value));
    assert.deepStrictEqual(options, ["", '{"a":1}', '{"b":2}']);
  });

  test("a recorded table equal to a table choice in another key order is that choice", () => {
    const p = selectPage([{ a: 1, b: 2 }], { b: 2, a: 1 });
    const select = control(p, "level");
    assert.deepStrictEqual([...select.options].map((o: DomNode) => String(o.value)), ["", '{"a":1,"b":2}']);
    assert.strictEqual(select.value, '{"a":1,"b":2}', "the select does not show the recorded choice");
    assert.deepStrictEqual(saved(p).level, { b: 2, a: 1 });
  });

  test("a choice with surrounding spaces is posted as the choice", () => {
    const p = selectPage([" fifo ", "unordered"], "unordered");
    control(p, "level").value = " fifo ";
    assert.strictEqual(saved(p).level, " fifo ");
  });
});
