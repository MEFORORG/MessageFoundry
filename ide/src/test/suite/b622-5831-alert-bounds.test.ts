// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { ALERT_COOLDOWN_MAX_SECONDS, alertEditorScript } from "../../alertEditorWebview";
import { CHANNEL_FIELD } from "../../webviewMessaging";

// BACKLOG #5831: the Alert Rules page's Add refuses a numeric value the engine's AlertRule model
// (messagefoundry/config/settings.py) would refuse at load: min_depth an integer of at least 1,
// min_oldest_seconds at least 0, cooldown_seconds above 0 and at most the engine's cap. Before the
// fix validate() checked only Number.isFinite, so each case below posted an "add".
//
// The REAL script runs in a jsdom page, as in webview-receivers.test.ts. Node-side only.

// Deliberately `any`: the base tsconfig has no DOM lib (see webview-receivers.test.ts).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;
const { JSDOM, VirtualConsole } = require("jsdom") as Any;

const TOKEN = "B622tokenB622tokenB62200";

interface AlertPage {
  posted: Any[];
  errors: unknown[];
  window: Any;
  close(): void;
}

function load(): AlertPage {
  const errors: unknown[] = [];
  const posted: Any[] = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e: unknown) => errors.push(e));
  const body = `<style>.error { display: none; }</style>
    <table id="rules"><tbody id="rows"></tbody></table><div id="empty"></div>
    <select id="event_type"></select><input id="connection" value="*" />
    <input id="min_depth" /><input id="min_oldest_seconds" /><input id="cooldown_seconds" />
    <select id="severity"></select><select id="transports"></select>
    <div id="error" class="error"></div><button id="add"></button><button id="close"></button>`;
  const dom = new JSDOM(`<!DOCTYPE html><body>${body}</body>`, {
    runScripts: "dangerously",
    virtualConsole,
    url: "https://localhost/",
  });
  const window = dom.window;
  window.acquireVsCodeApi = () => ({
    getState: () => null,
    setState: () => undefined,
    postMessage: (m: Any) => void posted.push(m),
  });
  const el = window.document.createElement("script");
  el.textContent = alertEditorScript(TOKEN, ["any", "queue_buildup"], ["info", "warning", "critical"]);
  window.document.body.appendChild(el);
  if (errors.length > 0) {
    window.close(); // the caller never gets a handle to close
    assert.fail(`the panel script threw while loading: ${errors.map(String).join("; ")}`);
  }
  // A list first, so the page is in its ordinary state and Add is on.
  window.dispatchEvent(
    new window.MessageEvent("message", {
      origin: window.origin,
      source: null,
      data: { command: "rules", rules: [], [CHANNEL_FIELD]: TOKEN },
    }),
  );
  return { posted, errors, window, close: () => window.close() };
}

function add(p: AlertPage, values: Record<string, string>): string {
  const doc = p.window.document;
  for (const [id, v] of Object.entries(values)) {
    doc.getElementById(id).value = v;
  }
  doc.getElementById("add").click();
  return doc.getElementById("error").textContent;
}

suite("b622 #5831 Alert Rules numeric bounds", () => {
  const refused: [string, Record<string, string>, string][] = [
    ["a negative min_depth", { min_depth: "-5" }, "Min depth"],
    ["a zero min_depth", { min_depth: "0" }, "Min depth"],
    ["a fractional min_depth", { min_depth: "2.5" }, "Min depth"],
    ["a min_depth past the safe-integer range", { min_depth: String(2 ** 53) }, "Min depth"],
    ["a negative min_oldest_seconds", { min_oldest_seconds: "-1" }, "Min oldest"],
    ["a negative cooldown_seconds", { cooldown_seconds: "-30" }, "Cooldown"],
    ["a zero cooldown_seconds", { cooldown_seconds: "0" }, "Cooldown"],
    ["a cooldown_seconds over the cap", { cooldown_seconds: String(ALERT_COOLDOWN_MAX_SECONDS + 1) }, "Cooldown"],
  ];
  for (const [name, values, label] of refused) {
    test(`Add refuses ${name}`, () => {
      const p = load();
      try {
        const shown = add(p, values);
        assert.deepStrictEqual(p.posted, [], `Add posted ${JSON.stringify(p.posted)}`);
        assert.ok(shown.startsWith(label), `no refusal naming ${label}: "${shown}"`);
      } finally {
        p.close();
      }
    });
  }

  // A number input reads '' for text it cannot parse. jsdom never sets badInput, so it is set here
  // as a browser would for "5-".
  test("Add refuses unparseable text in a number box rather than dropping the field", () => {
    const p = load();
    try {
      Object.defineProperty(p.window.document.getElementById("min_depth"), "validity", {
        value: { badInput: true },
      });
      const shown = add(p, { min_depth: "" });
      assert.deepStrictEqual(p.posted, [], `Add posted ${JSON.stringify(p.posted)}`);
      assert.ok(shown.startsWith("Min depth must be a number."), shown);
    } finally {
      p.close();
    }
  });

  // The control: values at the engine's bounds still post, so the refusals above are not a page
  // that refuses everything.
  test("Add posts values at the engine's bounds", () => {
    const p = load();
    try {
      add(p, { min_depth: "1", min_oldest_seconds: "0", cooldown_seconds: String(ALERT_COOLDOWN_MAX_SECONDS) });
      assert.strictEqual(p.posted.length, 1, `expected one add: ${JSON.stringify(p.posted)}`);
      const rule = JSON.parse(JSON.stringify(p.posted[0])).rule;
      assert.strictEqual(rule.min_depth, 1);
      assert.strictEqual(rule.min_oldest_seconds, 0);
      assert.strictEqual(rule.cooldown_seconds, ALERT_COOLDOWN_MAX_SECONDS);
    } finally {
      p.close();
    }
  });

  test("the cooldown cap matches the engine's _ALERT_COOLDOWN_MAX_SECONDS", () => {
    const source = fs.readFileSync(path.resolve(__dirname, "../../../../messagefoundry/config/settings.py"), "utf8");
    const m = /^_ALERT_COOLDOWN_MAX_SECONDS = ([0-9.]+)$/m.exec(source);
    assert.ok(m, "_ALERT_COOLDOWN_MAX_SECONDS not found in settings.py");
    assert.strictEqual(Number(m[1]), ALERT_COOLDOWN_MAX_SECONDS);
  });

  // The page mirrors these by hand, so a change to any of them on the engine fails here first.
  test("AlertRule still declares the lower bounds the page mirrors", () => {
    const source = fs.readFileSync(path.resolve(__dirname, "../../../../messagefoundry/config/settings.py"), "utf8");
    const start = source.indexOf("\nclass AlertRule(BaseModel):");
    assert.ok(start >= 0, "class AlertRule not found in settings.py");
    const end = source.indexOf("\nclass ", start + 1);
    const rule = source.slice(start, end < 0 ? undefined : end);
    assert.match(rule, /min_depth: int \| None = Field\(default=None, ge=1\)/);
    assert.match(rule, /min_oldest_seconds: float \| None = Field\(\s*default=None, ge=0, allow_inf_nan=False\s*\)/);
    assert.match(
      rule,
      /cooldown_seconds: float \| None = Field\(\s*default=None, gt=0, le=_ALERT_COOLDOWN_MAX_SECONDS, allow_inf_nan=False\s*\)/,
    );
  });
});
