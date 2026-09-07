// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import {
  CHANNEL_FIELD,
  guardScript,
  openChannel,
  postToWebview,
  type WebviewTarget,
} from "../../webviewMessaging";

// ASVS 3.5.5 (BACKLOG #1123) — the discard half of the webview trust boundary.
//
// The guard is three arms (origin, source, channel token) and the ACCEPT case is the control that
// keeps them honest: a guard that discarded EVERY message would satisfy every discard test here and
// prove nothing, so the accept case is asserted first and again at the end of the discard suite.
//
// The guard is exercised as SOURCE TEXT evaluated in a real DOM rather than reimplemented here.
// Reimplementing it would test the copy in this file, which is the one defect a pinning test exists
// to catch.
//
// Node-side only: this file must NOT import `vscode`, so it runs on every `ide` leg rather than only
// the Extension Host one. That is also why `webviewMessaging.ts` types its send target structurally
// instead of importing `vscode.Webview`.

// jsdom is loaded through a CommonJS `require` behind a narrow local shape ON PURPOSE, matching
// steps-mirror.test.ts: `ide/tsconfig.json` sets `lib: ["ES2022"]` with NO "DOM" (a deliberate
// guardrail for an extension that must not reach for browser globals), and `npm run typecheck`
// covers `src/test` too. Pulling in `@types/jsdom` would reference `lib.dom` and break the
// type-check for the whole extension.
interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib (see the note above).
  [key: string]: any;
}
interface JsdomWindow {
  document: DomNode;
  origin: string;
  MessageEvent: new (type: string, init?: Record<string, unknown>) => unknown;
  dispatchEvent(event: unknown): boolean;
  [key: string]: unknown;
}
interface JsdomVirtualConsole {
  on(event: string, handler: (err: unknown) => void): void;
}
interface JsdomModule {
  JSDOM: new (html: string, options?: Record<string, unknown>) => { window: JsdomWindow };
  VirtualConsole: new () => JsdomVirtualConsole;
}
const { JSDOM, VirtualConsole } = require("jsdom") as JsdomModule;

/** A minimal stand-in for `vscode.Webview`, recording what the host posted. */
class FakeWebview implements WebviewTarget {
  readonly sent: Record<string, unknown>[] = [];
  postMessage(message: unknown): PromiseLike<boolean> {
    this.sent.push(message as Record<string, unknown>);
    return Promise.resolve(true);
  }
}

interface Harness {
  readonly window: JsdomWindow;
  /** Dispatch a real MessageEvent; report what the receiver accepted, or null if it discarded. */
  deliver(init: { origin?: string; source?: unknown; data: unknown }): Record<string, unknown> | null;
}

/**
 * A page carrying the REAL guard source plus a receiver written the way the eight shipped ones are.
 *
 * One `<script>`, because that is how the panels ship it: `MF_CHANNEL` is a script-scoped `const`, so
 * a receiver in a second script could not see it and the harness would be testing a shape the
 * extension does not have.
 */
function harness(token: string): Harness {
  const scriptErrors: unknown[] = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e: unknown) => scriptErrors.push(e));
  const dom = new JSDOM("<!DOCTYPE html><body></body>", {
    runScripts: "dangerously",
    virtualConsole,
    url: "https://localhost/",
  });
  const window = dom.window;
  const script = window.document.createElement("script");
  script.textContent = `${guardScript(token)}
    window.__mfAccepted = null;
    window.addEventListener('message', (e) => {
      const d = mfTrusted(e);
      if (!d) { return; }
      window.__mfAccepted = d;
    });`;
  window.document.body.appendChild(script);
  assert.deepStrictEqual(
    scriptErrors.map((e) => String(e)),
    [],
    "the guard source threw while loading; nothing below would mean anything",
  );

  return {
    window,
    deliver(init): Record<string, unknown> | null {
      window.__mfAccepted = null;
      const ev = new window.MessageEvent("message", {
        origin: init.origin ?? window.origin,
        source: init.source ?? null,
        data: init.data,
      });
      window.dispatchEvent(ev);
      return (window.__mfAccepted as Record<string, unknown> | null) ?? null;
    },
  };
}

suite("webview channel token — host side", () => {
  test("openChannel mints a nonce and a token that are different 144-bit values", () => {
    // The separation is the point: the CSP nonce is a script-execution capability, and spending it
    // as an authentication tag would put it in every message the host sends.
    const wv = new FakeWebview();
    const seen = new Set<string>();
    for (let i = 0; i < 32; i++) {
      const ch = openChannel(wv);
      assert.notStrictEqual(ch.nonce, ch.token, "the CSP nonce was reused as the message token");
      assert.match(ch.token, /^[A-Za-z0-9_-]{24}$/, `not 18 base64url bytes: ${ch.token}`);
      assert.match(ch.nonce, /^[A-Za-z0-9_-]{24}$/, `not 18 base64url bytes: ${ch.nonce}`);
      seen.add(ch.token);
      seen.add(ch.nonce);
    }
    assert.strictEqual(seen.size, 64, "a value repeated across renders");
  });

  test("postToWebview stamps the token from the most recent openChannel", () => {
    const wv = new FakeWebview();
    const first = openChannel(wv);
    void postToWebview(wv, { command: "error", message: "x" });
    assert.strictEqual(wv.sent[0][CHANNEL_FIELD], first.token);
    assert.strictEqual(wv.sent[0].command, "error", "the payload must survive stamping");

    // Re-rendering the panel rotates the token and the host follows the document, which is what
    // stops a stale token from silently killing the channel.
    const second = openChannel(wv);
    assert.notStrictEqual(second.token, first.token);
    void postToWebview(wv, { command: "error", message: "y" });
    assert.strictEqual(wv.sent[1][CHANNEL_FIELD], second.token);
  });

  test("postToWebview refuses to send before a channel is open", () => {
    // Loud, because the quiet alternative is an unstamped message the receiver drops — a feature
    // that silently does nothing, which is the failure this whole guard makes possible.
    const wv = new FakeWebview();
    assert.throws(() => postToWebview(wv, { command: "error" }), /openChannel/);
    assert.deepStrictEqual(wv.sent, [], "nothing may reach the webview on that path");
  });

  test("each webview carries its own token", () => {
    const a = new FakeWebview();
    const b = new FakeWebview();
    const ta = openChannel(a).token;
    const tb = openChannel(b).token;
    assert.notStrictEqual(ta, tb);
    void postToWebview(a, { command: "x" });
    void postToWebview(b, { command: "x" });
    assert.strictEqual(a.sent[0][CHANNEL_FIELD], ta);
    assert.strictEqual(b.sent[0][CHANNEL_FIELD], tb);
  });
});

suite("webview message guard — what it accepts and what it discards", () => {
  const TOKEN = "TESTtokenTESTtokenTEST00";

  test("ACCEPTS a correctly stamped same-origin message", () => {
    // THE VACUITY CONTROL. Without it a guard that discarded everything would pass every test below.
    // It is first on purpose.
    const h = harness(TOKEN);
    const got = h.deliver({ data: { command: "rules", rules: [], [CHANNEL_FIELD]: TOKEN } });
    assert.ok(got, "a correctly stamped message must be delivered");
    assert.strictEqual(got.command, "rules");
  });

  test("discards a message with no channel token", () => {
    const h = harness(TOKEN);
    assert.strictEqual(h.deliver({ data: { command: "rules", rules: [] } }), null);
  });

  test("discards a message whose channel token is wrong", () => {
    const h = harness(TOKEN);
    assert.strictEqual(
      h.deliver({ data: { command: "rules", rules: [], [CHANNEL_FIELD]: "someoneElsesTokenXXXXXXX" } }),
      null,
    );
    // A token from a DIFFERENT render is the realistic wrong token, not a random string, so pin that
    // case rather than assume it behaves the same.
    const other = openChannel(new FakeWebview()).token;
    assert.notStrictEqual(other, TOKEN);
    assert.strictEqual(h.deliver({ data: { command: "rules", [CHANNEL_FIELD]: other } }), null);
  });

  test("discards a message posted by this document itself", () => {
    // The source arm. Written against `window`, not `window.parent`: VS Code's webview bridge injects
    // `window.parent = window` into the extension's document, so a genuine host message has
    // `ev.source !== window.parent` and a parent-based check would fail closed on every panel.
    const h = harness(TOKEN);
    assert.strictEqual(
      h.deliver({ source: h.window, data: { command: "rules", [CHANNEL_FIELD]: TOKEN } }),
      null,
    );
  });

  test("discards a cross-origin message even when it carries the right token", () => {
    const h = harness(TOKEN);
    assert.strictEqual(
      h.deliver({
        origin: "https://attacker.example",
        data: { command: "rules", [CHANNEL_FIELD]: TOKEN },
      }),
      null,
    );
  });

  test("discards a message whose data is not an object", () => {
    // The syntax half of the pinned verb, at the guard rather than at each receiver: a string body
    // carrying the token as a substring must not read as stamped.
    const h = harness(TOKEN);
    for (const data of [null, undefined, "rules", 7, TOKEN]) {
      assert.strictEqual(h.deliver({ data }), null, `accepted a ${typeof data} body`);
    }
    // An array IS an object, so what rejects it is the token check rather than the typeof check.
    assert.strictEqual(h.deliver({ data: [TOKEN] }), null);
  });

  test("the harness can tell accept from discard", () => {
    // NEGATIVE CONTROL over the harness itself. If `deliver` always reported null — a listener that
    // never ran, a MessageEvent jsdom silently dropped — every discard test above would pass while
    // measuring nothing.
    const h = harness(TOKEN);
    assert.strictEqual(h.deliver({ data: { [CHANNEL_FIELD]: "wrong" } }), null);
    assert.ok(h.deliver({ data: { ok: true, [CHANNEL_FIELD]: TOKEN } }), "the harness never accepts");
  });
});
