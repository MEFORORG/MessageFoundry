// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The trust boundary at every webview `message` receiver in this extension: what each receiver
// checks, what evidence each check rests on, and what it still does not cover. Stated once so the
// eight receivers do not each carry a different half-answer.
//
// SHAPE VALIDATION IS NOT ORIGIN VALIDATION. Every receiver dispatches on a discriminator (`command`
// or `type`) and ignores anything it does not recognise. That bounds WHAT a message can ask for; it
// says nothing about WHO sent it, and the two are routinely conflated. The checks below answer the
// second question; the discriminator still answers the first.
//
// WHAT ARRIVES AT A WEBVIEW RECEIVER, MEASURED RATHER THAN ASSUMED. This was previously written up
// as unknowable, and it is not. VS Code's shipped webview bridge is readable in any installation at
// `resources/app/out/vs/workbench/contrib/webview/browser/pre/index.html`; the three facts below were
// read there (VS Code 1.135.0, commit 08d4889f9e, against `engines.vscode ^1.95.0`):
//
//   1. The extension's document is an iframe whose `src` is `./fake.html`, RELATIVE to the outer
//      webview frame, carrying `sandbox="allow-same-origin ..."`. Its origin is therefore whatever
//      the outer frame's is — the generated per-panel `vscode-webview://<uuid>` on the desktop build,
//      and on the web a host the bridge itself validates against a base-32 sha-256 of the parent
//      origin (`hostname === parentOriginHash || hostname.startsWith(parentOriginHash + '.')`). The
//      check below does not depend on WHICH: only on both frames sharing one origin, and on that
//      origin being a real tuple origin rather than an opaque one. Fact 2 establishes the second.
//   2. Every host-to-webview message is delivered by that outer frame as
//      `contentWindow.postMessage(data.message, window.origin, ...)` — the targetOrigin is the outer
//      frame's own origin. `postMessage` rejects `"null"` as a targetOrigin, so a working delivery
//      path is itself proof the origin is a tuple origin: an opaque origin could not be addressed
//      this way at all. That is what makes `ev.origin === window.origin` a real comparison rather
//      than the vacuous `"null" === "null"` it would be under an opaque origin.
//      THE GUARD DOES NOT REST ON THIS FACT. It was read on one build and measured on two, and
//      `engines.vscode ^1.95.0` has an open top, so no set of measured builds covers the range. The
//      guard therefore refuses every message while `window.origin` is `"null"` (or not a string at
//      all). On a build that served an opaque origin, every panel would discard every message and fail
//      closed, rather than admit every opaque poster. That holds by construction, not by measurement.
//   3. What `window.parent` is inside the extension's document DEPENDS ON THE VS CODE VERSION, so no
//      check may rest on it. The 1.135.0 bridge read above injects
//      `window.parent = window; window.top = window; window.frameElement = null;`. The BACKLOG #1123
//      delivery probe (`ide/src/test/deliveryProbe.ts`) then measured two builds: at 1.95.0, the
//      `engines.vscode` floor, the bridge runs `delete window.parent` and it is `undefined`; at
//      1.139.1, stable at the time, `window.parent === window`. What BOTH builds share: a genuine host
//      message arrives with `ev.origin === window.origin`, as the tuple `vscode-webview://<id>`, and
//      with `ev.source !== window.parent`. So a receiver written as `ev.source === window.parent`
//      would fail closed on both and silently kill its panel — the obvious source check is the
//      broken one, which is why this note records the measurement. Builds between the two were not
//      measured.
//
// WHAT EACH RECEIVER CHECKS, and the limits of each:
//   * `window.origin` is a tuple origin. Checked first: when it is the opaque `"null"`, the guard
//     discards the message before any other arm runs (fact 2 says why this cannot rest on a
//     measurement). The cost is a panel that shows nothing on such a build, which is the safe failure.
//   * `ev.origin === window.origin`. A same-origin test whose comparand the document reads from its
//     OWN browsing context, not out of the incoming event. The embedder fixed that value and no
//     poster can change it, which is what distinguishes this from a sender-supplied comparand. It
//     does not identify the extension host specifically: it rejects every cross-origin poster and
//     admits anything already running at this panel's origin.
//   * `ev.source !== window`. Rejects a same-document post. Narrow. It is written against `window`
//     rather than `window.parent` because `window.parent` is `undefined` on one measured build and
//     `window` on another (fact 3), while `window` means the document itself on both.
//   * A per-render 144-bit channel token, minted host-side by `openChannel()` and embedded in the
//     document's own script. This is what actually authenticates the extension host: only code that
//     can read this document can read the token, and the CSP below is what bounds who that is. It is
//     minted SEPARATELY from the CSP nonce and must never be the same value — the nonce is a
//     script-execution capability (`cspNonce.ts` says why), and spending it as an authentication tag
//     would put it in every message the host sends.
//
// WHAT STILL BOUNDS THESE RECEIVERS BEYOND THE CHECKS, and the limits of each:
//   * The nonce CSP on every document that runs a script. That set is WIDER than the documents with
//     one of these receivers: some panels run a nonced script and embed no receiver at all. Each such
//     document is served a `<meta>` CSP of `default-src 'none'` with `script-src 'nonce-<n>'` and a
//     fresh cryptographically random nonce (see cspNonce.ts), so no injected or third-party script
//     executes in it. The one CSP variation is stepsView.ts's page, which has no receiver of this
//     kind: its `script-src` also names `webview.cspSource`, because it loads
//     `media/stepsWebview.js` (itself nonced), and `localResourceRoots` bounds that source to
//     `media/`. This is a real enforcement
//     property of the browser, not an assertion about it — but it is scoped to THIS document, and it
//     is the reason both the nonce and the token being unguessable is load-bearing rather than
//     cosmetic.
//     NOT every document a panel shows carries it. Two static notices run no script and have no
//     receiver: configEditors.ts's "outside the config dir" line has NO CSP and relies on the panel's
//     scripts still being off (it is set before `enableScripts`), and stepsView.ts's `noticeHtml` has
//     `default-src 'none'; style-src 'unsafe-inline'` with no `script-src`. What each panel shows when
//     its script does not run is stated in docs/BROWSER-SUPPORT.md, "The IDE extension's webviews".
//   * No nested frames. None of these panels embeds an iframe, so there is no child document that
//     could post into them, and no policy in the extension sets `frame-src` or `child-src` — nested
//     frames fall back to `default-src 'none'`.
//   * The discriminator check at each receiver, which is what makes an unexpected message a no-op.
//   * The payload shape check at each receiver: every message it handles must carry its required
//     fields with the right JS types, or it is discarded. Seven receivers use `SHAPE_HELPERS` below;
//     Test Bench keeps its own `shapeOk()`. Types only: value ranges are not checked here.
//
// WHAT THIS DOES NOT COVER, stated so a reviewer does not have to infer it. The token authenticates
// the SENDER, not the message: a host-side bug that posts the wrong payload is stamped as validly as
// a correct one, so the receivers' own shape checks stay load-bearing. And a script that already
// executes in the panel can read the token out of the document, so none of this is a control against
// script execution in the webview — the nonce CSP is.

import { nonce } from "./cspNonce";

/**
 * The field every host-to-webview message carries its channel token in.
 *
 * Double-underscored because it is transport, not payload: no receiver dispatches on it and no
 * handler should read it.
 */
export const CHANNEL_FIELD = "__mfChannel";

/** The single-line marker every webview `message` receiver in this extension carries, pointing here.
 *  Kept as an exported constant so the source-text test that enforces its presence and this file
 *  cannot drift apart. */
export const WEBVIEW_GUARD_NOTE = "// Origin, source and channel token are checked — see webviewMessaging.ts.";

/**
 * The part of `vscode.Webview` this module uses, spelled structurally.
 *
 * Importing `vscode` here would make the module unloadable outside an Extension Host, and the
 * `test:unit` mocha leg — which is where the guard's pinning tests live — runs in plain Node. A
 * `vscode.Webview` satisfies this shape, so call sites pass one unchanged.
 */
export interface WebviewTarget {
  postMessage(message: unknown): PromiseLike<boolean>;
}

/** The two per-render secrets a panel needs. They are different values and serve different jobs. */
export interface WebviewChannel {
  /** CSP nonce for this render's `<script nonce="...">`. A script-execution capability. */
  readonly nonce: string;
  /** This render's message token. An authentication tag. NEVER the nonce. */
  readonly token: string;
}

/**
 * The token the host stamps onto sends for a given webview, replaced on every `openChannel()`.
 *
 * Keyed on the webview object, which outlives any single `webview.html` assignment but dies with the
 * panel, so a disposed panel's token is collected with it.
 */
const openTokens = new WeakMap<WebviewTarget, string>();

/**
 * Mint this render's CSP nonce and channel token, and make the token the one `post()` will stamp.
 *
 * Call it exactly where the old `nonce()` call sat — once per `webview.html` assignment, in the
 * function that builds the HTML. Rotating on every assignment is what keeps a stale token from
 * silently killing a channel: the document that a receiver is running in and the token the host
 * stamps are minted together, so they cannot disagree. The cost carried instead is that a message
 * still in flight across a re-render is discarded by the new document, which is correct — it was
 * addressed to a document that no longer exists.
 */
export function openChannel(webview: WebviewTarget): WebviewChannel {
  // Two independent draws from the same generator, never one value used twice. cspNonce.ts is the
  // project's only source of 144-bit unguessable strings; what makes these different secrets is that
  // they are drawn separately, and only one of them ever reaches a CSP directive.
  const cspNonce = nonce();
  const token = nonce();
  openTokens.set(webview, token);
  return { nonce: cspNonce, token };
}

/**
 * Post to a webview with this render's channel token attached.
 *
 * Throws if no channel is open, because the alternative is worse: an unstamped send is discarded by
 * the receiver, which looks exactly like a feature that quietly does nothing. Every call site posts
 * after assigning `webview.html`, so this cannot fire on a wired path — it fires on a new one that
 * forgot to open a channel, which is when a reader most needs to be told.
 */
export function postToWebview(
  webview: WebviewTarget,
  message: Record<string, unknown>,
): PromiseLike<boolean> {
  const token = openTokens.get(webview);
  if (token === undefined) {
    throw new Error(
      "webview send before any openChannel() for this webview — assign webview.html from a builder " +
        "that calls openChannel() before posting (see webviewMessaging.ts)",
    );
  }
  return webview.postMessage({ ...message, [CHANNEL_FIELD]: token });
}

/**
 * JSON for interpolation into an inline `<script>`, with `<` escaped so no value can close the tag.
 *
 * The panel scripts (`*Webview.ts`) embed their seed data with it too. The token is base64url and
 * could not carry a `<` today; routing it through the escape anyway is what keeps that from becoming
 * an unstated assumption the next value inherits.
 */
export function embedJson(value: unknown): string {
  return JSON.stringify(value ?? null).replace(/</g, "\\u003c");
}

/**
 * The guard source every panel embeds at the top of its inline script.
 *
 * `mfTrusted(ev)` returns the message body for a trusted message and `null` otherwise, so a receiver
 * reads as `const d = mfTrusted(e); if (!d) return;` and the discard is the default path. Declared as
 * a function so it hoists above whatever order a panel's script happens to be written in.
 */
export function guardScript(token: string): string {
  return `
    // The trust boundary for this panel — what these checks rest on is in webviewMessaging.ts.
    const MF_CHANNEL = ${embedJson(token)};
    function mfTrusted(ev) {
      // An opaque origin reads as the string 'null', and then the origin test below would compare
      // 'null' with 'null' and pass for every opaque poster. Refuse everything instead, on any build.
      if (typeof window.origin !== 'string' || window.origin === 'null') { return null; }
      // Same-origin. window.origin is this document's own, not read out of the event.
      if (ev.origin !== window.origin) { return null; }
      // Not a same-document post. NOT window.parent: it differs by VS Code build (undefined at 1.95.0,
      // where the bridge deletes it; window itself at 1.139.1), so no check may rest on it.
      if (ev.source === window) { return null; }
      const d = ev.data;
      if (!d || typeof d !== 'object' || d.${CHANNEL_FIELD} !== MF_CHANNEL) { return null; }
      return d;
    }`;
}

/**
 * The payload-shape helpers a receiver runs AFTER `mfTrusted()`, as inline script source.
 *
 * ASVS 3.5.5 asks a receiver to check the syntax of what it is handed, not only who handed it. Here
 * that means the REQUIRED FIELDS of each message and their JS types. Value ranges and business limits
 * are a different requirement and are not checked here. A receiver declares one entry per message it
 * handles and calls `mfShapeOk(d, 'command', SHAPES, '<panel>')`; on `false` it returns without
 * acting. A message whose discriminator has no entry is discarded the same way.
 *
 * Test Bench predates this and keeps its own `shapeOk()` (testBenchWebview.ts). The `mf` prefix keeps
 * these names clear of any panel's own helpers.
 */
export const SHAPE_HELPERS = `
    // PAYLOAD SHAPE (ASVS 3.5.5): required fields and their JS types. See webviewMessaging.ts.
    function mfStr(x) { return typeof x === 'string'; }
    function mfNum(x) { return typeof x === 'number' && Number.isFinite(x); }
    function mfInt(x) { return Number.isSafeInteger(x); }
    function mfBool(x) { return typeof x === 'boolean'; }
    function mfObj(x) { return !!x && typeof x === 'object' && !Array.isArray(x); }
    function mfArrOf(x, f) { return Array.isArray(x) && x.every((v) => f(v) === true); }
    // An OPTIONAL field: absent (or null) passes, present must match.
    function mfOpt(x, f) { return x === undefined || x === null || f(x) === true; }
    function mfShapeOk(d, key, shapes, panel) {
      const k = d[key];
      const check = typeof k === 'string' && Object.prototype.hasOwnProperty.call(shapes, k) ? shapes[k] : null;
      if (check && check(d) === true) { return true; }
      // Named in the webview console, so a host and page that drift apart read as a discard.
      console.warn('MessageFoundry ' + panel + ': discarded a malformed "' + String(k) + '" message');
      return false;
    }`;
