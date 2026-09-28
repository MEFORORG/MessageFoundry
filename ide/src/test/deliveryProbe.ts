// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as vscode from "vscode";

import { guardScript, openChannel, postToWebview } from "../webviewMessaging";

// ASVS 3.5.5 (BACKLOG #1123), the origin arm: a DELIVERY PROBE, not a reading.
//
// webviewMessaging.ts states three facts about what reaches a webview receiver, read from one VS Code
// build's bridge source. This measures them instead, in whatever VS Code the Extension Host is
// running: it opens and reveals a real panel, posts through the extension's own send path
// (openChannel + postToWebview), and has the page report what its receiver actually saw.
//
// runTest.ts runs it at the floor `engines.vscode` declares and at the current stable build. Those
// are two ENDPOINTS of the declared range; nothing here measures the builds between them.
//
// Kept out of suite/ on purpose. It is shared by the mocha test there and by probeHost.ts, the
// mocha-free entry the floor build runs, and a `*.test.ts` here would be globbed into both.

/** What the page's receiver saw for one delivered message. */
export interface Echo {
  kind: "echo" | "selfEcho";
  evOrigin: string;
  windowOrigin: string;
  locationOrigin: string;
  sourceIsWindow: boolean;
  sourceIsParent: boolean;
  sourceIsNull: boolean;
  parentIsWindow: boolean;
  /** What `window.parent` is inside the page: "window" (shadowed), "undefined" (deleted), or "other". */
  parentKind: string;
  guardAccepted: boolean;
}

/** One probe run: the host message, the page's self-post, and the build they were measured in. */
export interface ProbeResult {
  vscodeVersion: string;
  hostNode: string;
  host: Echo;
  self: Echo;
}

/**
 * The probe page. It embeds the SAME guard source every panel ships, and reports on two messages:
 * the host's, and one the page posts to itself. The self-post is the negative control for the
 * source arm, measured in the real webview rather than in jsdom.
 */
function probeHtml(cspNonce: string, token: string): string {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-${cspNonce}';" />
</head><body>
<script nonce="${cspNonce}">
  const vscode = acquireVsCodeApi();${guardScript(token)}
  function report(kind, ev) {
    return {
      kind,
      evOrigin: String(ev.origin),
      windowOrigin: String(window.origin),
      locationOrigin: String(location.origin),
      sourceIsWindow: ev.source === window,
      sourceIsParent: ev.source === window.parent,
      sourceIsNull: ev.source === null,
      parentIsWindow: window.parent === window,
      parentKind: window.parent === window ? 'window' : (window.parent === undefined ? 'undefined' : 'other'),
      guardAccepted: mfTrusted(ev) !== null,
    };
  }
  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (!d || typeof d !== 'object') { return; }
    if (d.probe === 'host') {
      vscode.postMessage(report('echo', ev));
      // Re-post the host's own stamped body from this document. Same origin, right token; only the
      // source differs, so only the source arm can reject it.
      window.postMessage(Object.assign({}, d, { probe: 'self' }), window.origin);
    } else if (d.probe === 'self') {
      vscode.postMessage(report('selfEcho', ev));
    }
  });
  vscode.postMessage({ kind: 'ready' });
</script>
</body></html>`;
}

/**
 * Open and reveal a probe panel, post one host message through postToWebview, and collect the echoes.
 *
 * `budgetMs` is ONE deadline for the whole probe, not one per wait, so a caller with its own timeout
 * can size it to fit and still get this function's named error rather than a generic timeout.
 */
export async function measureDelivery(budgetMs = 45_000): Promise<ProbeResult> {
  const deadline = Date.now() + budgetMs;
  const panel = vscode.window.createWebviewPanel(
    "messagefoundry.deliveryProbe",
    "MessageFoundry delivery probe",
    vscode.ViewColumn.One,
    { enableScripts: true },
  );
  const got = new Map<string, Record<string, unknown>>();
  const waiters = new Map<string, (m: Record<string, unknown>) => void>();
  const sub = panel.webview.onDidReceiveMessage((m: Record<string, unknown>) => {
    const kind = String(m?.kind);
    got.set(kind, m);
    waiters.get(kind)?.(m);
  });
  const timers: NodeJS.Timeout[] = [];
  const waitFor = (kind: string): Promise<Record<string, unknown>> => {
    const seen = got.get(kind);
    if (seen) {
      return Promise.resolve(seen);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`the probe page never sent '${kind}' within the ${budgetMs} ms budget`)),
        Math.max(0, deadline - Date.now()),
      );
      timers.push(timer);
      waiters.set(kind, (m) => {
        clearTimeout(timer);
        resolve(m);
      });
    });
  };

  try {
    const { nonce, token } = openChannel(panel.webview);
    panel.webview.html = probeHtml(nonce, token);
    panel.reveal(vscode.ViewColumn.One, false);

    // A post before the page's listener exists is dropped, so wait until the page says it is live.
    await waitFor("ready");
    const delivered = await postToWebview(panel.webview, { probe: "host" });
    assert.strictEqual(delivered, true, "VS Code reported the host message undelivered");
    const host = (await waitFor("echo")) as unknown as Echo;
    const self = (await waitFor("selfEcho")) as unknown as Echo;
    return { vscodeVersion: vscode.version, hostNode: process.versions.node, host, self };
  } finally {
    timers.forEach(clearTimeout);
    sub.dispose();
    panel.dispose();
  }
}

/**
 * Assert what webviewMessaging.ts's three facts predict, in the form the shipped guard relies on.
 * The measured values are logged FIRST, so a failing run still leaves them in the CI log.
 */
export function assertTrustworthy(r: ProbeResult): void {
  console.log(
    `[delivery-probe] vscode ${r.vscodeVersion} (host node ${r.hostNode}) ` +
      `host=${JSON.stringify(r.host)} self=${JSON.stringify(r.self)}`,
  );
  const { host, self } = r;
  // Fact 2: the origin is a real tuple origin, so the origin arm is not "null" === "null".
  assert.notStrictEqual(host.evOrigin, "null", "the host message carried an opaque origin");
  assert.notStrictEqual(host.windowOrigin, "null", "the page's own origin is opaque");
  assert.match(host.evOrigin, /^vscode-webview:\/\/[^/]+$/, "not a per-panel desktop webview origin");
  // Fact 1: the host message comes from the page's own origin, which is what the guard compares.
  assert.strictEqual(host.evOrigin, host.windowOrigin, "the host message is not same-origin");
  // Fact 3, as MEASURED rather than as read. webviewMessaging.ts says the bridge sets
  // `window.parent = window`, which was read in 1.135.0. At the 1.95.0 floor the bridge instead
  // runs `delete window.parent`, so the page sees `undefined` there. Either way `window.parent` is
  // not the real sender, which is the property the guard's source arm is written around: a check
  // against `window.parent` would discard every genuine host message. That consequence is what is
  // asserted; which of the two mechanisms a build uses is recorded, not pinned.
  assert.ok(
    host.parentKind === "window" || host.parentKind === "undefined",
    `window.parent is neither shadowed nor removed (${host.parentKind}); re-read the bridge`,
  );
  assert.strictEqual(host.sourceIsParent, false, "a window.parent source check would now pass");
  assert.strictEqual(host.sourceIsWindow, false, "the host message claims this page as its source");
  assert.strictEqual(host.sourceIsNull, false, "the host message has no source at all");
  // The shipped guard accepts the real host message: the control that it does not fail closed.
  assert.strictEqual(host.guardAccepted, true, "mfTrusted() discarded a genuine host message");

  // Negative control, same page, same token: a post from the page itself is discarded.
  assert.strictEqual(self.evOrigin, host.evOrigin, "the self-post did not arrive same-origin");
  assert.strictEqual(self.sourceIsWindow, true, "the self-post did not come from the page");
  assert.strictEqual(self.guardAccepted, false, "mfTrusted() accepted a post from the page itself");
}
