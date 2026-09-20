// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #1695. The extension could not reach a stock engine: since ADR 0172 the engine always
// serves TLS with a self-signed certificate nobody trusts, so the https path failed with
// DEPTH_ZERO_SELF_SIGNED_CERT and the http default with ECONNRESET — reported as "engine not
// reachable … start it" while the engine was running.
//
// Measured against the engine's own TLS wiring (ensure_api_tls_material + build_api_ssl_context
// serving on 127.0.0.1:8765), four Node arms:
//   A https, default CA set                → ERROR DEPTH_ZERO_SELF_SIGNED_CERT
//   B http                                 → ERROR ECONNRESET
//   C https, ca = the minted certificate   → HTTP 200          <- what this change does
//   D https, rejectUnauthorized: false     → HTTP 200          (control; never shipped)
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import type * as httpsTypes from "https";

import { clearEngineTrustAnchors, getJson, setEngineTrustAnchor, tlsOptions } from "../../engineClient";
import { describeNetworkCode } from "../../engineStatusModel";
import {
  TLS_TRUST_CODES,
  engineHostKey,
  isTlsTrustError,
  parseApiTls,
  schemeMismatch,
  trustAnchorFor,
  trustAnchorForTarget,
  trustRemedy,
} from "../../engineTrustModel";

const GENERATED = {
  api_tls: {
    scheme: "https",
    source: "generated",
    cert: "C:\\engine\\state\\api-generated-cert.pem",
    cert_present: true,
  },
};

suite("engineTrustModel — reading the engine's own answer (BACKLOG #1695)", () => {
  test("parses the api_tls object the CLI reports", () => {
    const facts = parseApiTls(GENERATED);
    assert.deepStrictEqual(facts, {
      scheme: "https",
      source: "generated",
      cert: "C:\\engine\\state\\api-generated-cert.pem",
      certPresent: true,
    });
  });

  test("an OLDER engine, with no api_tls key, degrades to 'we learned nothing'", () => {
    // The extension shells whatever `messagefoundry` is on PATH. This must not throw or half-configure.
    assert.strictEqual(parseApiTls({ certs: [] }), undefined);
    assert.strictEqual(parseApiTls(undefined), undefined);
    assert.strictEqual(parseApiTls("not json at all"), undefined);
    assert.strictEqual(parseApiTls({ api_tls: [] }), undefined);
  });

  test("a malformed scheme or source is refused rather than coerced", () => {
    assert.strictEqual(parseApiTls({ api_tls: { scheme: "ftp", source: "generated" } }), undefined);
    assert.strictEqual(parseApiTls({ api_tls: { scheme: "https", source: "guessed" } }), undefined);
  });

  test("a certificate that is not on disk yet is parsed but not anchored", () => {
    const facts = parseApiTls({
      api_tls: { scheme: "https", source: "generated", cert: "/s/c.pem", cert_present: false },
    });
    assert.strictEqual(facts?.certPresent, false);
    assert.strictEqual(trustAnchorFor(facts), undefined);
  });

  test("an operator chain is anchored too, not only the minted pair", () => {
    // Anchoring only the generated pair would leave an internal-CA deployment failing for a reason
    // the extension could have fixed; the file named is the cert that server presents either way.
    const facts = parseApiTls({
      api_tls: { scheme: "https", source: "operator", cert: "/etc/mf/chain.pem", cert_present: true },
    });
    assert.strictEqual(trustAnchorFor(facts), "/etc/mf/chain.pem");
  });

  test("a declared upstream terminator anchors nothing — there is no engine handshake", () => {
    const facts = parseApiTls({
      api_tls: { scheme: "http", source: "upstream", cert: null, cert_present: false },
    });
    assert.strictEqual(facts?.scheme, "http");
    assert.strictEqual(trustAnchorFor(facts), undefined);
  });

  test("the host key is scheme-free and case-folded, so one anchor serves both spellings", () => {
    assert.strictEqual(engineHostKey("https://127.0.0.1:8765"), "127.0.0.1:8765");
    assert.strictEqual(engineHostKey("http://127.0.0.1:8765/x"), "127.0.0.1:8765");
    assert.strictEqual(engineHostKey("https://Engine.Example.COM:8765"), "engine.example.com:8765");
    assert.strictEqual(engineHostKey("not a url"), undefined);
  });

  test("scheme disagreement is REPORTED, never silently corrected (SEC-005)", () => {
    const https = parseApiTls(GENERATED);
    assert.match(
      schemeMismatch(https, "http://127.0.0.1:8765") ?? "",
      /engineUrl is http:\/\/ but this engine serves https/,
    );
    assert.strictEqual(schemeMismatch(https, "https://127.0.0.1:8765"), undefined);

    const upstream = parseApiTls({
      api_tls: { scheme: "http", source: "upstream", cert: null, cert_present: false },
    });
    assert.match(
      schemeMismatch(upstream, "https://127.0.0.1:8765") ?? "",
      /tls_terminated_upstream/,
      "a client that assumes https breaks the one topology the engine deliberately leaves plaintext",
    );
  });
});

suite("which target may have the local certificate, and where that file is", () => {
  // The composition `engineTrust.ts` calls. `engine-trust-shell.test.ts` drives it through the real
  // refresh against real files; this block pins the decision matrix itself.
  const WS = path.resolve(path.sep, "ws");
  const LOCAL_ABS = path.join(WS, "state", "api-generated-cert.pem");

  function factsFor(cert: string): ReturnType<typeof parseApiTls> {
    return parseApiTls({
      api_tls: { scheme: "https", source: "operator", cert, cert_present: true },
    });
  }

  test("every loopback spelling is anchored; everything else is refused as notLocal", () => {
    const facts = factsFor(LOCAL_ABS);
    for (const local of ["https://127.0.0.1:8765", "https://localhost:8765", "https://[::1]:8765"]) {
      assert.deepStrictEqual(
        trustAnchorForTarget(facts, local, WS),
        { kind: "anchor", file: LOCAL_ABS },
        local,
      );
    }
    // NEGATIVE CONTROL. `messagefoundry.serviceConfig` describes the LOCAL engine, so handing its
    // certificate to any of these anchors a file belonging to a different server — and `ca` REPLACES
    // Node's default root store, so a valid public chain would stop verifying.
    for (const remote of [
      "https://prod.example.com:8765",
      "https://10.0.0.7:8765",
      "https://127.0.0.1.evil.example:8765",
      "not a url",
    ]) {
      assert.deepStrictEqual(trustAnchorForTarget(facts, remote, WS), { kind: "notLocal" }, remote);
    }
  });

  test("a relative path is resolved against the workspace; an absolute one is left alone", () => {
    // The engine passes an operator's `[api].tls_cert_file` through UNCHANGED, so a relative operator
    // path arrives verbatim and must be resolved against the directory `cert inventory` ran in.
    assert.deepStrictEqual(
      trustAnchorForTarget(factsFor("certs/server.pem"), "https://127.0.0.1:8765", WS),
      { kind: "anchor", file: path.join(WS, "certs", "server.pem") },
    );
    assert.deepStrictEqual(
      trustAnchorForTarget(factsFor(LOCAL_ABS), "https://127.0.0.1:8765", WS),
      { kind: "anchor", file: LOCAL_ABS },
    );
  });

  test("no anchor can escape the workspace through a process cwd", () => {
    // The win32 case that separates `path.resolve` from join/normalize: resolve('C:\\ws',
    // 'D:certs\\server.pem') returns 'D:\\certs\\server.pem' — it drops the workspace because the
    // devices differ and falls back to that DRIVE's cwd (process.env['=D:']), which is the
    // extension-host-cwd read this whole function exists to remove. Asserted as a property rather
    // than a literal so it holds on both platforms.
    for (const odd of ["D:certs\\server.pem", "certs/../certs/server.pem", "./server.pem"]) {
      const decision = trustAnchorForTarget(factsFor(odd), "https://127.0.0.1:8765", WS);
      assert.strictEqual(decision.kind, "anchor", odd);
      assert.ok(
        decision.kind === "anchor" && decision.file.startsWith(WS),
        `${odd} resolved outside the workspace: ${JSON.stringify(decision)}`,
      );
    }
  });

  test("nothing anchorable is 'nothing', not 'notLocal' — the two reasons stay apart", () => {
    // The shell logs on `notLocal` only. Folding these into it would tell a user with an engine that
    // has simply never started that their loopback URL is not a loopback address.
    const notYet = parseApiTls({
      api_tls: { scheme: "https", source: "generated", cert: "/s/c.pem", cert_present: false },
    });
    const upstream = parseApiTls({
      api_tls: { scheme: "http", source: "upstream", cert: null, cert_present: false },
    });
    for (const [facts, url] of [
      [notYet, "https://127.0.0.1:8765"],
      [upstream, "http://127.0.0.1:8765"],
      [undefined, "https://127.0.0.1:8765"],
      [notYet, "https://prod.example.com:8765"], // remote AND nothing to anchor: nothing wins
    ] as const) {
      assert.deepStrictEqual(trustAnchorForTarget(facts, url, WS), { kind: "nothing" }, url);
    }
  });
});

suite("a trust failure is not an absent engine (BACKLOG #1695)", () => {
  test("every trust code carries a remedy, and the non-trust codes carry none", () => {
    assert.ok(TLS_TRUST_CODES.length > 0, "an empty code list would pass every assertion below");
    for (const code of TLS_TRUST_CODES) {
      assert.ok(isTlsTrustError(code), code);
      assert.match(trustRemedy(code, "https://127.0.0.1:8765") ?? "", /serviceConfig/);
    }
    // NEGATIVE CONTROL. These are verification failures too, with DIFFERENT remedies — folding them
    // in would tell a user with an expired cert to check a settings path that is already correct.
    for (const other of ["ECONNREFUSED", "CERT_HAS_EXPIRED", "ERR_TLS_CERT_ALTNAME_INVALID", undefined]) {
      assert.strictEqual(isTlsTrustError(other), false, String(other));
      assert.strictEqual(trustRemedy(other, "https://127.0.0.1:8765"), undefined);
    }
  });

  test("a REMOTE engine is not told to check a local settings path", () => {
    // messagefoundry.serviceConfig is a workspace-relative path to the LOCAL engine's TOML. A remote
    // engine reads its own filesystem, so naming that setting sends the user to fix a file with no
    // bearing on the host that just failed to verify.
    const remote = trustRemedy("DEPTH_ZERO_SELF_SIGNED_CERT", "https://prod-host:8765") ?? "";
    assert.match(remote, /remote engine's must be trusted by this machine/);
    assert.ok(
      !/check that `messagefoundry\.serviceConfig` names it/.test(remote),
      `the loopback remedy leaked into the remote one: ${remote}`,
    );
    // The control: loopback still gets the local remedy, so the branch really does branch.
    assert.match(
      trustRemedy("DEPTH_ZERO_SELF_SIGNED_CERT", "https://127.0.0.1:8765") ?? "",
      /check that `messagefoundry\.serviceConfig` names it/,
    );
  });

  test("the status bar does not call an unverifiable certificate 'nothing is listening'", () => {
    const trust = describeNetworkCode("DEPTH_ZERO_SELF_SIGNED_CERT", "https://127.0.0.1:8765");
    assert.match(trust, /cannot verify/);
    assert.ok(!/nothing is listening/.test(trust), trust);
    // ONE wording, not two: the status bar composes trustRemedy rather than re-authoring it.
    assert.strictEqual(trust, trustRemedy("DEPTH_ZERO_SELF_SIGNED_CERT", "https://127.0.0.1:8765"));
    // The control: the code that really does mean nothing is listening still says so.
    assert.match(
      describeNetworkCode("ECONNREFUSED", "https://127.0.0.1:8765"),
      /nothing is listening/,
    );
    assert.match(describeNetworkCode("CERT_HAS_EXPIRED", "https://127.0.0.1:8765"), /expired/);
  });
});

suite("the registered anchor reaches the TLS layer", () => {
  // Asserted on the options object the client actually hands Node, the same way the TLS floor is
  // (extension-hardening.test.ts) — grepping for `ca` would not show that it survives to the wire.
  const PEM = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n";
  const httpsModule = require("node:https") as { request: typeof httpsTypes.request };
  let captured: httpsTypes.RequestOptions | undefined;
  let realRequest: typeof httpsTypes.request;

  setup(() => {
    captured = undefined;
    clearEngineTrustAnchors();
    realRequest = httpsModule.request;
    httpsModule.request = ((_url: unknown, options: httpsTypes.RequestOptions): unknown => {
      captured = options;
      throw new Error("intercepted before the socket");
    }) as unknown as typeof httpsTypes.request;
  });

  teardown(() => {
    httpsModule.request = realRequest;
    clearEngineTrustAnchors();
  });

  test("with no anchor registered the request is byte-identical to before", () => {
    assert.deepStrictEqual(tlsOptions(new URL("https://127.0.0.1:8765")), {
      minVersion: "TLSv1.2",
    });
  });

  test("a registered anchor rides along as `ca`, and rejectUnauthorized is never touched", () => {
    setEngineTrustAnchor("https://127.0.0.1:8765", PEM);
    const opts = tlsOptions(new URL("https://127.0.0.1:8765"));
    assert.strictEqual(opts.ca, PEM);
    assert.strictEqual(opts.minVersion, "TLSv1.2");
    assert.ok(
      !("rejectUnauthorized" in opts),
      "verification must stay on in every posture — the anchor widens what can succeed, nothing else",
    );
  });

  test("the anchor reaches getJson's real request options", async () => {
    setEngineTrustAnchor("https://127.0.0.1:8765", PEM);
    await assert.rejects(getJson("https://127.0.0.1:8765", "/health"));
    assert.ok(captured, "the interceptor never ran — the test proves nothing");
    assert.strictEqual(captured!.ca, PEM);
  });

  test("an anchor for one engine is not offered to another", async () => {
    setEngineTrustAnchor("https://127.0.0.1:8765", PEM);
    await assert.rejects(getJson("https://other.example.com:8765", "/health"));
    assert.ok(captured, "the interceptor never ran — the test proves nothing");
    assert.strictEqual(captured!.ca, undefined);
  });

  test("clearing drops it", () => {
    setEngineTrustAnchor("https://127.0.0.1:8765", PEM);
    setEngineTrustAnchor("https://127.0.0.1:8765", undefined);
    assert.strictEqual(tlsOptions(new URL("https://127.0.0.1:8765")).ca, undefined);
  });
});

suite("the http default is pinned in BOTH places (BACKLOG #1695)", () => {
  // The default lives twice — in the manifest (what a user who never touched the setting gets) and
  // as cli.ts's `get` fallback. Nothing in VS Code reconciles them, and the pre-#1695 value was
  // `http://`, which cannot reach an engine that always serves TLS.
  const ROOT = path.join(__dirname, "..", "..", "..");
  const EXPECTED = "https://127.0.0.1:8765";

  test("package.json and cli.ts agree, and both say https", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
      contributes: { configuration: { properties: Record<string, { default?: unknown }> } };
    };
    const declared = pkg.contributes.configuration.properties["messagefoundry.engineUrl"].default;
    assert.strictEqual(declared, EXPECTED);

    const cli = fs.readFileSync(path.join(ROOT, "src", "cli.ts"), "utf8");
    const fallback = /config\(\)\.get<string>\("engineUrl",\s*"([^"]+)"\)/.exec(cli);
    assert.ok(fallback, "engineUrl()'s fallback moved — re-point this scan before trusting it");
    assert.strictEqual(fallback![1], EXPECTED);
  });
});
