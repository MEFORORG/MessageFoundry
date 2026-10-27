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
import { EventEmitter } from "events";
import * as fs from "fs";
import * as path from "path";
import type * as httpsTypes from "https";

import {
  CertificateChangedError,
  clearEngineTrustAnchors,
  getJson,
  postJson,
  setEngineTrustAnchor,
  setPinnedEngineHosts,
  setTrustFailureHandler,
  snapshotEngineTrustAnchors,
  TLS_12_SUITES,
  TLS_13_SUITES,
  TLS_CIPHERS,
  tlsOptions,
} from "../../engineClient";
import { describeNetworkCode } from "../../engineStatusModel";
import {
  CAFILE_REFUSED_CODE,
  CAFILE_UNREAD_CODE,
  TLS_TRUST_CODES,
  engineHostKey,
  hostPinsOf,
  isFullyQualifiedPath,
  isTlsTrustError,
  parseApiTls,
  pinnedFile,
  pinTargetsOf,
  schemeMismatch,
  trustAnchorFor,
  trustAnchorForTarget,
  trustPinsFor,
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

  test("a request refused for an unread caFile is a trust failure that names the setting", () => {
    // A trust failure, so the failure handler reads the file and the request is not called absent.
    assert.ok(isTlsTrustError(CAFILE_UNREAD_CODE));
    for (const url of ["https://prod-host:8765", "https://127.0.0.1:8765"]) {
      const text = describeNetworkCode(CAFILE_UNREAD_CODE, url);
      assert.strictEqual(text, trustRemedy(CAFILE_UNREAD_CODE, url));
      assert.match(text, /caFile in `messagefoundry\.environments`/);
      assert.match(text, /never verified against the default CAs/);
      // Not the serviceConfig remedy: a pinned host never takes that certificate.
      assert.ok(!/serviceConfig/.test(text), text);
    }
  });

  test("hostPinsOf: an accepted pin wins over any refusal for its host; http:// claims nothing", () => {
    const flavour = path.posix;
    const hosts = hostPinsOf(
      trustPinsFor(
        [
          { url: "https://a:1", caFile: "rel/ca.pem" }, // refused before the accepted pin
          { url: "https://a:1", caFile: "/pki/a.pem" },
          { url: "https://a:1", caFile: "/pki/other.pem" }, // conflict, refused after it
          { url: "https://b:1", caFile: 7 },
          { url: "https://b:1", caFile: "rel/b.pem" }, // the first reason is kept
          { url: "http://c:1", caFile: "rel/c.pem" },
        ],
        flavour,
      ),
    );
    assert.deepStrictEqual(hosts.get("a:1"), { kind: "pin", file: "/pki/a.pem" });
    assert.deepStrictEqual(hosts.get("b:1"), { kind: "refused", reason: "caFile is not a string" });
    assert.strictEqual(hosts.has("c:1"), false);
    assert.strictEqual(pinnedFile(hosts, "a:1"), "/pki/a.pem");
    assert.strictEqual(pinnedFile(hosts, "b:1"), undefined);
  });

  test("a request refused for a refused caFile names the reason, not a file to make readable", () => {
    assert.ok(isTlsTrustError(CAFILE_REFUSED_CODE));
    assert.notStrictEqual(CAFILE_REFUSED_CODE, CAFILE_UNREAD_CODE);
    const url = "https://prod-host:8765";
    const text = trustRemedy(CAFILE_REFUSED_CODE, url, "caFile pki/ca.pem is not an absolute path") ?? "";
    assert.match(text, /\(caFile pki\/ca\.pem is not an absolute path\)/);
    assert.match(text, /never verified against the default CAs/);
    assert.match(text, /Correct the caFile, or remove it/);
    assert.ok(!/exists/.test(text), `sends the user to look for a file: ${text}`);
    // With no reason (the status bar has only the code), it still names the setting and the fix.
    const bare = describeNetworkCode(CAFILE_REFUSED_CODE, url);
    assert.match(bare, /caFile in `messagefoundry\.environments` was refused/);
    assert.ok(!/serviceConfig/.test(bare), bare);
  });
});

suite("the registered anchor reaches the TLS layer", () => {
  // Asserted on the options object the client actually hands Node, the same way the TLS floor is
  // (extension-hardening.test.ts) — grepping for `ca` would not show that it survives to the wire.
  const PEM = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n";
  const httpsModule = require("node:https") as { request: typeof httpsTypes.request };
  let captured: httpsTypes.RequestOptions | undefined;
  let realRequest: typeof httpsTypes.request;
  // Restored, not cleared: in the Extension Host leg engineTrust.ts holds its own record of these.
  let restoreAnchors: () => void;

  setup(() => {
    captured = undefined;
    restoreAnchors = snapshotEngineTrustAnchors();
    setPinnedEngineHosts([]); // the activated extension's own pins must not refuse these requests
    clearEngineTrustAnchors();
    realRequest = httpsModule.request;
    httpsModule.request = ((_url: unknown, options: httpsTypes.RequestOptions): unknown => {
      captured = options;
      throw new Error("intercepted before the socket");
    }) as unknown as typeof httpsTypes.request;
  });

  teardown(() => {
    httpsModule.request = realRequest;
    restoreAnchors();
  });

  test("with no anchor registered the request carries only the floor and the suite pin", () => {
    // BACKLOG #300 added `ciphers`; the anchor is still absent, which is what this test is about.
    assert.deepStrictEqual(tlsOptions(new URL("https://127.0.0.1:8765")), {
      minVersion: "TLSv1.2",
      ciphers: TLS_CIPHERS,
    });
  });

  test("the suite pin is the approved AEAD list and carries no CBC suite (BACKLOG #300)", () => {
    const opts = tlsOptions(new URL("https://127.0.0.1:8765"));
    assert.strictEqual(opts.ciphers, TLS_12_SUITES.concat(TLS_13_SUITES).join(":"));
    assert.strictEqual(TLS_12_SUITES.length, 5);
    assert.strictEqual(TLS_13_SUITES.length, 2);
    for (const name of TLS_12_SUITES.concat(TLS_13_SUITES)) {
      assert.ok(/GCM|CHACHA20/.test(name), `${name} is not an AEAD suite`);
      // Owner ruling R4 of 2026-09-26 (BACKLOG #2042): no AES-128 suite named at either version.
      assert.ok(!/AES128|AES_128/.test(name), `${name} is an AES-128 suite`);
    }
    setEngineTrustAnchor("https://127.0.0.1:8765", PEM);
    assert.strictEqual(
      tlsOptions(new URL("https://127.0.0.1:8765")).ciphers,
      TLS_CIPHERS,
      "a registered anchor must not drop the suite pin",
    );
  });

  test("plain http carries no TLS options at all, the pin included", () => {
    assert.deepStrictEqual(tlsOptions(new URL("http://127.0.0.1:8765")), {});
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

suite("per-target caFile pins (BACKLOG #1695, residual a)", () => {
  const WIN_PIN = "C:\\pki\\prod-ca.pem";
  const POSIX_PIN = "/etc/mf/prod-ca.pem";

  test("an engine shard takes its own caFile, else its environment's", () => {
    assert.deepStrictEqual(
      pinTargetsOf([
        {
          url: "https://prod:8765",
          caFile: POSIX_PIN,
          shards: [
            { url: "https://prod-1:8765" },
            { url: "https://prod-2:8765", caFile: "/etc/mf/other.pem" },
          ],
        },
        { url: "https://dev:8765" },
      ]),
      [
        { url: "https://prod:8765", caFile: POSIX_PIN },
        { url: "https://prod-1:8765", caFile: POSIX_PIN },
        { url: "https://prod-2:8765", caFile: "/etc/mf/other.pem" },
        { url: "https://dev:8765", caFile: undefined },
      ],
    );
  });

  test("no caFile is the ordinary case: no pin and no refusal", () => {
    const targets = [{ url: "https://dev:8765" }, { url: "https://qa:8765", caFile: "" }];
    assert.deepStrictEqual(trustPinsFor(targets, path.posix), []);
  });

  test("a full path pins its target, keyed by host:port", () => {
    assert.deepStrictEqual(
      trustPinsFor([{ url: "https://Prod:8765", caFile: POSIX_PIN }], path.posix),
      [{ kind: "pin", url: "https://Prod:8765", key: "prod:8765", file: POSIX_PIN }],
    );
    assert.deepStrictEqual(
      trustPinsFor([{ url: "https://prod:8765", caFile: WIN_PIN }], path.win32),
      [{ kind: "pin", url: "https://prod:8765", key: "prod:8765", file: WIN_PIN }],
    );
  });

  test("a path that depends on a cwd is refused, never resolved", () => {
    // A relative path would be read against the workspace or the extension host's cwd, and the
    // machine scope exists to keep a workspace out of this decision. On Windows a ROOT-relative path
    // depends on the current drive, so it is refused even though path.win32.isAbsolute accepts it.
    const cases: [string, typeof path.posix][] = [
      ["certs/ca.pem", path.posix],
      ["./ca.pem", path.posix],
      ["certs\\ca.pem", path.win32],
      ["\\pki\\ca.pem", path.win32],
      ["C:pki\\ca.pem", path.win32],
      ["/pki/ca.pem", path.win32],
      // Device namespaces are not files, and a read of one can block the extension host.
      ["\\\\.\\pipe\\x", path.win32],
      ["\\\\?\\C:\\pki\\ca.pem", path.win32],
    ];
    for (const [caFile, flavour] of cases) {
      const [decision] = trustPinsFor([{ url: "https://prod:8765", caFile }], flavour);
      assert.strictEqual(decision?.kind, "refused", caFile);
    }
    // The controls: the full spellings on each flavour are accepted, and the root-relative case
    // really is one that path.win32.isAbsolute would have let through.
    assert.ok(isFullyQualifiedPath("C:/pki/ca.pem", path.win32));
    assert.ok(isFullyQualifiedPath("\\\\pki-host\\share\\ca.pem", path.win32));
    assert.ok(isFullyQualifiedPath(POSIX_PIN, path.posix));
    assert.ok(path.win32.isAbsolute("\\pki\\ca.pem"));
  });

  test("a non-string caFile, an http url and an unparseable url are refused", () => {
    const decisions = trustPinsFor(
      [
        { url: "https://prod:8765", caFile: 42 },
        { url: "http://prod:8765", caFile: POSIX_PIN },
        { url: "not a url", caFile: POSIX_PIN },
      ],
      path.posix,
    );
    assert.deepStrictEqual(
      decisions.map((d) => d.kind),
      ["refused", "refused", "refused"],
    );
    // An https refusal still claims its host, so it is not handed the workspace's certificate. An
    // http one claims nothing: its key has no scheme and would take an https engine's anchor.
    assert.deepStrictEqual(
      decisions.map((d) => (d.kind === "refused" ? d.claims : d.key)),
      ["prod:8765", undefined, undefined],
    );
  });

  test("a second, different file for one host:port is refused; the same file twice is not", () => {
    const decisions = trustPinsFor(
      [
        { url: "https://prod:8765", caFile: POSIX_PIN },
        { url: "https://PROD:8765/mf", caFile: POSIX_PIN },
        { url: "https://prod:8765", caFile: "/etc/mf/other.pem" },
      ],
      path.posix,
    );
    assert.deepStrictEqual(
      decisions.map((d) => d.kind),
      ["pin", "refused"],
    );
    const refusal = decisions[1];
    assert.ok(refusal?.kind === "refused");
    assert.match(refusal.reason, /already pinned to \/etc\/mf\/prod-ca\.pem/);
  });

  test("on Windows two spellings of one file differing only in case are one file", () => {
    const decisions = trustPinsFor(
      [
        { url: "https://prod:8765", caFile: "C:\\PKI\\ca.pem" },
        { url: "https://prod:8765", caFile: "c:\\pki\\ca.pem" },
      ],
      path.win32,
    );
    assert.deepStrictEqual(
      decisions.map((d) => d.kind),
      ["pin"],
    );
  });

  test("an engine shard's empty caFile inherits its environment's, like an absent one", () => {
    const [, shard] = pinTargetsOf([
      { url: "https://prod:8765", caFile: POSIX_PIN, shards: [{ url: "https://p1:8765", caFile: "" }] },
    ]);
    assert.strictEqual(shard?.caFile, POSIX_PIN);
  });

  test("the remote remedy names caFile", () => {
    assert.match(
      trustRemedy("DEPTH_ZERO_SELF_SIGNED_CERT", "https://prod-host:8765") ?? "",
      /set `caFile` on its `messagefoundry\.environments` entry/,
    );
  });
});

suite("a request that fails verification follows a changed anchor once (BACKLOG #1695, c)", () => {
  const TARGET = "https://127.0.0.1:8765";
  const OLD = "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n";
  const NEW = "-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n";
  const httpsModule = require("node:https") as { request: typeof httpsTypes.request };
  let realRequest: typeof httpsTypes.request;
  let calls: { ca: unknown }[];

  /** A request that fails the handshake the way Node reports an untrusted self-signed certificate. */
  function failingRequest(_url: unknown, options: httpsTypes.RequestOptions): unknown {
    calls.push({ ca: options.ca });
    const req = new EventEmitter() as EventEmitter & Record<string, unknown>;
    req.setTimeout = (): unknown => req;
    req.write = (): boolean => true;
    req.destroy = (): unknown => req;
    req.end = (): unknown => {
      const err = Object.assign(new Error("self-signed certificate"), {
        code: "DEPTH_ZERO_SELF_SIGNED_CERT",
      });
      setImmediate(() => req.emit("error", err));
      return req;
    };
    return req;
  }

  // Saved and restored, not just cleared: in the Extension Host leg activation has installed the
  // production handler, and this suite must hand it back for the suites after it.
  let savedHandler: ReturnType<typeof setTrustFailureHandler>;
  // The same for the anchors: clearing every one at teardown left engineTrust.ts's record of what it
  // registered disagreeing with what the client holds, for every suite after this one.
  let restoreAnchors: () => void;

  setup(() => {
    calls = [];
    restoreAnchors = snapshotEngineTrustAnchors();
    setPinnedEngineHosts([]); // the activated extension's own pins must not refuse these requests
    clearEngineTrustAnchors();
    setEngineTrustAnchor(TARGET, OLD);
    savedHandler = setTrustFailureHandler(undefined);
    realRequest = httpsModule.request;
    httpsModule.request = failingRequest as unknown as typeof httpsTypes.request;
  });

  teardown(() => {
    httpsModule.request = realRequest;
    setTrustFailureHandler(savedHandler);
    restoreAnchors();
  });

  test("a handler that registers a new anchor gets exactly one retry, carrying it", async () => {
    const seen: (string | undefined)[] = [];
    setTrustFailureHandler(async (url, usedCa) => {
      seen.push(usedCa);
      setEngineTrustAnchor(url, NEW);
      return true;
    });
    await assert.rejects(getJson(TARGET, "/health"), /cannot verify/);
    assert.deepStrictEqual(
      calls.map((c) => c.ca),
      [OLD, NEW],
      "the retry must carry the new anchor, and there is exactly one",
    );
    assert.deepStrictEqual(seen, [OLD], "the handler is told which anchor the failed request used");
  });

  test("a POST is NOT retried, but the anchor is still followed for the next request", async () => {
    // Whether Node can flush a POST before its JS-side verification fails is unmeasured, and a
    // reload or a dual-control approval sent twice is costly. So: report, follow, do not resend.
    let told = 0;
    setTrustFailureHandler(async (url) => {
      told++;
      setEngineTrustAnchor(url, NEW);
      return true;
    });
    // And the user is told a retry will work, not sent to fix a configuration that is not at fault.
    await assert.rejects(postJson(TARGET, "/config/reload", {}), (err: unknown) => {
      assert.ok(err instanceof CertificateChangedError, String(err));
      assert.ok(/certificate .* changed/.test(err.message) && /Retry/.test(err.message), err.message);
      assert.ok(!/serviceConfig|caFile/.test(err.message), err.message);
      assert.strictEqual(err.code, "DEPTH_ZERO_SELF_SIGNED_CERT");
      return true;
    });
    assert.deepStrictEqual(
      calls.map((c) => c.ca),
      [OLD],
    );
    assert.strictEqual(told, 1, "the handler was not told, so the next request would fail too");
    assert.strictEqual(tlsOptions(new URL(TARGET)).ca, NEW);
  });

  test("a POST whose handler followed nothing keeps the trust error and its remedy — the control", async () => {
    setTrustFailureHandler(async () => false);
    await assert.rejects(postJson(TARGET, "/config/reload", {}), (err: unknown) => {
      assert.ok(!(err instanceof CertificateChangedError), String(err));
      assert.ok(/cannot verify/.test(String(err)), String(err));
      return true;
    });
    assert.strictEqual(calls.length, 1);
  });

  test("a snapshot restores exactly the anchors it captured", () => {
    const restore = snapshotEngineTrustAnchors();
    setEngineTrustAnchor("https://other.example.com:8765", NEW);
    clearEngineTrustAnchors();
    restore();
    assert.strictEqual(tlsOptions(new URL(TARGET)).ca, OLD);
    assert.strictEqual(tlsOptions(new URL("https://other.example.com:8765")).ca, undefined);
  });

  test("a handler that changed nothing gets no retry — the control", async () => {
    setTrustFailureHandler(async () => false);
    await assert.rejects(getJson(TARGET, "/health"), /cannot verify/);
    assert.strictEqual(calls.length, 1);
  });

  test("with no handler installed the request fails once, as before", async () => {
    await assert.rejects(getJson(TARGET, "/health"), /cannot verify/);
    assert.strictEqual(calls.length, 1);
  });

  test("a handler that throws does not replace the trust error", async () => {
    setTrustFailureHandler(async () => {
      throw new Error("boom");
    });
    await assert.rejects(getJson(TARGET, "/health"), /cannot verify/);
    assert.strictEqual(calls.length, 1);
  });
});
