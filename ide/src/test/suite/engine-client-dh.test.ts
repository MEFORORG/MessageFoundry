// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #300. The IDE offers one DHE suite (`DHE-RSA-AES256-GCM-SHA384`, a copy of the engine's
// approved list), and Node's own floor on a DHE group is 1024 bits. These tests run real TLS 1.2
// handshakes against a local server that offers only that suite, so what they pin is what reaches the
// wire, not a field on an options object alone.
//
// Measured on Node 24.20.0 / OpenSSL 3.5.7, with this file's own server and certificate:
//   group      client options                                result
//   1536 bit   default OpenSSL level, either minDHSize       EPROTO "dh key too small" (level 2)
//   1536 bit   shipped ciphers + @SECLEVEL=1, minDHSize 1024 handshake completes
//   1536 bit   shipped ciphers + @SECLEVEL=1, minDHSize 2048 ERR_TLS_DH_PARAM_SIZE
//   2048 bit   shipped ciphers, minDHSize 2048               handshake completes
// So on this runtime OpenSSL's default security level already refuses under 2048. `minDHSize` is what
// holds the floor where that level is 1: OpenSSL before 3.2 defaults to it, and a system OpenSSL
// configuration can lower it. The tests below therefore lower the level themselves, to show the
// option does the refusing.
import * as assert from "assert";
import * as crypto from "crypto";
import * as https from "https";
import type { AddressInfo } from "net";
import * as tls from "tls";

import {
  clearEngineTrustAnchors,
  getJson,
  setEngineTrustAnchor,
  setPinnedEngineHosts,
  snapshotEngineTrustAnchors,
  TLS_CIPHERS,
  tlsOptions,
} from "../../engineClient";
import type { EngineTlsOptions } from "../../engineClient";

/** The one DHE suite the IDE offers; the test server offers nothing else, so DHE is what runs. */
const DHE_SUITE = "DHE-RSA-AES256-GCM-SHA384";

/** A DER TLV. Only what a minimal self-signed certificate and a DH parameter block need. */
function der(tag: number, body: Buffer): Buffer {
  let length: Buffer;
  if (body.length < 0x80) {
    length = Buffer.from([body.length]);
  } else {
    const hex = body.length.toString(16);
    const bytes = Buffer.from(hex.length % 2 === 0 ? hex : `0${hex}`, "hex");
    length = Buffer.concat([Buffer.from([0x80 | bytes.length]), bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), length, body]);
}

const sequence = (...parts: Buffer[]): Buffer => der(0x30, Buffer.concat(parts));
const integer = (value: Buffer): Buffer =>
  der(0x02, value[0] & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value);
const utcTime = (at: Date): Buffer =>
  der(0x17, Buffer.from(`${at.toISOString().replace(/[-:T]/g, "").slice(2, 14)}Z`));

function toPem(label: string, body: Buffer): string {
  const lines = body.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/**
 * A throwaway self-signed certificate for 127.0.0.1, minted in memory. Node has no API that makes one,
 * and a key checked into the tree would trip the secret scan, so the few DER fields it needs are
 * written out here. It is passed as `ca`, so the client verifies it exactly as it verifies the engine's
 * own minted certificate: verification stays on.
 */
function mintCertificate(): { key: string; cert: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const sha256WithRsa = sequence(Buffer.from("06092a864886f70d01010b", "hex"), Buffer.from([5, 0]));
  const name = sequence(
    der(0x31, sequence(Buffer.from("0603550403", "hex"), der(0x0c, Buffer.from("mefor dh test")))),
  );
  const ipSan = sequence(
    Buffer.from("0603551d11", "hex"),
    der(0x04, sequence(der(0x87, Buffer.from([127, 0, 0, 1])))),
  );
  const now = Date.now();
  const tbs = sequence(
    Buffer.from("a003020102", "hex"), // version 3
    integer(Buffer.from([1])),
    sha256WithRsa,
    name,
    sequence(utcTime(new Date(now - 86_400_000)), utcTime(new Date(now + 86_400_000))),
    name,
    publicKey.export({ type: "spki", format: "der" }),
    der(0xa3, sequence(ipSan)),
  );
  const signature = crypto.sign("sha256", tbs, privateKey);
  const cert = sequence(tbs, sha256WithRsa, der(0x03, Buffer.concat([Buffer.from([0]), signature])));
  return {
    key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    cert: toPem("CERTIFICATE", cert),
  };
}

/** One of the RFC 2409 / 3526 MODP groups, as the PEM `dhparam` a Node TLS server takes. */
function dhParams(group: "modp5" | "modp14"): string {
  const dh = crypto.getDiffieHellman(group);
  return toPem("DH PARAMETERS", sequence(integer(dh.getPrime()), integer(dh.getGenerator())));
}

/** Whether this runtime's TLS library can negotiate the DHE suite at all. BoringSSL, under VS Code's
 *  desktop Electron, is taken to have none, so the floor has nothing to act on there. */
function runtimeSpeaksDhe(): boolean {
  return process.versions.electron === undefined && tls.getCiphers().includes(DHE_SUITE.toLowerCase());
}

suite("the IDE refuses a DHE group under 2048 bits (BACKLOG #300)", function () {
  this.timeout(20_000);
  let material: { key: string; cert: string };
  const servers: https.Server[] = [];
  let restoreAnchors: () => void;

  suiteSetup(function () {
    if (!runtimeSpeaksDhe()) {
      this.skip();
    }
    material = mintCertificate();
  });

  setup(() => {
    restoreAnchors = snapshotEngineTrustAnchors();
    setPinnedEngineHosts([]); // the activated extension's own pins must not refuse these requests
    clearEngineTrustAnchors();
  });

  teardown(() => {
    for (const server of servers.splice(0)) {
      server.closeAllConnections();
      server.close();
    }
    restoreAnchors();
  });

  /** A TLS 1.2 server that offers only the DHE suite, over `group`. Its own level is lowered so it
   *  will SERVE a small group: what is under test is whether the client accepts one. */
  async function serve(group: "modp5" | "modp14"): Promise<string> {
    const server = https.createServer(
      {
        key: material.key,
        cert: material.cert,
        dhparam: dhParams(group),
        ciphers: `${DHE_SUITE}:@SECLEVEL=0`,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.2",
      },
      (_req, res) => {
        res.setHeader("Content-Type", "application/json");
        res.end("{}");
      },
    );
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  /** One handshake with `options`, answering the DH size negotiated or the error code. */
  function handshake(base: string, options: EngineTlsOptions): Promise<string> {
    return new Promise((resolve) => {
      const req = https.request(
        `${base}/health`,
        { agent: false, ...options, ca: material.cert },
        (res) => {
          const info = (res.socket as tls.TLSSocket).getEphemeralKeyInfo();
          res.resume();
          const size = info !== null && "size" in info ? info.size : "none";
          res.on("end", () => resolve(`completed DH ${size}`));
        },
      );
      req.on("error", (err: NodeJS.ErrnoException) => resolve(err.code ?? err.message));
      req.end();
    });
  }

  test("a 1536-bit group is refused by the floor, where OpenSSL's own level would let it through", async () => {
    const base = await serve("modp5");
    const lowered = `${TLS_CIPHERS}:@SECLEVEL=1`;
    // CONTROL: Node's default floor of 1024 at the same lowered level completes, so the group is
    // negotiable and the refusal below is the floor's, not the server's or OpenSSL's.
    assert.strictEqual(
      await handshake(base, { ...tlsOptions(new URL(base)), ciphers: lowered, minDHSize: 1024 }),
      "completed DH 1536",
    );
    assert.strictEqual(
      await handshake(base, { ...tlsOptions(new URL(base)), ciphers: lowered }),
      "ERR_TLS_DH_PARAM_SIZE",
    );
  });

  test("the real client completes against a 2048-bit group", async () => {
    // The floor must not refuse what it is meant to admit. The engine's own listener was measured
    // accepting ffdhe2048, a 2048-bit group like this one.
    const base = await serve("modp14");
    setEngineTrustAnchor(base, material.cert);
    assert.deepStrictEqual(await getJson(base, "/health"), {});
    assert.strictEqual(
      await handshake(base, tlsOptions(new URL(base))),
      "completed DH 2048",
    );
  });

  test("the real client never completes against a 1536-bit group", async () => {
    // Whichever layer refuses first on this runtime (OpenSSL's level, or the floor where the level
    // is lower), the request the extension makes must fail.
    const base = await serve("modp5");
    setEngineTrustAnchor(base, material.cert);
    await assert.rejects(getJson(base, "/health"), (err: NodeJS.ErrnoException) => {
      assert.ok(
        err.code === "ERR_TLS_DH_PARAM_SIZE" || err.code === "EPROTO",
        `unexpected failure ${err.code}: ${err.message}`,
      );
      return true;
    });
  });
});
