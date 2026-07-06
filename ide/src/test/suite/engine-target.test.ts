import * as assert from "assert";

import { assertTargetAllowed, isLocalEngine } from "../../engineTarget";

// SEC-005 regression. assertTargetAllowed is the pure gate that runs BEFORE any credential prompt or
// token send: loopback over http is allowed (the dev flow), non-loopback over plain http is refused
// (credentials would go in clear off-box), https off-box is allowed (the confirmation modal follows),
// and an unparseable URL fails safe.
suite("assertTargetAllowed (SEC-005)", () => {
  test("loopback over http is allowed (127.0.0.1)", () => {
    assert.deepStrictEqual(assertTargetAllowed("http://127.0.0.1:8765"), { ok: true });
  });

  test("loopback over http is allowed (localhost and ::1)", () => {
    assert.strictEqual(assertTargetAllowed("http://localhost:8765").ok, true);
    assert.strictEqual(assertTargetAllowed("http://[::1]:8765").ok, true);
  });

  test("non-loopback over plain http is REFUSED (the core SEC-005 case)", () => {
    const r = assertTargetAllowed("http://evil.internal:8765");
    assert.strictEqual(r.ok, false);
    assert.ok(!r.ok && /evil\.internal/.test(r.reason), "the refusal names the host");
    assert.ok(!r.ok && /https/.test(r.reason), "the refusal recommends https");
  });

  test("https off-box is allowed (TLS — the confirmation path follows)", () => {
    assert.deepStrictEqual(assertTargetAllowed("https://prod-host:8765"), { ok: true });
  });

  test("an unparseable URL fails safe (not ok)", () => {
    assert.strictEqual(assertTargetAllowed("not a url").ok, false);
  });
});

suite("isLocalEngine (SEC-005)", () => {
  test("classifies the loopback host set", () => {
    assert.strictEqual(isLocalEngine("http://127.0.0.1:8765"), true);
    assert.strictEqual(isLocalEngine("http://localhost:8765"), true);
    assert.strictEqual(isLocalEngine("https://[::1]:8765"), true);
    assert.strictEqual(isLocalEngine("https://prod-host:8765"), false);
    assert.strictEqual(isLocalEngine("garbage"), false);
  });
});
