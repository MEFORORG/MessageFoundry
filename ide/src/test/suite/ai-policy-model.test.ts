// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import {
  CACHED_PERMIT_MAX_AGE_MS,
  assistantState,
  cachedPolicyOffline,
  mergeAuthoritativePolicy,
  type AiPolicy,
} from "../../aiPolicyModel";

// BACKLOG #330, defect 1 — the authoritative-merge guard, and its coupling to the gate it feeds.
//
// WHY THIS FILE EXISTS SEPARATELY FROM ai-policy.test.ts: `ide/package.json`'s `test:unit` script
// `--ignore`s `out/test/suite/ai-policy.test.js` (aiPolicy.ts imports vscode), so anything asserted
// only there runs solely in the Windows-only `npm test` leg. These import the zero-import
// aiPolicyModel, so they execute in the node-side runner on EVERY ide CI leg — which is where the
// security invariant belongs.
//
// The rule under test is ASYMMETRIC, and the asymmetry is the whole design: a cached DENY survives a
// fresh `null`; a cached PERMIT does not. Tests T1 and T3 are the two poles, and neither alone can
// tell a correct guard from a broken one.
function policy(p: Partial<AiPolicy>): AiPolicy {
  return {
    mode: "byo",
    dataScope: "code_only",
    environment: null,
    assistPermitted: null,
    reason: null,
    ...p,
  };
}

suite("mergeAuthoritativePolicy (BACKLOG #330 — a degraded read must not upgrade assistance)", () => {
  test("T1: a fresh null does NOT overwrite a cached ai:assist deny", () => {
    // The exact defect-1 regression. `assist_permitted` is identity-dependent, so an unattributed read
    // answers null; writing that raw would re-enable assistance a central policy had switched off.
    const merged = mergeAuthoritativePolicy(
      policy({ assistPermitted: false }),
      policy({ assistPermitted: null }),
    );
    assert.strictEqual(merged.assistPermitted, false);
  });

  test("T2: an evaluable GRANT un-sticks the deny (the escape hatch is signing in)", () => {
    // Without this, the guard would be a permanent lockout: once false was cached, nothing could clear
    // it. T1 alone passes for a guard that never lets go — this is what distinguishes the two.
    const merged = mergeAuthoritativePolicy(
      policy({ assistPermitted: false }),
      policy({ assistPermitted: true }),
    );
    assert.strictEqual(merged.assistPermitted, true);
  });

  test("T3: a cached PERMIT is NOT sticky — null wins, and stays enabled", () => {
    // The fail-OPEN direction, pinned. Carrying a cached `true` over a fresh `null` would fabricate a
    // permit from stale state; `null` under BYO is allowed by design (docs/AI.md's trust note), so the
    // correct behaviour is to take the null and remain enabled — not to invent a grant.
    const merged = mergeAuthoritativePolicy(
      policy({ assistPermitted: true }),
      policy({ assistPermitted: null }),
    );
    assert.strictEqual(merged.assistPermitted, null);
    assert.strictEqual(assistantState(merged).enabled, true);
  });

  test("T4: `mode` is never resurrected from the cache — a central re-enable propagates", () => {
    // Only assistPermitted is retained. mode is identity-INDEPENDENT, so an admin flipping off → byo
    // must take effect on the very next read; a guard that froze the whole policy would pass T1.
    const merged = mergeAuthoritativePolicy(
      policy({ mode: "off", assistPermitted: false }),
      policy({ mode: "byo", assistPermitted: null }),
    );
    assert.strictEqual(merged.mode, "byo");
    assert.strictEqual(merged.assistPermitted, false, "the deny is still retained");
  });

  test("T5: the first ever read (no cache) is a plain pass-through and does not throw", () => {
    const fresh = policy({ mode: "byo", assistPermitted: null });
    assert.deepStrictEqual(mergeAuthoritativePolicy(null, fresh), fresh);
  });

  test("T6: the retained deny actually reaches the GATE, not just the struct", () => {
    // The item's real claim. A field that survives a merge but never changes assistantState's verdict
    // would be a fix in name only.
    const merged = mergeAuthoritativePolicy(
      policy({ mode: "byo", assistPermitted: false }),
      policy({ mode: "byo", assistPermitted: null }),
    );
    const state = assistantState(merged);
    assert.strictEqual(state.enabled, false);
    assert.ok(/ai:assist/i.test(state.message ?? ""), "the message names the missing permission");
  });

  // T7-T9: the guard must key on "is this an EVALUABLE answer", not on the single literal `null`.
  // T1-T6 all construct `assistPermitted: null`, so none of them can see a value that is merely
  // not-null — and `undefined !== null`, so a `=== null` guard lets one straight through.
  test("T7: a fresh answer that OMITS the permission does not overwrite a cached deny", () => {
    // The reachable degraded case: a 200 whose body has no `assist_permitted` at all parses to
    // `undefined`. `AiPolicyWire` is a compile-time claim and JSON.parse does not honour it, so this
    // reaches the merge as a real value. Unguarded it is the fail-OPEN direction — and worse than a
    // one-off, because `undefined` is not `false` either, so the cache is poisoned permanently.
    const merged = mergeAuthoritativePolicy(policy({ assistPermitted: false }), {
      ...policy({}),
      assistPermitted: undefined as unknown as boolean | null,
    });
    assert.strictEqual(merged.assistPermitted, false, "the deny survives an absent field");
    assert.strictEqual(assistantState(merged).enabled, false, "and it still reaches the gate");
  });

  test("T8: a non-boolean answer is not a permit either", () => {
    // Same rule, other shape: a proxy or a mistyped target answering a string must not read as
    // "permitted". Anything that is not the literal true/false means "not evaluated".
    const merged = mergeAuthoritativePolicy(policy({ assistPermitted: false }), {
      ...policy({}),
      assistPermitted: "yes" as unknown as boolean | null,
    });
    assert.strictEqual(merged.assistPermitted, false);
    assert.strictEqual(assistantState(merged).enabled, false);
  });

  test("T9: a non-evaluable answer is NORMALIZED to null, so the cache stays comparable", () => {
    // With no cache there is no deny to retain — but the value written must still be `null`, not the
    // `undefined` that came in. Storing `undefined` would make every later `cached?.assistPermitted
    // === false` test false, i.e. a single degraded read would disarm the guard for good.
    const merged = mergeAuthoritativePolicy(null, {
      ...policy({}),
      assistPermitted: undefined as unknown as boolean | null,
    });
    assert.strictEqual(merged.assistPermitted, null);
    assert.ok("assistPermitted" in merged, "the key is present, not dropped");
  });
});

// BACKLOG #1154 (ASVS 8.3.2) — the age bound on a cached answer, asserted node-side for the reason
// the header gives. The rule is asymmetric like the merge: a cached ENABLE expires, a cached
// DISABLE never does. Each pole needs its own test, or a rule that expired everything (or nothing)
// would pass.
suite("cachedPolicyOffline (BACKLOG #1154 — a cached permit expires, a cached deny does not)", () => {
  const NOW = 1_800_000_000_000;
  const FRESH = NOW - 60_000; // a minute old
  const STALE = NOW - CACHED_PERMIT_MAX_AGE_MS - 1;

  test("C1: a fresh cached permit still enables assistance offline", () => {
    const p = cachedPolicyOffline({ ...policy({ assistPermitted: true }), cachedAt: FRESH }, NOW);
    assert.strictEqual(p.mode, "byo");
    assert.strictEqual(assistantState(p).enabled, true);
    assert.ok(!("cachedAt" in p), "the stamp does not leak into the returned policy");
  });

  test("C2: a cached permit past the bound fails closed", () => {
    const p = cachedPolicyOffline({ ...policy({ assistPermitted: true }), cachedAt: STALE }, NOW);
    assert.strictEqual(p.mode, "unverified");
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("C3: the bound is inclusive at exactly the limit, and exclusive one millisecond past it", () => {
    const at = { ...policy({ assistPermitted: true }), cachedAt: NOW - CACHED_PERMIT_MAX_AGE_MS };
    assert.strictEqual(assistantState(cachedPolicyOffline(at, NOW)).enabled, true);
    assert.strictEqual(assistantState(cachedPolicyOffline(at, NOW + 1)).enabled, false);
  });

  test("C4: an unknown permit (null) under byo expires like a permit, since it enables", () => {
    const p = cachedPolicyOffline({ ...policy({ assistPermitted: null }), cachedAt: STALE }, NOW);
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("C5: a cache with no stamp (written before the bound) cannot vouch for a permit", () => {
    const p = cachedPolicyOffline(policy({ assistPermitted: true }), NOW);
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("C6: a stamp from the future (a clock stepped back) cannot vouch for a permit", () => {
    const p = cachedPolicyOffline({ ...policy({ assistPermitted: true }), cachedAt: NOW + 1 }, NOW);
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("C7: a cached deny survives any age — the SEC-022 rule is unchanged", () => {
    for (const cachedAt of [FRESH, STALE, undefined]) {
      const deny = cachedPolicyOffline({ ...policy({ assistPermitted: false }), cachedAt }, NOW);
      assert.strictEqual(deny.assistPermitted, false);
      assert.strictEqual(deny.mode, "byo", "the deny itself is returned, with its own message");
      const off = cachedPolicyOffline({ ...policy({ mode: "off" }), cachedAt }, NOW);
      assert.strictEqual(off.mode, "off");
    }
  });
});
