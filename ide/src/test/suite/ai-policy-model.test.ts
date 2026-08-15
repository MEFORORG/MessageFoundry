// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import { assistantState, mergeAuthoritativePolicy, type AiPolicy } from "../../aiPolicyModel";

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
