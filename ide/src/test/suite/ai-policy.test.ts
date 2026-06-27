import * as assert from "assert";

import { assistantState, pickOfflinePolicy, type AiPolicy } from "../../aiPolicy";

// SEC-022 regression. The offline AI-policy resolution must FAIL CLOSED: when the engine is
// unreachable and nothing can positively confirm a policy, assistance is disabled (an org-set central
// "off" must not be bypassable by going offline). These cover the two pure pieces — assistantState's
// gating of the "unverified" sentinel, and pickOfflinePolicy's cached→cli→fail-closed order.
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

suite("assistantState (SEC-022)", () => {
  test("the 'unverified' fallback is DISABLED with a 'could not be verified' message", () => {
    const s = assistantState(policy({ mode: "unverified" }));
    assert.strictEqual(s.enabled, false);
    assert.ok(/could not be verified/i.test(s.message ?? ""), "message explains why it is off");
  });

  test("mode 'off' stays disabled (unchanged)", () => {
    assert.strictEqual(assistantState(policy({ mode: "off" })).enabled, false);
  });

  test("byo + assistPermitted:false stays disabled (unchanged)", () => {
    assert.strictEqual(assistantState(policy({ mode: "byo", assistPermitted: false })).enabled, false);
  });

  test("byo + assistPermitted:true stays enabled (online-permitted unchanged)", () => {
    assert.strictEqual(assistantState(policy({ mode: "byo", assistPermitted: true })).enabled, true);
  });

  test("byo + assistPermitted:null (online, RBAC-unevaluable) stays enabled", () => {
    assert.strictEqual(assistantState(policy({ mode: "byo", assistPermitted: null })).enabled, true);
  });

  test("managed_claude stays disabled (unchanged)", () => {
    assert.strictEqual(assistantState(policy({ mode: "managed_claude" })).enabled, false);
  });
});

suite("pickOfflinePolicy (SEC-022)", () => {
  test("a cached authoritative 'off' wins over the CLI when offline", () => {
    const cached = policy({ mode: "off" });
    const cli = policy({ mode: "byo", assistPermitted: true });
    assert.strictEqual(pickOfflinePolicy(cached, cli).mode, "off");
  });

  test("with no cache, a positively-returned CLI policy is used", () => {
    const cli = policy({ mode: "off" });
    assert.strictEqual(pickOfflinePolicy(null, cli).mode, "off");
  });

  test("no cache AND no CLI policy → fail-closed 'unverified' (NOT silently-enabled byo)", () => {
    const fallback = pickOfflinePolicy(null, null);
    assert.strictEqual(fallback.mode, "unverified");
    assert.strictEqual(assistantState(fallback).enabled, false);
  });
});
