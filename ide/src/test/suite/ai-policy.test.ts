import * as assert from "assert";

import type * as vscode from "vscode";

import {
  DEFAULT_AI_POLICY_IO,
  assistantState,
  pickOfflinePolicy,
  resolveAiPolicy,
  type AiPolicy,
  type AiPolicyIo,
  type AiPolicyWire,
} from "../../aiPolicy";
import { peekToken } from "../../auth";

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

// BACKLOG #330 — resolveAiPolicy's fetch-and-cache path, where BOTH defects lived and which had no
// test at all. It needs the vscode-importing module, so these run only under `npm test` (the
// Extension-Host leg); the pure merge rule they depend on is asserted node-side on every leg in
// ai-policy-model.test.ts. That split is deliberate — see R4 in the plan.

/** A fake globalState that records what was written, so a guard cannot pass by not writing. */
function fakeCtx(seed?: AiPolicy): {
  ctx: vscode.ExtensionContext;
  stored: () => AiPolicy | undefined;
  updates: () => number;
} {
  let value = seed;
  let updates = 0;
  const ctx = {
    globalState: {
      get: (_key: string): AiPolicy | undefined => value,
      update: async (_key: string, v: AiPolicy): Promise<void> => {
        value = v;
        updates++;
      },
    },
  } as unknown as vscode.ExtensionContext;
  return { ctx, stored: () => value, updates: () => updates };
}

function wire(w: Partial<AiPolicyWire>): AiPolicyWire {
  return {
    mode: "byo",
    data_scope: "code_only",
    environment: null,
    assist_permitted: null,
    reason: null,
    ...w,
  };
}

/** An io whose calls are recorded. `url` defaults to loopback, which SEC-005 permits over http. */
function fakeIo(opts: {
  url?: string;
  token?: string;
  answer: AiPolicyWire;
}): AiPolicyIo & { calls: { url: string; route: string; token: string | undefined }[] } {
  const calls: { url: string; route: string; token: string | undefined }[] = [];
  return {
    calls,
    url: () => opts.url ?? "http://127.0.0.1:8765",
    readToken: async () => opts.token,
    getPolicy: async (url, route, token) => {
      calls.push({ url, route, token });
      return opts.answer;
    },
    getCliPolicy: async () => {
      throw new Error("the CLI must not be consulted when the engine answered");
    },
  };
}

suite("resolveAiPolicy — the bearer (BACKLOG #330, defect 2)", () => {
  test("T10: the cached bearer is attached to the /ai/policy read", async () => {
    const { ctx } = fakeCtx();
    const io = fakeIo({ token: "tok-abc", answer: wire({ assist_permitted: false }) });
    const p = await resolveAiPolicy(ctx, io);
    assert.strictEqual(io.calls.length, 1);
    assert.strictEqual(io.calls[0].token, "tok-abc", "the bearer must reach the request");
    assert.strictEqual(io.calls[0].route, "/ai/policy");
    // And the whole point: with an identity attached, the engine's `false` now arrives and gates.
    assert.strictEqual(p.assistPermitted, false);
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("T11: the production io reads the token PASSIVELY — peekToken, never ensureToken", async () => {
    // `ensureToken` has an identical signature, so the type system cannot rule it out; this identity
    // check is the actual control. A chat turn resolves the policy before every request — an
    // ensureToken here would pop a sign-in modal out of typing a question.
    assert.strictEqual(DEFAULT_AI_POLICY_IO.readToken, peekToken);
  });

  test("T12: SEC-005 — no bearer to a non-loopback plain-http target, but yes to loopback", async () => {
    const offBox = fakeIo({
      url: "http://engine.example.test:8765",
      token: "tok-abc",
      answer: wire({}),
    });
    await resolveAiPolicy(fakeCtx().ctx, offBox);
    assert.strictEqual(
      offBox.calls[0].token,
      undefined,
      "a bearer must never go in clear to a non-loopback http:// host",
    );

    // The other polarity, so the guard cannot pass by refusing everything.
    const loopback = fakeIo({ url: "http://127.0.0.1:8765", token: "tok-abc", answer: wire({}) });
    await resolveAiPolicy(fakeCtx().ctx, loopback);
    assert.strictEqual(loopback.calls[0].token, "tok-abc", "loopback over http is the dev default");
  });
});

suite("resolveAiPolicy — the guarded cache write (BACKLOG #330, defect 1)", () => {
  test("T13: a null answer does not overwrite a cached deny, in the RETURN or the STORE", async () => {
    const seeded = {
      mode: "byo",
      dataScope: "code_only",
      environment: null,
      assistPermitted: false,
      reason: null,
    } satisfies AiPolicy;
    const f = fakeCtx(seeded);
    const io = fakeIo({ token: "tok-abc", answer: wire({ assist_permitted: null }) });
    const p = await resolveAiPolicy(f.ctx, io);
    // Assert BOTH: a half-fix that returns the merged policy while storing the raw one would leave the
    // deny to be lost on the next read.
    assert.strictEqual(p.assistPermitted, false, "the returned policy keeps the deny");
    assert.strictEqual(f.stored()?.assistPermitted, false, "the STORED policy keeps the deny");
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("T13b: a 200 that OMITS assist_permitted cannot launder the deny either", async () => {
    // The COMPOSED behaviour, end to end: `AiPolicyWire` is a compile-time claim that JSON.parse does
    // not enforce, so a body with no `assist_permitted` key arrives as `undefined` — which is NOT
    // `null`. Two independent lines stop it (the `fromWire` narrowing and the merge's), so this test
    // stays green if either survives; T7 in ai-policy-model.test.ts is what pins the merge's line
    // specifically, and T13c below pins `fromWire`'s. Kept because it is the only assertion that the
    // whole path — wire → narrow → merge → store → gate — holds together.
    const seeded = {
      mode: "byo",
      dataScope: "code_only",
      environment: null,
      assistPermitted: false,
      reason: null,
    } satisfies AiPolicy;
    const f = fakeCtx(seeded);
    const degraded = {
      mode: "byo",
      data_scope: "code_only",
      environment: null,
      reason: null,
    } as unknown as AiPolicyWire; // a proxy, or an engine build predating the field
    const p = await resolveAiPolicy(f.ctx, fakeIo({ token: "tok-abc", answer: degraded }));
    assert.strictEqual(p.assistPermitted, false, "the returned policy keeps the deny");
    assert.strictEqual(f.stored()?.assistPermitted, false, "the STORED policy keeps the deny");
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("T13c: the CLI fallback narrows too — it never reaches the merge, so fromWire must", async () => {
    // The path that proves `fromWire`'s narrowing is not redundant with the merge's: when the engine
    // is unreachable, `resolveAiPolicy` runs `fromWire(await io.getCliPolicy())` and hands the result
    // to `pickOfflinePolicy` WITHOUT ever calling mergeAuthoritativePolicy (aiPolicy.ts). So an
    // unnarrowed copy survives to the caller as `undefined`, and `showAiPolicy` renders that with
    // `assistPermitted === null ? "unknown" : p.assistPermitted ? "yes" : "no"` — i.e. it would tell a
    // user "assist_permitted=no", asserting a deny the engine never issued.
    const io: AiPolicyIo = {
      url: () => "http://127.0.0.1:8765",
      readToken: async () => "tok-abc",
      getPolicy: async () => {
        throw new Error("engine unreachable");
      },
      getCliPolicy: async () =>
        ({ mode: "byo", data_scope: "code_only", environment: "dev", reason: null }) as unknown as AiPolicyWire,
    };
    const p = await resolveAiPolicy(fakeCtx().ctx, io);
    assert.strictEqual(p.assistPermitted, null, "an absent CLI field is 'unknown', never a deny");
    assert.notStrictEqual(p.assistPermitted, undefined, "and never the raw undefined");
  });

  test("T14: AC-6 still holds — a successful read is still CACHED (the guard is not a skip)", async () => {
    // The obvious wrong turn is to "fix" an unguarded write by removing it. That would break ADR 0035
    // AC-6: the cache is what makes a central "off" survive the engine going offline.
    const f = fakeCtx();
    const io = fakeIo({ token: "tok-abc", answer: wire({ mode: "off" }) });
    await resolveAiPolicy(f.ctx, io);
    assert.strictEqual(f.updates(), 1, "the authoritative answer must be written exactly once");
    assert.strictEqual(f.stored()?.mode, "off");
  });
});
