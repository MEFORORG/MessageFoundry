// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  AI_POLICY_CACHE_PREFIX,
  CACHED_PERMIT_MAX_AGE_MS,
  CARRIED_DENY,
  aiPolicyCacheKey,
  assistantState,
  cachedPolicyOffline,
  mergeAuthoritativePolicy,
  pickOfflinePolicy,
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

// BACKLOG #5564: the cached policy is keyed by the engine that answered, so one engine's permit
// never enables assistance against another, and one engine's deny is never replaced by another's.
suite("aiPolicyCacheKey (BACKLOG #5564)", () => {
  test("K1: two engines get two keys, so neither answers for the other offline", () => {
    const a = aiPolicyCacheKey("https://127.0.0.1:8765");
    const b = aiPolicyCacheKey("https://engine-b.example.test:8765");
    assert.notStrictEqual(a, b);
    assert.ok(a.startsWith(AI_POLICY_CACHE_PREFIX) && b.startsWith(AI_POLICY_CACHE_PREFIX));
  });

  test("K2: one engine spelled two ways shares one key (case, default port, trailing slash)", () => {
    const key = aiPolicyCacheKey("https://engine.example.test");
    for (const spelling of [
      "HTTPS://Engine.Example.Test/",
      "https://engine.example.test:443",
      "  https://engine.example.test//  ",
    ]) {
      assert.strictEqual(aiPolicyCacheKey(spelling), key, spelling);
    }
  });

  test("K3: the scheme, the port and the path each name a different engine", () => {
    const base = aiPolicyCacheKey("https://engine.example.test:8765");
    assert.notStrictEqual(aiPolicyCacheKey("http://engine.example.test:8765"), base);
    assert.notStrictEqual(aiPolicyCacheKey("https://engine.example.test:8766"), base);
    // The engine client appends each route to the URL's path, so a path prefix is part of the target.
    assert.notStrictEqual(
      aiPolicyCacheKey("https://proxy.example.test/engine-a"),
      aiPolicyCacheKey("https://proxy.example.test/engine-b"),
    );
  });

  test("K4: text that is not a URL is still keyed, by its own text", () => {
    assert.strictEqual(aiPolicyCacheKey("not a url/"), AI_POLICY_CACHE_PREFIX + "not a url");
    assert.notStrictEqual(aiPolicyCacheKey("not a url"), aiPolicyCacheKey("also not a url"));
  });

  test("K5: a carried deny is a deny to the merge, and nothing else", () => {
    const merged = mergeAuthoritativePolicy(CARRIED_DENY, policy({ mode: "byo", assistPermitted: null }));
    assert.strictEqual(merged.assistPermitted, false);
    assert.strictEqual(merged.mode, "byo", "the fresh mode still comes through");
    assert.strictEqual(mergeAuthoritativePolicy(CARRIED_DENY, policy({ assistPermitted: true })).assistPermitted, true);
  });
});

// BACKLOG #5564: per-engine keys mean a retarget finds no cache. Once any engine has answered, that
// must fail closed, not fall to the local CLI, or changing the setting bypasses a cached deny.
suite("pickOfflinePolicy — a retarget does not bypass a cached deny (BACKLOG #5564)", () => {
  const byo = policy({ mode: "byo", assistPermitted: null });

  test("P1: no cache, no engine ever answered: the CLI's policy is used", () => {
    assert.strictEqual(pickOfflinePolicy(null, byo, 0, false), byo);
  });

  test("P2: no cache for this engine, but an engine has answered: fail closed, not the CLI", () => {
    const p = pickOfflinePolicy(null, byo, 0, true);
    assert.strictEqual(p.mode, "unverified");
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("P3: this engine's own cache still answers whatever the flag says", () => {
    const deny = { ...policy({ mode: "off" }), cachedAt: 0 };
    assert.strictEqual(pickOfflinePolicy(deny, byo, 0, true).mode, "off");
    assert.strictEqual(pickOfflinePolicy(deny, byo, 0, false).mode, "off");
  });
});

// aiPolicy.ts imports vscode, so its behavioural tests run only in the Extension Host leg
// (ai-policy.test.ts). These read its source so the two halves of BACKLOG #5564 are pinned on every
// leg: the policy is read from the status bar's target, and every cache read and write is keyed.
suite("aiPolicy.ts reads the target engine's policy, and keys its cache (BACKLOG #5564)", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "aiPolicy.ts"), "utf8");
  const code = src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");

  const urlResolvesTarget = (line: string): boolean => /^\s*url:\s*aiPolicyEngineUrl,?\s*$/.test(line);
  const keyedAccess = (call: string): boolean => /^globalState\.(get<\w+>|update)\(cacheKey[,)]/.test(call);

  test("T1: DEFAULT_AI_POLICY_IO.url resolves through resolveEngineStatusTarget, not engineUrl alone", () => {
    const block = /DEFAULT_AI_POLICY_IO: AiPolicyIo = \{([\s\S]*?)\n\};/.exec(code);
    assert.ok(block, "DEFAULT_AI_POLICY_IO moved — re-point this scan before trusting it");
    const urlLines = block[1].split(/\r?\n/).filter((l) => /^\s*url:/.test(l));
    assert.strictEqual(urlLines.length, 1, "expected one url entry in DEFAULT_AI_POLICY_IO");
    assert.ok(urlResolvesTarget(urlLines[0]), `the policy is read from the wrong engine: ${urlLines[0].trim()}`);
    // The control: the line the file carried before the fix must fail the predicate.
    assert.ok(!urlResolvesTarget("  url: engineUrl,"), "the predicate accepts the defect line");
    assert.ok(
      /function aiPolicyEngineUrl\(\): string \{\s*return resolveEngineStatusTarget\(engineUrl\(\),\s*environments\(\)\)\.url;/.test(
        code,
      ),
      "aiPolicyEngineUrl must resolve the status bar's target",
    );
  });

  test("T3: an engine-brokered chat request goes to the engine the policy was read from", () => {
    const chat = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "chat.ts"), "utf8");
    // One read of the target feeds both the policy read and the broker.
    assert.strictEqual((chat.match(/aiPolicyEngineUrl\(\)/g) ?? []).length, 1, "read the target once");
    assert.ok(/const engine = aiPolicyEngineUrl\(\);/.test(chat));
    assert.ok(/resolveAiPolicy\(context, \{ \.\.\.DEFAULT_AI_POLICY_IO, url: \(\) => engine \}\)/.test(chat));
    assert.ok(/const url = engine;/.test(chat), "chat.ts brokers to a different engine");
    assert.ok(!/\bengineUrl\(\)/.test(chat), "chat.ts reads engineUrl directly");
  });

  test("T2: every globalState read and write of the policy goes through the per-engine key", () => {
    // The policy reads are the CachedAiPolicy gets; the policy write is the one that stores `stamped`.
    const reads = code.match(/globalState\.get<CachedAiPolicy>\([^)]*\)/g) ?? [];
    const writes = code.match(/globalState\.update\([^,]*,\s*stamped\)/g) ?? [];
    assert.strictEqual(reads.length, 2, `expected the merge read and the offline read: ${reads.join(" | ")}`);
    assert.strictEqual(writes.length, 1, `expected one policy write: ${writes.join(" | ")}`);
    for (const call of [...reads, ...writes]) {
      assert.ok(keyedAccess(call), `an unkeyed policy cache access: ${call}`);
    }
    assert.ok(!keyedAccess("globalState.get<CachedAiPolicy>(LAST_POLICY_KEY)"), "the predicate accepts the defect");
    assert.ok(/cacheKey = aiPolicyCacheKey\(url\);/.test(code), "the key must be derived from the url asked");
  });

  test("T5: with no cache for this engine, a deny seen from any engine stands in for the merge", () => {
    assert.ok(
      /get<CachedAiPolicy>\(cacheKey\) \?\? \(denySeen \? CARRIED_DENY : null\)/.test(code),
      "a deny must carry to an engine with no cache of its own",
    );
    assert.ok(/update\(AI_POLICY_DENY_KEY, true\)/.test(code), "a deny must be recorded");
    assert.ok(/update\(AI_POLICY_DENY_KEY, undefined\)/.test(code), "a permit must clear it");
  });

  test("T4: the offline path passes whether any engine has answered", () => {
    assert.ok(
      /pickOfflinePolicy\(cached, cli, now\(\), heard\)/.test(code),
      "resolveAiPolicy must tell pickOfflinePolicy whether an engine has answered",
    );
    assert.ok(/globalState\.update\(AI_POLICY_HEARD_KEY, true\)/.test(code), "a successful read must set the flag");
  });
});
