// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  AI_POLICY_CACHE_PREFIX,
  AI_POLICY_DENY_KEY,
  CACHED_PERMIT_MAX_AGE_MS,
  LEGACY_AI_POLICY_KEY,
  aiPolicyCacheKey,
  assistantState,
  cachedPolicyOffline,
  carryDeniesOffline,
  carryDeniesOnline,
  mergeAuthoritativePolicy,
  pickOfflinePolicy,
  type AiPolicy,
  type PolicyStore,
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

});

// BACKLOG #5564: per-engine keys mean a retarget finds no cache. For an operator-configured target
// that must fail closed, not fall to the local CLI, or changing the setting bypasses a cached deny.
suite("pickOfflinePolicy — a retarget does not bypass a cached deny (BACKLOG #5564)", () => {
  const byo = policy({ mode: "byo", assistPermitted: null });

  test("P1: no cache, default target: the CLI's policy is used, as before", () => {
    assert.strictEqual(pickOfflinePolicy(null, byo, 0, false), byo);
  });

  test("P2: no cache for a configured target: fail closed, not the CLI", () => {
    const p = pickOfflinePolicy(null, byo, 0, true);
    assert.strictEqual(p.mode, "unverified");
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("P3: this engine's own cache still answers either way", () => {
    const deny = { ...policy({ mode: "off" }), cachedAt: 0 };
    assert.strictEqual(pickOfflinePolicy(deny, byo, 0, true).mode, "off");
    assert.strictEqual(pickOfflinePolicy(deny, byo, 0, false).mode, "off");
  });
});

/** A globalState stand-in whose writes yield first, so two overlapping resolves really interleave. */
function memStore(seed: Record<string, unknown> = {}): PolicyStore & { map: Map<string, unknown> } {
  const map = new Map<string, unknown>(Object.entries(seed));
  return {
    map,
    get: <T>(key: string): T | undefined => map.get(key) as T | undefined,
    update: async (key: string, value: unknown): Promise<void> => {
      await new Promise((resolve) => setTimeout(resolve, 1));
      if (value === undefined) {
        map.delete(key);
      } else {
        map.set(key, value);
      }
    },
  };
}

// The same steps resolveAiPolicy takes (the source scan below pins that it takes them): an answer is
// merged over the engine's own cache, cached, then passed through the carrier; offline, the own
// cache or the CLI is picked, then passed through the carrier.
async function answered(store: PolicyStore, url: string, fresh: AiPolicy): Promise<AiPolicy> {
  const key = aiPolicyCacheKey(url);
  const merged = mergeAuthoritativePolicy(store.get<AiPolicy>(key) ?? null, fresh);
  await store.update(key, { ...merged, cachedAt: 0 });
  return carryDeniesOnline(store, key, fresh, merged);
}

async function unreachable(store: PolicyStore, url: string, cli: AiPolicy | null, configured: boolean): Promise<AiPolicy> {
  const cached = store.get<AiPolicy & { cachedAt?: number }>(aiPolicyCacheKey(url)) ?? null;
  return carryDeniesOffline(store, pickOfflinePolicy(cached, cli, 0, configured));
}

suite("the deny carrier — a deny survives a retarget (BACKLOG #5564)", () => {
  const CENTRAL = "https://central.example.test:8765";
  const LOCAL = "https://127.0.0.1:8765";
  const ALIAS = "https://localhost:8765";
  const OTHER = "https://other.example.test:8765";
  const cliByo = policy({ mode: "byo" });

  test("D1: a cached central off survives clearing engineUrl back to the default target", async () => {
    const store = memStore();
    await answered(store, CENTRAL, policy({ mode: "off" }));
    const p = await unreachable(store, LOCAL, cliByo, false);
    assert.strictEqual(p.mode, "off", "the local CLI's byo must not outrank the central off");
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("D1b: the default target's own cached permit does not outrank it either", async () => {
    const store = memStore();
    await answered(store, LOCAL, policy({ assistPermitted: true }));
    await answered(store, CENTRAL, policy({ mode: "off" }));
    const p = await unreachable(store, LOCAL, cliByo, false);
    assert.strictEqual(assistantState(p).enabled, false);
  });

  test("D2: an alias URL of the same engine inherits its ai:assist deny, reachable or not", async () => {
    const store = memStore();
    await answered(store, LOCAL, policy({ assistPermitted: false }));
    // The alias has no bearer cached, so the engine cannot evaluate the permission.
    const online = await answered(store, ALIAS, policy({ assistPermitted: null }));
    assert.strictEqual(online.assistPermitted, false, "a tokenless read at the alias kept the deny");
    assert.strictEqual(assistantState(online).enabled, false);
    const offline = await unreachable(store, ALIAS, cliByo, true);
    assert.strictEqual(assistantState(offline).enabled, false);
  });

  test("D3: only the issuing engine's permit clears its deny", async () => {
    const store = memStore();
    await answered(store, CENTRAL, policy({ assistPermitted: false }));
    // Another engine's evaluated grant is its own answer, so it enables there...
    const other = await answered(store, OTHER, policy({ assistPermitted: true }));
    assert.strictEqual(assistantState(other).enabled, true, "an evaluated grant is that engine's own answer");
    // ...but it does not clear the central deny for a target with no answer of its own.
    assert.strictEqual(assistantState(await unreachable(store, LOCAL, cliByo, false)).enabled, false);
    // A tokenless read from the issuer does not clear it either.
    await answered(store, CENTRAL, policy({ assistPermitted: null }));
    assert.strictEqual(assistantState(await unreachable(store, LOCAL, cliByo, false)).enabled, false);
    // The issuer's evaluated grant does.
    await answered(store, CENTRAL, policy({ assistPermitted: true }));
    assert.strictEqual(assistantState(await unreachable(store, LOCAL, cliByo, false)).enabled, true);
  });

  test("D3b: a central off is cleared only when that engine stops answering off", async () => {
    const store = memStore();
    await answered(store, CENTRAL, policy({ mode: "off" }));
    await answered(store, OTHER, policy({ mode: "byo" }));
    assert.strictEqual((await unreachable(store, LOCAL, cliByo, false)).mode, "off");
    await answered(store, CENTRAL, policy({ mode: "byo" }));
    assert.strictEqual((await unreachable(store, LOCAL, cliByo, false)).mode, "byo");
  });

  test("D4: the old unscoped key's deny is migrated once, with an unknown issuer, then deleted", async () => {
    const store = memStore({ [LEGACY_AI_POLICY_KEY]: { ...policy({ mode: "off" }), cachedAt: 0 } });
    const p = await unreachable(store, LOCAL, cliByo, false);
    assert.strictEqual(p.mode, "off", "the pre-upgrade central off must not be dropped");
    assert.strictEqual(store.map.has(LEGACY_AI_POLICY_KEY), false, "the old key is deleted");
    assert.ok(store.map.has(AI_POLICY_DENY_KEY), "the deny is carried");
    // Any engine's authoritative permit clears an unknown issuer's deny, as origin/main's key did.
    await answered(store, OTHER, policy({ mode: "byo" }));
    assert.strictEqual((await unreachable(store, LOCAL, cliByo, false)).mode, "byo");
  });

  test("D4b: an old ai:assist deny is migrated too, and an old permit is deleted without carrying", async () => {
    const deny = memStore({ [LEGACY_AI_POLICY_KEY]: policy({ assistPermitted: false }) });
    assert.strictEqual(assistantState(await unreachable(deny, LOCAL, cliByo, false)).enabled, false);
    const permit = memStore({ [LEGACY_AI_POLICY_KEY]: policy({ assistPermitted: true }) });
    assert.strictEqual(assistantState(await unreachable(permit, LOCAL, cliByo, false)).enabled, true);
    assert.strictEqual(permit.map.has(LEGACY_AI_POLICY_KEY), false);
    assert.strictEqual(permit.map.has(AI_POLICY_DENY_KEY), false, "a permit is not a deny to carry");
  });

  test("D4c: a failed carrier write keeps the old key, and its deny stays in effect", async () => {
    const store = memStore({ [LEGACY_AI_POLICY_KEY]: { ...policy({ mode: "off" }), cachedAt: 0 } });
    const write = store.update;
    let failing = true;
    store.update = async (key: string, value: unknown): Promise<void> => {
      if (failing && key === AI_POLICY_DENY_KEY) {
        throw new Error("synthetic storage failure");
      }
      return write(key, value);
    };
    for (let i = 0; i < 2; i++) {
      const p = await unreachable(store, LOCAL, cliByo, false);
      assert.strictEqual(p.mode, "off", "the old key's deny must apply while the carrier cannot be written");
      assert.ok(store.map.has(LEGACY_AI_POLICY_KEY), "the old key was deleted before its deny was carried");
    }
    failing = false;
    assert.strictEqual((await unreachable(store, LOCAL, cliByo, false)).mode, "off");
    assert.strictEqual(store.map.has(LEGACY_AI_POLICY_KEY), false, "once carried, the old key is deleted");
    assert.ok(store.map.has(AI_POLICY_DENY_KEY));
  });

  test("D5: two overlapping resolves cannot drop each other's deny", async () => {
    const store = memStore();
    await Promise.all([
      answered(store, CENTRAL, policy({ mode: "off" })),
      answered(store, OTHER, policy({ assistPermitted: false })),
    ]);
    const carried = store.map.get(AI_POLICY_DENY_KEY) as Record<string, AiPolicy>;
    assert.deepStrictEqual(
      Object.keys(carried).sort(),
      [aiPolicyCacheKey(CENTRAL), aiPolicyCacheKey(OTHER)].sort(),
      "the read-modify-write of the carrier interleaved",
    );
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

  test("T5: the cache is read and written only by this engine's key; the carrier only through the model", () => {
    // A direct globalState access must be the per-engine key. The one state that crosses engines is
    // the deny carrier, and aiPolicy.ts reaches it only through carryDeniesOnline / carryDeniesOffline.
    const all = code.match(/globalState\.(?:get<[^>]+>|get|update)\([^,)]*/g) ?? [];
    assert.strictEqual(all.length, 3, `expected only the merge read, the write and the offline read: ${all.join(" | ")}`);
    for (const call of all) {
      assert.ok(/\(cacheKey$/.test(call), `a globalState access not keyed by engine: ${call}`);
    }
  });

  test("T6: every answer and every offline choice passes through the deny carrier", () => {
    assert.ok(
      /return await carryDeniesOnline\(ctx\.globalState, cacheKey, fresh, merged\);/.test(code),
      "an engine's answer must pass through the carrier before it gates assistance",
    );
    assert.ok(
      /return carryDeniesOffline\(\s*ctx\.globalState,\s*pickOfflinePolicy\(cached, cli, now\(\), targetConfigured\),?\s*\);/.test(
        code,
      ),
      "the offline choice must pass through the carrier",
    );
    // The only return statements in resolveAiPolicy are those two, so no path skips the carrier.
    const body = /export async function resolveAiPolicy\([\s\S]*?\n\}/.exec(code);
    assert.ok(body, "resolveAiPolicy moved — re-point this scan");
    assert.strictEqual((body[0].match(/\breturn\b/g) ?? []).length, 2, "a return that skips the carrier");
  });

  test("T4: the offline path falls to the CLI only for an unconfigured target", () => {
    assert.ok(
      /pickOfflinePolicy\(cached, cli, now\(\), targetConfigured\)/.test(code),
      "resolveAiPolicy must tell pickOfflinePolicy whether the target is configured",
    );
    assert.ok(/targetConfigured: engineTargetIsSet,/.test(code), "the production io must read the settings");
  });
});

suite("cli.ts engineTargetIsSet (BACKLOG #5564)", () => {
  test("a set engineUrl or any environment is a configured target", () => {
    const cli = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "cli.ts"), "utf8");
    assert.ok(
      /function engineTargetIsSet\(\): boolean \{\s*return settingIsSet\(config\(\)\.inspect\("engineUrl"\)\) \|\| environments\(\)\.length > 0;/.test(
        cli,
      ),
    );
  });
});
