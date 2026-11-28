// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The AI policy cached from one engine never answers for another (BACKLOG #5564, the per-engine cache
// key).
//
// This drives the real `resolveAiPolicy` against a stubbed `vscode`, a fake globalState and a fake
// engine IO. It names only what aiPolicy.ts exported before the per-engine key was added
// (`resolveAiPolicy`, `assistantState`, the `AiPolicyIo` and `AiPolicyWire` types), so it runs
// against that earlier source too, where it fails on the behaviour rather than on a missing symbol.
// The Extension Host twins are T17 and T18 in ai-policy.test.ts, which `test:unit` ignores and which
// cannot compile against that earlier source (it imports `aiPolicyCacheKey`); this file runs
// node-side, on every ide leg, and skips in the Extension Host, which resolves the real `vscode`.
//
// What each test pins on main: all three go red if aiPolicyCacheKey gives every engine one key,
// since the deny carrier names its issuer by that key too. A change that shared only the stored
// cache entry, keeping the carrier's issuer per engine, turns K-A1 red and leaves K-B1 and K-B2
// green, as the carrier still holds B's deny. Against the single unscoped key before both, all three
// fail.
import * as assert from "assert";
import * as path from "node:path";

import type * as vscode from "vscode";

import type { AiPolicyIo, AiPolicyWire } from "../../aiPolicy";

/** Two engines, told apart only by port. */
const ENGINE_A = "http://127.0.0.1:8765";
const ENGINE_B = "http://127.0.0.1:9876";
/** A fixed clock, so a cached permit is never too old to stand and the age bound decides nothing. */
const NOW = 1_800_000_000_000;

// Empty on purpose: loading the modules touches no vscode member, and the injected IO means the
// resolve does not either. A later change that reads vscode on this path then throws here, rather
// than reading a stubbed fallback.
const vscodeStub = {};

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

function insideExtensionHost(): boolean {
  try {
    // Both fields, as the sibling suites check: a stray package exporting only `version` must not
    // turn this suite into a silent skip.
    const api = realLoad.call(loader, "vscode", module, false) as {
      version?: unknown;
      env?: { appName?: unknown };
    };
    return typeof api?.version === "string" && typeof api?.env?.appName === "string";
  } catch {
    return false;
  }
}

const NODE_SIDE = !insideExtensionHost();

type AiPolicyModule = typeof import("../../aiPolicy");
let aiPolicy!: AiPolicyModule;

if (NODE_SIDE) {
  // Every extension module is loaded fresh against this stub, and the cache is put back afterwards,
  // so a sibling suite holding its own stubbed copies is unaffected.
  const outDir = path.resolve(__dirname, "..", "..");
  const testDir = path.join(outDir, "test") + path.sep;
  const isExtensionModule = (f: string): boolean => f.startsWith(outDir + path.sep) && !f.startsWith(testDir);
  const saved = new Map(
    Object.keys(require.cache)
      .filter(isExtensionModule)
      .map((f) => [f, require.cache[f]]),
  );
  for (const f of saved.keys()) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    aiPolicy = require("../../aiPolicy") as AiPolicyModule;
  } finally {
    loader._load = realLoad;
    for (const f of Object.keys(require.cache).filter(isExtensionModule)) {
      delete require.cache[f];
    }
    for (const [f, entry] of saved) {
      require.cache[f] = entry;
    }
  }
}

/** A globalState with VS Code's Memento semantics: an undefined value deletes the key. */
function freshCtx(): vscode.ExtensionContext {
  const store = new Map<string, unknown>();
  return {
    globalState: {
      get: (key: string): unknown => store.get(key),
      keys: (): readonly string[] => [...store.keys()],
      update: async (key: string, v: unknown): Promise<void> => {
        if (v === undefined) {
          store.delete(key);
        } else {
          store.set(key, v);
        }
      },
    },
  } as unknown as vscode.ExtensionContext;
}

function wire(w: Partial<AiPolicyWire>): AiPolicyWire {
  return { mode: "byo", data_scope: "code_only", environment: null, assist_permitted: null, reason: null, ...w };
}

/**
 * The engine at `url` answers `answer`, or is unreachable when `answer` is undefined. The local CLI
 * has no answer, so an offline result is never the CLI's: it is the cache's, a deny the carrier holds
 * (on main), or the fail-closed policy.
 */
function engine(url: string, answer: AiPolicyWire | undefined): AiPolicyIo {
  return {
    url: () => url,
    readToken: async () => "tok-synthetic",
    getPolicy: async () => {
      if (answer === undefined) {
        throw new Error("engine unreachable");
      }
      return answer;
    },
    getCliPolicy: async () => {
      throw new Error("no CLI here");
    },
    now: () => NOW,
  };
}

const keySuite = NODE_SIDE ? suite : suite.skip;

keySuite("resolveAiPolicy keys its cache by engine (BACKLOG #5564)", () => {
  test("K-A1: a permit engine A answered does not enable assistance while engine B is unreachable", async () => {
    const ctx = freshCtx();
    const onA = await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_A, wire({ assist_permitted: true })));
    // Control: A's own answer enables, so the red below is about B, not a stub that never enables.
    assert.strictEqual(aiPolicy.assistantState(onA).enabled, true, "engine A's own permit must enable");
    const offB = await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_B, undefined));
    assert.strictEqual(
      aiPolicy.assistantState(offB).enabled,
      false,
      `engine A's permit was carried to engine B: B resolved to ${JSON.stringify(offB)}`,
    );
    assert.strictEqual(offB.mode, "unverified", "B has no answer of its own, so it fails closed");
  });

  test("K-B1: engine B's central off is not missed after engine A answers a permit", async () => {
    const ctx = freshCtx();
    await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_B, wire({ mode: "off" })));
    await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_A, wire({ assist_permitted: true })));
    const offB = await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_B, undefined));
    assert.strictEqual(offB.mode, "off", `engine B's central off was missed: B resolved to ${JSON.stringify(offB)}`);
    assert.strictEqual(aiPolicy.assistantState(offB).enabled, false);
  });

  test("K-B2: engine B's ai:assist deny is not missed after engine A answers a permit", async () => {
    const ctx = freshCtx();
    await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_B, wire({ assist_permitted: false })));
    await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_A, wire({ assist_permitted: true })));
    const offB = await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_B, undefined));
    assert.strictEqual(
      offB.assistPermitted,
      false,
      `engine B's ai:assist deny was missed: B resolved to ${JSON.stringify(offB)}`,
    );
    assert.strictEqual(aiPolicy.assistantState(offB).enabled, false);
  });

  test("K-C1: control: one engine's own cached permit still answers for it offline", async () => {
    // Without this, a resolve that failed closed on every offline read would pass the three above.
    const ctx = freshCtx();
    await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_A, wire({ assist_permitted: true })));
    const offA = await aiPolicy.resolveAiPolicy(ctx, engine(ENGINE_A, undefined));
    assert.strictEqual(aiPolicy.assistantState(offA).enabled, true, "engine A's own fresh permit must still stand");
  });
});
