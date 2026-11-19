// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5960: withStepUpAuth as shipped, composed with withAuth, end to end. step-up.test.ts drives
// withStepUp alone against a fake host, so it cannot see what withAuth does with the token the
// re-proof rotated. A 401 on that rotated token used to read as a sign-in elsewhere, because the
// cache held a token newer than the one withAuth handed in, and the retry spent a call on the token
// the engine had just refused.
//
// This drives the real auth.ts against a stubbed `vscode`, as auth-target-gate.test.ts does, with
// engineClient's postJson and getJson replaced by scripted spies. Node-side only: the Extension Host
// resolves the real `vscode`.
import * as assert from "assert";
import * as path from "node:path";

const ENGINE_URL = "http://127.0.0.1:8765";
const KEY = "messagefoundry.token:" + ENGINE_URL;
/** Synthetic test values only. */
const REPROOF_PASSWORD = "a-typed-password-never-echoed";
const SIGN_IN_PASSWORD = "a-sign-in-password-never-echoed";

let secrets: Map<string, string>;
let posts: { route: string; token: string | undefined }[];
let prompts: string[];

const vscodeStub = {
  window: {
    showErrorMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showWarningMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showInformationMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showQuickPick: (): Promise<undefined> => Promise.resolve(undefined),
    // Each prompt is answered by what it asks for, so a test can tell a step-up re-proof from a
    // fresh sign-in by the prompts it saw.
    showInputBox: (opts: { prompt?: string }): Promise<string | undefined> => {
      const prompt = opts.prompt ?? "";
      prompts.push(prompt);
      if (prompt.startsWith("Re-enter")) {
        return Promise.resolve(REPROOF_PASSWORD);
      }
      if (prompt.startsWith("MessageFoundry username")) {
        return Promise.resolve("alice");
      }
      if (prompt === "Password") {
        return Promise.resolve(SIGN_IN_PASSWORD);
      }
      if (prompt.startsWith("Authenticator code")) {
        return Promise.resolve(""); // the optional authenticator code
      }
      // A prompt this stub does not know fails the test rather than being answered with a blank.
      return Promise.reject(new Error(`unexpected prompt: ${prompt}`));
    },
  },
  env: { openExternal: (): Promise<boolean> => Promise.resolve(false) },
  Uri: { parse: (v: string): string => v },
};

const ctx = {
  secrets: {
    get: (k: string): Promise<string | undefined> => Promise.resolve(secrets.get(k)),
    store: (k: string, v: string): Promise<void> => {
      secrets.set(k, v);
      return Promise.resolve();
    },
    delete: (k: string): Promise<void> => {
      secrets.delete(k);
      return Promise.resolve();
    },
  },
};

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

function insideExtensionHost(): boolean {
  try {
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

type AuthModule = typeof import("../../auth");
type ClientModule = typeof import("../../engineClient");
let auth!: AuthModule;
/** The HttpError class the freshly loaded auth.ts checks against, not a copy from another load. */
let HttpErrorCls!: ClientModule["HttpError"];

if (NODE_SIDE) {
  // Every extension module is loaded fresh against the stub, and the cache is put back afterwards,
  // so a sibling suite holding its own copies is unaffected.
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
    const loaded = require("../../engineClient") as ClientModule;
    HttpErrorCls = loaded.HttpError;
    const client = loaded as unknown as Record<string, unknown>;
    client.getJson = (): Promise<unknown> => Promise.resolve({ local: true, ad: false, kerberos: false });
    client.postJson = (_url: string, route: string, _body: unknown, token?: string): Promise<unknown> => {
      posts.push({ route, token });
      if (route === "/me/reauth") {
        return Promise.resolve({ token: "rotated" });
      }
      if (route === "/auth/login") {
        return Promise.resolve({ token: "fresh", must_change_password: false });
      }
      return Promise.reject(new Error(`unexpected route ${route}`));
    };
    auth = require("../../auth") as AuthModule;
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

const composedSuite = NODE_SIDE ? suite : suite.skip;

composedSuite("withStepUpAuth composed with withAuth, end to end (BACKLOG #5960)", () => {
  const context = ctx as unknown as Parameters<AuthModule["withStepUpAuth"]>[0];
  const stepUpRefusal = () =>
    new HttpErrorCls(403, "step-up re-verification required", { action: "config_reload", viaIdp: false });
  const unauthorized = () => new HttpErrorCls(401, "session ended; sign in again");

  setup(() => {
    secrets = new Map([[KEY, "old"]]);
    posts = [];
    prompts = [];
  });

  test("a 401 on the rotated token signs in again, without retrying the refused token", async () => {
    const used: string[] = [];
    const out = await auth.withStepUpAuth(context, ENGINE_URL, (token) => {
      used.push(token);
      if (token === "old") {
        return Promise.reject(stepUpRefusal());
      }
      if (token === "rotated") {
        return Promise.reject(unauthorized());
      }
      return Promise.resolve("reloaded");
    });
    assert.strictEqual(out, "reloaded");
    // Before the fix: ["old", "rotated", "rotated", "fresh"], the second "rotated" a wasted call.
    assert.deepStrictEqual(used, ["old", "rotated", "fresh"]);
    assert.deepStrictEqual(
      posts.map((p) => p.route),
      ["/me/reauth", "/auth/login"],
    );
    assert.strictEqual(posts[0].token, "old", "the re-proof is sent on the token that was refused");
    assert.strictEqual(secrets.get(KEY), "fresh");
    assert.strictEqual(prompts.filter((p) => p.startsWith("Re-enter")).length, 1);
    assert.strictEqual(prompts.filter((p) => p.startsWith("MessageFoundry username")).length, 1);
  });

  test("control: a sign-in elsewhere after the re-proof is still picked up, with no new sign-in", async () => {
    const used: string[] = [];
    const out = await auth.withStepUpAuth(context, ENGINE_URL, (token) => {
      used.push(token);
      if (token === "old") {
        return Promise.reject(stepUpRefusal());
      }
      if (token === "rotated") {
        // Another window signed in and replaced the rotated token before this call reached the engine.
        secrets.set(KEY, "elsewhere");
        return Promise.reject(unauthorized());
      }
      return Promise.resolve("reloaded");
    });
    assert.strictEqual(out, "reloaded");
    assert.deepStrictEqual(used, ["old", "rotated", "elsewhere"]);
    assert.deepStrictEqual(
      posts.map((p) => p.route),
      ["/me/reauth"],
    );
  });

  test("control: withAuth alone still retries a 401 with a newer cached token", async () => {
    const used: string[] = [];
    const out = await auth.withAuth(context, ENGINE_URL, (token) => {
      used.push(token);
      if (token === "old") {
        secrets.set(KEY, "elsewhere");
        return Promise.reject(unauthorized());
      }
      return Promise.resolve("read");
    });
    assert.strictEqual(out, "read");
    assert.deepStrictEqual(used, ["old", "elsewhere"]);
    assert.deepStrictEqual(posts, []);
  });
});
