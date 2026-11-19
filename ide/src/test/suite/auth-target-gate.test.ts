// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// signOut and withAuth send a cached bearer only to a target assertTargetAllowed passes, the gate
// signIn applies (BACKLOG #5407).
//
// This drives the real auth.ts against a stubbed `vscode`, with engineClient's postJson replaced by a
// spy, so "sent" means the spy saw the token. Each refusal is paired with a loopback control that
// DOES send, so a refusal assertion cannot pass because the spy was not wired. Node-side only, as
// restart-trust.test.ts is: the Extension Host resolves the real `vscode`.
import * as assert from "assert";
import * as path from "node:path";

const LOOPBACK = "http://127.0.0.1:8765";
/** Plain http off-box: assertTargetAllowed refuses it. `.invalid` never resolves. */
const REFUSED = "http://engine.invalid:8765";
const TOKEN = "cached-bearer";

let secrets: Map<string, string>;
let errors: string[];
let posts: { url: string; route: string; token: string | undefined }[];

const vscodeStub = {
  window: {
    showErrorMessage: (message: string): Promise<undefined> => {
      errors.push(message);
      return Promise.resolve(undefined);
    },
    showWarningMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showInformationMessage: (): Promise<undefined> => Promise.resolve(undefined),
    // A sign-in prompt is answered by cancelling, so no test can reach a network sign-in.
    showInputBox: (): Promise<undefined> => Promise.resolve(undefined),
    showQuickPick: (): Promise<undefined> => Promise.resolve(undefined),
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

type AuthModule = typeof import("../../auth");
let auth!: AuthModule;

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
    const client = require("../../engineClient") as Record<string, unknown>;
    client.postJson = (url: string, route: string, _body: unknown, token?: string): Promise<unknown> => {
      posts.push({ url, route, token });
      return Promise.resolve({});
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

const gateSuite = NODE_SIDE ? suite : suite.skip;

gateSuite("a cached bearer goes only to a target assertTargetAllowed passes (BACKLOG #5407)", () => {
  const key = (url: string): string => "messagefoundry.token:" + url;
  const context = ctx as unknown as Parameters<AuthModule["signOut"]>[0];

  setup(() => {
    secrets = new Map([
      [key(LOOPBACK), TOKEN],
      [key(REFUSED), TOKEN],
    ]);
    errors = [];
    posts = [];
  });

  test("A1: signOut to a refused target sends nothing, still forgets the token, and reports no revoke", async () => {
    assert.strictEqual(await auth.signOut(context, REFUSED), false);
    assert.deepStrictEqual(posts, [], "the cached bearer was sent to a refused target");
    assert.strictEqual(secrets.has(key(REFUSED)), false, "the local token must still be forgotten");
    assert.strictEqual(errors.length, 1, "the refusal is shown");
  });

  test("A1 control: signOut to loopback revokes with the cached token", async () => {
    assert.strictEqual(await auth.signOut(context, LOOPBACK), true);
    assert.deepStrictEqual(posts, [{ url: LOOPBACK, route: "/auth/logout", token: TOKEN }]);
    assert.strictEqual(secrets.has(key(LOOPBACK)), false);
  });

  test("A2: withAuth to a refused target never makes the call, though a token is cached", async () => {
    const seen: string[] = [];
    const result = await auth.withAuth(context, REFUSED, (token) => {
      seen.push(token);
      return Promise.resolve("called");
    });
    assert.strictEqual(result, undefined);
    assert.deepStrictEqual(seen, [], "the cached bearer was handed to a call for a refused target");
    assert.strictEqual(errors.length, 1, "the refusal is shown");
  });

  test("A2 control: withAuth to loopback makes the call with the cached token", async () => {
    const seen: string[] = [];
    const result = await auth.withAuth(context, LOOPBACK, (token) => {
      seen.push(token);
      return Promise.resolve("called");
    });
    assert.strictEqual(result, "called");
    assert.deepStrictEqual(seen, [TOKEN]);
  });

  test("A4: a refused URL carrying a markdown command link is not shown as a link at sign-in", async () => {
    // assertTargetAllowed quotes the URL in its reason; the notification would render the link.
    assert.strictEqual(await auth.signIn(context, "[x](command:foo)"), undefined);
    assert.deepStrictEqual(posts, []);
    assert.strictEqual(errors.length, 1, "the refusal is shown");
    assert.ok(!errors[0].includes("[x](command:foo)"), errors[0]);
    assert.ok(!/\]\(command:/.test(errors[0]), errors[0]);
    // Control: it is the target gate's refusal that was shown.
    assert.match(errors[0], /^MessageFoundry: not a valid engine URL: /);
  });

  test("A4 control: a refused host is shown as written, an underscore unescaped", async () => {
    assert.strictEqual(await auth.signIn(context, "http://engine_prod.invalid:8765"), undefined);
    assert.strictEqual(errors.length, 1);
    assert.ok(errors[0].includes("non-loopback host engine_prod.invalid"), errors[0]);
  });

  test("A3: withStepUpAuth inherits the gate through withAuthAdopting", async () => {
    const seen: string[] = [];
    const result = await auth.withStepUpAuth(context, REFUSED, (token) => {
      seen.push(token);
      return Promise.resolve("called");
    });
    assert.strictEqual(result, undefined);
    assert.deepStrictEqual(seen, []);
  });
});
