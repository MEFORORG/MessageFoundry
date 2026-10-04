// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import * as path from "node:path";

import { HttpError, postJson } from "../../engineClient";
import { signInSettled, signInSuperseding, type TokenCache } from "../../signInSession";

// BACKLOG #2281 (ASVS 7.2.4): a sign-in names the token it replaces as `supersedes`, so the engine ends
// that session before its per-user cap counts. The IDE used to sign in and then POST /auth/logout with
// the old token, which let the cap push out another of the user's sessions first.
//
// Node-side, against a loopback server and the real `postJson`, so what is asserted is the body on the
// wire. `auth.ts` imports `vscode` and cannot load here; the last suite reads its source instead.

const KEY = "messagefoundry.token:http://engine.test";
const CREDENTIALS = { username: "op", password: "a-strong-test-passphrase", provider: "local" };

interface Seen {
  route: string;
  body: Record<string, unknown>;
}

class MapCache implements TokenCache {
  readonly values = new Map<string, string>();
  async get(key: string): Promise<string | undefined> {
    return this.values.get(key);
  }
  async store(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }
}

suite("sign-in names the cached token as superseded (BACKLOG #2281)", () => {
  let server: http.Server;
  let url: string;
  let seen: Seen[];
  let refuse: boolean;

  setup(async () => {
    seen = [];
    refuse = false;
    server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<string, unknown>;
        seen.push({ route: req.url ?? "", body });
        res.setHeader("Content-Type", "application/json");
        if (refuse) {
          res.statusCode = 401;
          res.end(JSON.stringify({ detail: "invalid credentials" }));
          return;
        }
        res.end(JSON.stringify({ token: `tok-${seen.length}`, must_change_password: false }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  teardown(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const signIn = (cache: TokenCache) =>
    signInSuperseding(cache, KEY, CREDENTIALS, (body) =>
      postJson<{ token: string }>(url, "/auth/login", body),
    );

  test("with nothing cached the body carries no supersedes field", async () => {
    const cache = new MapCache();
    const reply = await signIn(cache);
    assert.deepStrictEqual(seen, [{ route: "/auth/login", body: CREDENTIALS }]);
    assert.ok(!("supersedes" in seen[0].body), "an absent token must be omitted, not sent empty");
    assert.strictEqual(cache.values.get(KEY), reply.token);
  });

  test("a cached token rides in the sign-in, and no /auth/logout follows", async () => {
    const cache = new MapCache();
    cache.values.set(KEY, "tok-cached");
    const reply = await signIn(cache);
    // RED when: the sign-in goes back to revoking afterwards (a second request appears), or stops
    // naming the token (the engine's cap then counts the session that is about to be replaced).
    assert.deepStrictEqual(seen, [
      { route: "/auth/login", body: { ...CREDENTIALS, supersedes: "tok-cached" } },
    ]);
    assert.strictEqual(cache.values.get(KEY), reply.token);
    assert.notStrictEqual(reply.token, "tok-cached");
  });

  test("a refused sign-in leaves the cached token in place", async () => {
    const cache = new MapCache();
    cache.values.set(KEY, "tok-cached");
    refuse = true;
    await assert.rejects(
      () => signIn(cache),
      (e: unknown) => e instanceof HttpError && e.status === 401,
    );
    assert.strictEqual(cache.values.get(KEY), "tok-cached");
    assert.strictEqual(seen.length, 1, "a refused sign-in must not be followed by a revoke");
  });
});

suite("a caller can wait out a sign-in in flight (BACKLOG #2281)", () => {
  // The engine ends the superseded token inside the sign-in request. Until the reply is stored the
  // cache still holds that dead token, so a caller refused with a 401 must be able to wait.

  /** A `post` the test answers by hand, to hold a sign-in between its request and its reply. */
  function heldPost(): {
    post: (body: Record<string, string>) => Promise<{ token: string }>;
    sent: Promise<void>;
    answer: (token: string) => void;
    fail: (e: Error) => void;
  } {
    let markSent!: () => void;
    const sent = new Promise<void>((resolve) => (markSent = resolve));
    let answer!: (token: string) => void;
    let fail!: (e: Error) => void;
    const reply = new Promise<{ token: string }>((resolve, reject) => {
      answer = (token) => resolve({ token });
      fail = reject;
    });
    return {
      post: () => {
        markSent();
        return reply;
      },
      sent,
      answer,
      fail,
    };
  }

  test("signInSettled resolves only after the new token is stored", async () => {
    const cache = new MapCache();
    cache.values.set(KEY, "tok-old");
    const held = heldPost();
    const signingIn = signInSuperseding(cache, KEY, CREDENTIALS, held.post);
    await held.sent; // the request has left: the engine has ended tok-old by now

    let settled = false;
    const waiting = signInSettled(KEY).then(() => {
      settled = true;
      return cache.values.get(KEY);
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    // RED when: the wait resolves while the dead token is still the cached one. `withAuth` would
    // then clear the cache and prompt for a sign-in the user already made.
    assert.strictEqual(settled, false, "the wait ended while the sign-in was still in flight");
    assert.strictEqual(cache.values.get(KEY), "tok-old");

    held.answer("tok-new");
    assert.strictEqual(await waiting, "tok-new", "the waiter read the cache before the store");
    assert.strictEqual((await signingIn).token, "tok-new");
  });

  test("a failed sign-in ends the wait without rejecting it", async () => {
    const cache = new MapCache();
    cache.values.set(KEY, "tok-old");
    const held = heldPost();
    const signingIn = signInSuperseding(cache, KEY, CREDENTIALS, held.post);
    await held.sent;
    const waiting = signInSettled(KEY);
    held.fail(new Error("engine went away"));
    await assert.rejects(signingIn, /engine went away/);
    await waiting; // must resolve: the waiter is some other call, and this failure is not its own
    assert.strictEqual(cache.values.get(KEY), "tok-old");
  });

  test("with no sign-in in flight the wait resolves at once, and a finished one is forgotten", async () => {
    await signInSettled("messagefoundry.token:http://never-signed-in.test");
    const cache = new MapCache();
    const held = heldPost();
    const signingIn = signInSuperseding(cache, KEY, CREDENTIALS, held.post);
    held.answer("tok-1");
    await signingIn;
    await signInSettled(KEY);
    // A second, later sign-in is tracked afresh rather than read as already settled.
    const again = heldPost();
    const second = signInSuperseding(cache, KEY, CREDENTIALS, again.post);
    await again.sent;
    let settled = false;
    const waiting = signInSettled(KEY).then(() => (settled = true));
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.strictEqual(settled, false);
    again.answer("tok-2");
    await second;
    await waiting;
  });

  test("a second sign-in waits for the first and names the token the first one stored", async () => {
    const cache = new MapCache();
    cache.values.set(KEY, "tok-old");
    const named: Array<string | undefined> = [];
    const first = heldPost();
    const signingInFirst = signInSuperseding(cache, KEY, CREDENTIALS, (body) => {
      named.push(body.supersedes);
      return first.post(body);
    });
    await first.sent;
    const signingInSecond = signInSuperseding(cache, KEY, CREDENTIALS, async (body) => {
      named.push(body.supersedes);
      return { token: "tok-second" };
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    // RED when: both sign-ins read the cache up front. Both then name tok-old, and the first new
    // session is overwritten in the cache and left live on the engine.
    assert.deepStrictEqual(named, ["tok-old"], "the second sign-in did not wait for the first");
    first.answer("tok-first");
    await signingInFirst;
    await signingInSecond;
    assert.deepStrictEqual(named, ["tok-old", "tok-first"]);
    assert.strictEqual(cache.values.get(KEY), "tok-second");
  });

  test("a sign-in that never answers is waited for only as long as the bound", async () => {
    const cache = new MapCache();
    cache.values.set(KEY, "tok-old");
    const hung = heldPost();
    void signInSuperseding(cache, KEY, CREDENTIALS, hung.post, 20).catch(() => undefined);
    await hung.sent;
    // RED when: the wait has no bound. postJson has no timeout, so a reader would hang with it.
    await signInSettled(KEY, 20);
    assert.strictEqual(cache.values.get(KEY), "tok-old");
    hung.fail(new Error("cleanup")); // release it, so the next test starts with nothing in flight
    await signInSettled(KEY, 1000);
  });
});

suite("auth.ts routes sign-in through the superseding path (BACKLOG #2281)", () => {
  // auth.ts needs the Extension Host, so this reads its source. A scan that silently matches nothing
  // is indistinguishable from a clean file, hence the controls below.
  const AUTH_TS = path.resolve(__dirname, "../../../src/auth.ts");

  /** The source of the top-level function `name`, from its declaration to the next one. */
  function functionSource(text: string, name: string): string {
    const start = text.search(new RegExp(`export async function ${name}[(<]`));
    assert.ok(start >= 0, `${name} was not found in auth.ts`);
    const next = text.indexOf("\nexport ", start + 1);
    return text.slice(start, next < 0 ? undefined : next);
  }

  /** The lines that post `/auth/logout`. */
  const logoutSites = (text: string): string[] =>
    text.split(/\r?\n/).filter((l) => l.includes('"/auth/logout"'));

  test("signIn posts through signInSuperseding and no longer revokes afterwards", () => {
    const text = fs.readFileSync(AUTH_TS, "utf8");
    assert.ok(text.includes("signInSuperseding(ctx.secrets, secretKey(url), body"), "signIn's call moved");
    const sites = logoutSites(text);
    assert.strictEqual(sites.length, 1, `only signOut may post /auth/logout; found ${sites.length}`);
    assert.ok(/postJson<unknown>\(url, "\/auth\/logout", \{\}, token\)/.test(sites[0]), sites[0]);
    // Control: the same count over the pre-fix shape, signOut's line plus the trailing revoke that
    // signIn carried, must find both.
    const before = [
      '    await postJson<unknown>(url, "/auth/logout", {}, token);',
      '      void postJson<unknown>(url, "/auth/logout", {}, prior).catch(() => undefined);',
    ].join("\n");
    assert.strictEqual(logoutSites(before).length, 2, "the predicate cannot see the old revoke");
  });

  test("every cache read waits for a sign-in in flight, and withAuth reads before it clears", () => {
    const text = fs.readFileSync(AUTH_TS, "utf8");
    const peek = functionSource(text, "peekToken");
    const wait = peek.indexOf("await signInSettled(secretKey(url));");
    const read = peek.indexOf("ctx.secrets.get(secretKey(url))");
    assert.ok(wait > 0, "peekToken no longer waits for a sign-in in flight");
    assert.ok(read > wait, "peekToken reads the cache before the wait");
    // Every other read of the cache goes through peekToken.
    const direct = text.split(/\r?\n/).filter((l) => l.includes("ctx.secrets.get("));
    assert.strictEqual(direct.length, 1, `a cache read bypasses peekToken: ${direct.join(" | ")}`);
    assert.ok(functionSource(text, "ensureToken").includes("await peekToken(ctx, url)"));
    const withAuth = functionSource(text, "withAuth");
    const cached = withAuth.indexOf("const cached = await peekToken(ctx, url);");
    const clear = withAuth.indexOf("await clearToken(ctx, url);");
    assert.ok(cached > 0, "withAuth no longer reads the cache through peekToken after a 401");
    assert.ok(clear > cached, "the clear moved ahead of the cache read");
  });
});
