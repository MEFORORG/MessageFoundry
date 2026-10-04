// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The part of sign-in that touches the token cache: name the cached token as superseded, send the
// sign-in, store the new token. Kept free of `vscode` so the node-side unit suite can run it; auth.ts
// owns the prompts around it.
//
// WHY THE OLD TOKEN RIDES IN THE SIGN-IN (ASVS 7.2.4, BACKLOG #2281). A sign-in REPLACES the token
// cached for this engine, so the session behind it has to end or it would stay valid, unreachable from
// here, until it idled out. The IDE used to sign in first and then end the old token with its own
// `POST /auth/logout`. The engine applies its per-user session cap inside the sign-in, so for a user
// already at the cap that order pushed out their oldest OTHER session to make room for a session that
// was about to be replaced anyway. `supersedes` in the sign-in body has the engine end the named
// session first, before the cap counts (BACKLOG #2096).
//
// THE COST IS THE ORDER ON THIS SIDE. The old token now dies inside the request, before the new one is
// in the cache. Four things follow.
//   1. A reader of the cache could pick up the dead token in that span. Each sign-in is therefore
//      tracked from before its request leaves until the new token is stored, and `peekToken` in
//      auth.ts awaits `signInSettled` before it reads. A call already sent on the old token can still
//      get a 401, and `withAuth` then reads the cache again through `peekToken`.
//   2. Two sign-ins for one engine run one after the other. The second reads the cache only once the
//      first has stored its token, so it names THAT token and the first one's session ends too. Run
//      side by side, both would name the same old token, and the first new session would be left live
//      and unreachable.
//   3. Nothing may wait forever. auth.ts sends the sign-in with SIGN_IN_TIMEOUT_MS, so every attempt
//      settles, and each wait here is bounded by the longer SIGN_IN_WAIT_MS as well. Only an engine
//      that trickles bytes slower than the timeout could outlast a wait. A reader would then see the
//      old token, and a later sign-in would name it again and could be overwritten by the late reply.
//   4. The tracking lives in one extension host, which is one VS Code window, while SecretStorage is
//      shared by every window. A sign-in in one window is NOT waited for in another. A call there on
//      the old token can get a 401 and prompt for a sign-in the user already made. Its `withAuth`
//      clears the cache before that prompt, and if the first window stored its new token in between,
//      the clear drops it, leaving that session live and unheld until it idles out. Nothing here can
//      wait across windows.
// The order also costs when the reply is lost. If the engine minted the new session and ended the old
// one, and the reply never arrived (a timeout included) or the new token could not be stored, the cache
// still holds a dead token. The next authenticated call gets a 401 and `withAuth` signs in again, and
// the new session stays live, unheld, until it idles out. Before, the old token stayed live in those
// cases. That is the accepted price of ending the old session ahead of the cap; it is not harmless.

/** The slice of `vscode.SecretStorage` a sign-in needs. */
export interface TokenCache {
  get(key: string): PromiseLike<string | undefined>;
  store(key: string, value: string): PromiseLike<void>;
}

/** How long the sign-in request may go silent, in ms. It runs the engine's password hash and its
 *  per-account queue, so it gets far more than a status read. */
export const SIGN_IN_TIMEOUT_MS = 30_000;

/** The longest any wait here lasts, in ms: past the request timeout, so a waiter outlasts the attempt. */
export const SIGN_IN_WAIT_MS = SIGN_IN_TIMEOUT_MS + 5_000;

/** Sign-ins between "request about to leave" and "new token stored", by cache key. Never rejects. */
const inFlight = new Map<string, Promise<void>>();

/** `pending`, or `ms` elapsing, whichever comes first. Never rejects. */
function bounded(pending: Promise<void> | undefined, ms: number): Promise<void> {
  if (pending === undefined) {
    return Promise.resolve();
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expiry = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, ms);
  });
  return Promise.race([pending, expiry]).finally(() => clearTimeout(timer));
}

/**
 * Send one sign-in for the engine cached under `key`, and store the token it returns.
 *
 * `credentials` is the body without `supersedes`. The cached token, when there is one, is added as
 * `supersedes`; with nothing cached the field is omitted, so the body is exactly `credentials`. A
 * refused sign-in rejects with whatever `post` threw and leaves the cache as it was: the engine ends
 * the named session only once it has accepted the new credential.
 *
 * A sign-in already in flight for `key` is waited for first, up to `waitMs`, so this one names the
 * token that one stored.
 */
export function signInSuperseding<R extends { token: string }>(
  cache: TokenCache,
  key: string,
  credentials: Record<string, string>,
  post: (body: Record<string, string>) => Promise<R>,
  waitMs: number = SIGN_IN_WAIT_MS,
): Promise<R> {
  const earlier = inFlight.get(key);
  const attempt = (async () => {
    await bounded(earlier, waitMs);
    const prior = await cache.get(key);
    const reply = await post(prior ? { ...credentials, supersedes: prior } : credentials);
    await cache.store(key, reply.token);
    return reply;
  })();
  // The attempt waits for the earlier sign-in first, so one await covers them all. Set in the same
  // tick the attempt starts, which is before its request can leave.
  const settled = attempt.then(
    () => undefined,
    () => undefined,
  );
  inFlight.set(key, settled);
  void settled.then(() => {
    if (inFlight.get(key) === settled) {
      inFlight.delete(key);
    }
  });
  return attempt;
}

/**
 * Resolves once no sign-in tracked for `key` is still between its request and its store, or after
 * `waitMs`, whichever is first. Never rejects: a failed sign-in settles it too. Resolves at once when
 * none is in flight.
 */
export function signInSettled(key: string, waitMs: number = SIGN_IN_WAIT_MS): Promise<void> {
  return bounded(inFlight.get(key), waitMs);
}
