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
// in the cache. Two things follow.
//   1. A call already running on the old token can be refused with a 401 in that span. Each sign-in is
//      therefore tracked from before its request leaves until the new token is stored, and a caller
//      that gets a 401 awaits `signInSettled` before it reads the cache. Without that, `withAuth`
//      would find its own dead token still cached, clear the cache and prompt again, and the clear
//      could land after the store and drop the new token.
//   2. A lost reply leaves the cache holding a dead token. If the engine minted the new session and
//      ended the old one, and the reply never arrived, the next authenticated call gets a 401 and
//      `withAuth` signs in again. Before, the old token stayed live in that case. That is the accepted
//      price of ending the old session ahead of the cap; it is not harmless.

/** The slice of `vscode.SecretStorage` a sign-in needs. */
export interface TokenCache {
  get(key: string): PromiseLike<string | undefined>;
  store(key: string, value: string): PromiseLike<void>;
}

/** Sign-ins between "request about to leave" and "new token stored", by cache key. */
const inFlight = new Map<string, Promise<void>>();

/**
 * Send one sign-in for the engine cached under `key`, and store the token it returns.
 *
 * `credentials` is the body without `supersedes`. The cached token, when there is one, is added as
 * `supersedes`; with nothing cached the field is omitted, so the body is exactly `credentials`. A
 * refused sign-in rejects with whatever `post` threw and leaves the cache as it was: the engine ends
 * the named session only once it has accepted the new credential.
 */
export function signInSuperseding<R extends { token: string }>(
  cache: TokenCache,
  key: string,
  credentials: Record<string, string>,
  post: (body: Record<string, string>) => Promise<R>,
): Promise<R> {
  const attempt = (async () => {
    const prior = await cache.get(key);
    const reply = await post(prior ? { ...credentials, supersedes: prior } : credentials);
    await cache.store(key, reply.token);
    return reply;
  })();
  // Chained onto any sign-in already in flight for this key, so one await covers them all. Set in the
  // same tick the attempt starts, which is before its request can leave.
  const settled = Promise.allSettled([inFlight.get(key), attempt]).then(() => undefined);
  inFlight.set(key, settled);
  void settled.then(() => {
    if (inFlight.get(key) === settled) {
      inFlight.delete(key);
    }
  });
  return attempt;
}

/**
 * Resolves once no sign-in tracked for `key` is still between its request and its store. Never
 * rejects: a failed sign-in settles it too. Resolves at once when none is in flight.
 */
export async function signInSettled(key: string): Promise<void> {
  await inFlight.get(key);
}
