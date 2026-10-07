// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Step-up re-verification for an engine call (ASVS 7.5.3, ADR 0077, vault BACKLOG #2625). The pure,
// vscode-free half: auth.ts supplies the prompt and the token store, so the node-only `test:unit`
// leg drives this on every CI leg.
//
// The engine refuses a sensitive call with 403 + `X-Step-Up-Required` when the session has not
// re-proved its credential, and names the action in `X-Step-Up-Action` when the route takes a proof
// bound to it (config reload, purge, export, resend). A fresh sign-in does not satisfy an
// action-bound route, so promote failed on every reload until the IDE re-proved. This mirrors the
// engine client (`messagefoundry/apiclient/client.py`, `_request` and `reauth`): prompt for the
// password, POST /me/reauth with the named action as `purpose`, adopt the re-keyed token, retry once.
import { HttpError, type StepUpSignal } from "./engineClient";

/** What {@link withStepUp} needs from its host. Every member is supplied by the caller, so this
 *  module never holds a password beyond the one call that sends it. */
export interface StepUpHost {
  /** Ask the user for their password, masked. `undefined` means the user cancelled. `retry` is
   *  true after a wrong one, so the prompt can say so. */
  promptPassword(signal: StepUpSignal, retry: boolean): Promise<string | undefined>;
  /** POST /me/reauth with `token`; resolve to the re-keyed token the engine returns, if any. */
  reauth(token: string, password: string, purpose: string | undefined): Promise<string | undefined>;
  /** Keep the re-keyed token, so later calls and the sign-in cache use the live session. */
  storeToken(token: string): Promise<void>;
}

/** Thrown for a session that steps up at its identity provider. The IDE cannot drive that leg: it
 *  needs a browser redirect, as the engine client's `IdpStepUpRequired` says. */
export class IdpStepUpRequiredError extends Error {
  constructor() {
    super(
      "this session signed in through the identity provider, so it confirms a sensitive action " +
        "there, in a browser: re-authenticate in the web console at /ui/reauth, then try again",
    );
    this.name = "IdpStepUpRequiredError";
  }
}

/** How many passwords one step-up asks for before it gives up, as the sign-in prompt does. Each
 *  wrong one counts toward the engine's own re-proof budget and lockout, which stay the real bound. */
export const STEP_UP_ATTEMPTS = 3;

const CANCELLED = Symbol("cancelled");

/** Prompt and re-prove, re-asking after a wrong password. Resolves to the re-keyed token (or
 *  `undefined` from an older engine), or {@link CANCELLED}. A refusal that is not a wrong password,
 *  and the last wrong one, reject as they came. */
async function reprove(
  token: string,
  signal: StepUpSignal,
  host: StepUpHost,
): Promise<string | undefined | typeof CANCELLED> {
  for (let attempt = 1; ; attempt++) {
    const password = await host.promptPassword(signal, attempt > 1);
    if (password === undefined) {
      return CANCELLED;
    }
    try {
      return await host.reauth(token, password, signal.action);
    } catch (e) {
      // A wrong password is a plain 403 from /me/reauth. A 403 carrying the IdP signal, a 401 (the
      // session ended) and anything else are not, and re-asking would not help.
      const wrong = e instanceof HttpError && e.status === 403 && e.stepUp === undefined;
      if (!wrong || attempt >= STEP_UP_ATTEMPTS) {
        if (stepUpOf(e)?.viaIdp) {
          throw new IdpStepUpRequiredError();
        }
        throw e;
      }
    }
  }
}

function stepUpOf(e: unknown): StepUpSignal | undefined {
  return e instanceof HttpError && e.status === 403 ? e.stepUp : undefined;
}

/**
 * Run `call` with `token`. On a step-up refusal, re-prove once and retry once.
 *
 * Resolves to `undefined` when the user cancels the prompt. A wrong password re-asks, up to
 * {@link STEP_UP_ATTEMPTS} in all. A refusal of the retried call, the last wrong password and every
 * other error reject as they came, so no loop can form. The password is passed straight to
 * `host.reauth` and is never stored, logged or put in an error message.
 */
export async function withStepUp<T>(
  token: string,
  call: (token: string) => Promise<T>,
  host: StepUpHost,
): Promise<T | undefined> {
  try {
    return await call(token);
  } catch (e) {
    const signal = stepUpOf(e);
    if (signal === undefined) {
      throw e;
    }
    if (signal.viaIdp) {
      throw new IdpStepUpRequiredError();
    }
    const rotated = await reprove(token, signal, host);
    if (rotated === CANCELLED) {
      return undefined; // cancelled: nothing more was sent
    }
    // The engine rotates the session on a successful re-proof (ASVS 7.2.4), so the token this call
    // used is dead once reauth returns. A body with no token is an older engine: keep the one we have.
    let live = token;
    if (rotated !== undefined && rotated !== "") {
      live = rotated;
      await host.storeToken(live);
    }
    return await call(live);
  }
}
