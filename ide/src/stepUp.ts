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
  /** Ask the user for their password, masked. `undefined` means the user cancelled. */
  promptPassword(signal: StepUpSignal): Promise<string | undefined>;
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

function stepUpOf(e: unknown): StepUpSignal | undefined {
  return e instanceof HttpError && e.status === 403 ? e.stepUp : undefined;
}

/**
 * Run `call` with `token`. On a step-up refusal, re-prove once and retry once.
 *
 * Resolves to `undefined` when the user cancels the prompt. A second refusal, a wrong password and
 * every other error reject as they came, so no loop can form. The password is passed straight to
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
    const password = await host.promptPassword(signal);
    if (password === undefined) {
      return undefined; // cancelled: nothing was sent
    }
    // The engine rotates the session on a successful re-proof (ASVS 7.2.4), so the token this call
    // used is dead once reauth returns. A body with no token is an older engine: keep the one we have.
    const rotated = await host.reauth(token, password, signal.action);
    let live = token;
    if (rotated !== undefined && rotated !== "") {
      live = rotated;
      await host.storeToken(live);
    }
    return await call(live);
  }
}
