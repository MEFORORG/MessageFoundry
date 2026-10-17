// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Pure (vscode-free) runner for what a workspace-trust grant re-runs (vault BACKLOG #3166). VS Code
// does not re-activate a "limited" extension when trust is granted, so activation work an untrusted
// workspace skipped stays undone until something re-runs it. Node-side unit-tested.

/**
 * At least these activation steps are skipped in an untrusted workspace and re-run on a grant.
 * Without them the Problems list, the CONNECTIONS tree and the code sets stay empty until the next
 * save, and the status bar's hover keeps the actions it planned without trust until the next poll.
 * Each step is a required field, so a caller that leaves one of these out does not compile.
 *
 * A step may return a promise or other thenable; a rejection is reported the same way as a throw.
 */
export interface TrustGrantSteps {
  /** The validate + graph + code-sets pass, which activation runs only in a trusted workspace. */
  refreshViews(): unknown;
  /** Re-plan the engine status bar's actions, whose `canControl` reads workspace trust. */
  repaintStatusBar(): unknown;
  /** Re-learn the engine's certificate, which `refreshEngineTrust` skips when untrusted. */
  refreshEngineTrust(): unknown;
  /** Re-offer the one-time version-control nudge, silent when untrusted (vault BACKLOG #2791). */
  suggestSourceControl(): unknown;
}

/** The run order. `satisfies` makes a step added to {@link TrustGrantSteps} but not here an error. */
const ORDER = {
  refreshViews: 0,
  repaintStatusBar: 1,
  refreshEngineTrust: 2,
  suggestSourceControl: 3,
} satisfies Record<keyof TrustGrantSteps, number>;

/**
 * Run every {@link TrustGrantSteps} step once, views first. Each runs on its own: a step that
 * throws, or returns a thenable that rejects, is handed to `onError` and never skips the steps after
 * it. Nothing is awaited, so a slow step does not delay the others.
 */
export function runTrustGrantSteps(
  steps: TrustGrantSteps,
  onError: (step: keyof TrustGrantSteps, err: unknown) => void,
): void {
  for (const name of Object.keys(ORDER) as (keyof TrustGrantSteps)[]) {
    try {
      Promise.resolve(steps[name]()).catch((err: unknown) => onError(name, err));
    } catch (err) {
      onError(name, err);
    }
  }
}
