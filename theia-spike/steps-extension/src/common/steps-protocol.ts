// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-1 (ADR 0208): the JSON-RPC contract between the Steps widget (frontend) and the backend
// service that shells the engine's `lens` CLI. The frontend never runs a process (spec section 9);
// it hands the backend module SOURCE text, never a path, so the backend has no path to resolve.

export const STEPS_LENS_PATH = '/services/mf-steps-lens';
export const StepsLensService = Symbol('StepsLensService');

/** A finished `python -m messagefoundry ...` call. Never a rejection: a failure is a non-zero code. */
export interface LensCallResult {
    stdout: string;
    stderr: string;
    code: number;
}

/** What the backend found when it resolved the interpreter. */
export interface LensServiceInfo {
    /** The configured interpreter, or undefined when none is configured (the service then refuses). */
    python?: string;
    /** Why the service is unavailable, when it is. */
    problem?: string;
}

export interface StepsLensService {
    /** `lens parse - --json --contract 2` over `source` piped on stdin. */
    parse(source: string): Promise<LensCallResult>;
    /** `lens rewrite - --contract 2 --edit <spec>` over `source` piped on stdin. */
    rewrite(source: string, spec: object): Promise<LensCallResult>;
    /** `lens schema --json`: the per-parameter widget kinds, so an int stays an int on write-back. */
    schema(): Promise<LensCallResult>;
    /**
     * The reused `ide/` webview assets: `ide/media/stepsWebview.js` unchanged, and the `<style>` block
     * of `pageHtml` in `ide/src/stepsView.ts`, cut out of that file's text at run time (the spike's
     * stand-in for moving the CSS into a shared package).
     */
    webviewAssets(): Promise<{ script: string; style: string }>;
    info(): Promise<LensServiceInfo>;
}
