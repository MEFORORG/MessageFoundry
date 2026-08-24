// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
//
// Why none of this extension's webview `message` receivers checks `event.origin`, stated once so the
// eight of them do not each carry a different half-answer.
//
// SHAPE VALIDATION IS NOT ORIGIN VALIDATION. Every receiver dispatches on a discriminator (`command`
// or `type`) and ignores anything it does not recognise. That bounds WHAT a message can ask for; it
// says nothing about WHO sent it, and the two are routinely conflated. So the origin question has to
// be answered on its own terms rather than treated as covered.
//
// THE VS CODE API EXPOSES NO ORIGIN A WEBVIEW COULD VERIFY. A webview document is hosted at a
// generated, per-panel `vscode-webview://<uuid>` origin. The extension does not choose it, is not told
// it, and it differs between panels, sessions, and desktop-versus-web VS Code. There is therefore no
// value the extension can bake into the script for `event.origin` to be compared against. Anything
// this script could compare with would have to be read out of the incoming event or out of its own
// document at runtime — that is, supplied by the very sender the check is supposed to authenticate.
// A check like that passes for an attacker exactly as readily as for the extension host, so writing
// one would not be a weak control; it would be a control-shaped comment that makes a reviewer stop
// looking. That is the failure mode worth avoiding here, so the check is deliberately NOT written and
// its absence is documented instead.
//
// WHAT ACTUALLY BOUNDS THESE RECEIVERS, and the limits of each:
//   * The nonce CSP on every panel. Each webview is served with `script-src 'nonce-<n>'` and a fresh
//     cryptographically random nonce (see cspNonce.ts), so no injected or third-party script executes
//     in the document. A `postMessage` has to come from script that is already running somewhere; a
//     document in which only extension-authored script can run has no in-document sender. This is a
//     real enforcement property of the browser, not an assertion about it — but it is scoped to THIS
//     document, and it is the reason the nonce being unguessable is load-bearing rather than cosmetic.
//   * No nested frames. None of these panels embeds an iframe, so there is no child document that
//     could post into them.
//   * The discriminator check at each receiver, which is what makes an unexpected message a no-op.
//
// This is a documented gap, not a closed one: an origin check that could be verified would still be
// worth having, and if VS Code ever exposes one this note is what should be revisited. The one-line
// marker below is what each receiver carries; it is a pointer to this file, not a summary of it.

/** The single-line marker every webview `message` receiver in this extension carries, pointing here.
 *  Kept as an exported constant so the source-text test that enforces its presence and this file
 *  cannot drift apart. */
export const WEBVIEW_ORIGIN_NOTE = "// Origin is NOT checked here — see webviewMessaging.ts.";
