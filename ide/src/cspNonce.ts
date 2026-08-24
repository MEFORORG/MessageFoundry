// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// The single source of CSP nonces for every webview the extension builds.
//
// WHY node:crypto AND NOT crypto.getRandomValues. The two contexts have different crypto APIs and
// picking the wrong one is the trap here. Every caller of this module is EXTENSION-HOST code building
// an HTML string before the webview exists, so it runs in Node — `node:crypto` is the right API and
// `window.crypto` is not even in scope. A nonce generated INSIDE a webview would need
// `crypto.getRandomValues`; none is, and none should be, because a nonce the webview computed for
// itself would be a nonce the injected script could also read.
//
// WHY Math.random cannot be used for this. A CSP nonce is a capability: script-src 'nonce-X' means
// "any script that can present X may execute", so guessing X converts a markup-injection foothold
// into script execution and defeats the CSP outright. Math.random is a fast NON-cryptographic PRNG
// (V8 uses xorshift128+) whose full internal state is recoverable from a short run of outputs and is
// explicitly documented as unsuitable for anything security-related. That is a property of the
// generator, not of how many characters are drawn from it: 24 characters of a predictable stream are
// predictable. This module existing at all is the control — twelve hand-copied generators is how the
// project got twelve copies of the same defect.

import { randomBytes } from "node:crypto";

/**
 * A fresh, unguessable CSP nonce: 18 cryptographically random bytes (144 bits) in base64url.
 *
 * base64url, not plain base64, so the value is safe verbatim in both places it lands — the
 * `nonce="..."` HTML attribute and the `'nonce-...'` CSP directive — with no `+`, `/` or `=` to
 * escape. 18 bytes encode to exactly 24 characters with no padding, which is also the length the
 * generators this replaces produced.
 */
export function nonce(): string {
  return randomBytes(18).toString("base64url");
}
