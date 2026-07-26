// SPDX-License-Identifier: AGPL-3.0-or-later
// CSP-ENFORCEMENT CANARY (ASVS 3.7.5). Loaded by the /ui page shell as an UN-NONCED <script src>
// whenever a per-response nonce CSP is bound. Under `script-src 'nonce-…' 'strict-dynamic'` a browser
// that ENFORCES the policy refuses this parser-inserted, un-nonced script before it is even fetched —
// so the global below stays undefined. A browser that does NOT enforce CSP fetches and runs it, and
// the nonce'd detect script in the shell then sees the global and raises the visible
// "hardening degraded" banner. It is therefore a TRUE enforcement detect: the flag can only be set
// when the policy is not being applied. Deliberately inert — one boolean, no DOM, no network, no PHI.
window.__mfCspProbe = true;
