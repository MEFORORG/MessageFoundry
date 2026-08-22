<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0172 — The engine always serves TLS, minting a self-signed certificate on first run

- **Status:** Accepted (2026-08-22)
- **Date:** 2026-08-22
- **Supersedes:** [ADR 0143](0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md)'s *decision*, not its analysis — see "What of 0143 survives" below
- **Related:** [ADR 0002](0002-tls-everywhere.md) · [ADR 0065](0065-web-ops-dashboard.md) · [ADR 0118](0118-secure-by-default-security-configuration-section.md) · BACKLOG #1276

## Context

`[api].tls_cert_file` and `tls_key_file` both shipped `None`, and `tls_enabled` was literally
`bool(self.tls_cert_file)`. An engine nobody had configured therefore opened a **cleartext
socket** — `uvicorn.run` with no `ssl_context_factory`.

The minting primitive already shipped and was already driven end to end by a CLI verb:
`pki.make_self_signed`, and `_write_private_key` with its `O_EXCL` + `0o600` + Windows-DACL
sequence. Nothing needed inventing; the gap was wiring.

**ADR 0143 considered exactly this change and declined it.** Its own words: *"A full fix —
terminate TLS on the loopback bind so `effective_https` is true and everything (headers +
secure cookie + HSTS) engages — is an **XL**: it means moving the whole API to https by default
and migrating every client (harness, `apiclient`, tray, IDE) in lockstep. Out of scope here."*
It shipped an http-safe hardening subset over the loopback secure-context **without** auto-TLS.

That decline was reasonable on the information it had. **The sizing claim it rests on is
measurably false**, which is why this ADR supersedes the decision rather than merely amending it.

## The measurement that overturns the sizing

0143 sized the client migration as four clients moving in lockstep. Measured on `origin/main`:

| Client | How it decides the scheme |
|---|---|
| tray | **Infers** — `service_toml_uses_tls`, exactly ONE caller (`tray/config.py`) |
| `apiclient` | **Does not.** Zero references to `tls_cert_file`; it is *given* a base URL and only validates the scheme |
| IDE | **Does not.** Its `tls_cert_file` hits are MLLP *connector* schema — the same name for a different setting |
| harness | **Does not infer — it assumes.** Hardcoded `http://127.0.0.1:8765` |

So it is **one inference site plus a set of hardcoded defaults**, not a four-way lockstep
migration. Each default is a one-line flip. The XL that justified declining the full fix does
not exist.

## Decision

**The engine always serves TLS.** An operator-supplied `[api].tls_cert_file` always wins; with
none configured the engine mints a self-signed pair on first run, persists it, and serves HTTPS.

1. **Unconditional, deliberately.** A *conditional* scheme is what let the tray, the harness and
   the DAST target each decide it their own way. Clients cannot disagree about a scheme that has
   no conditional — the divergence is removed rather than managed.
2. **Beneath the operator, never instead of.** The fallback is reached only when no certificate
   is configured, so a site with its own chain sees no behaviour change at all.
3. **NOT in every topology.** `tls_terminated_upstream` (+ `trusted_proxies`) declares a reverse
   proxy terminating TLS *in front* of the engine and speaking plaintext to it. Minting there
   would break the proxy's own hop rather than harden anything. **"Always serves TLS" means the
   engine never leaves a hop unprotected — not that it terminates TLS in every deployment.**
4. **The generated pair is a placeholder to be replaced.** Self-signed, so no chain of trust:
   strictly better than cleartext, strictly worse than an operator chain. A browser shows a trust
   interstitial until it is imported.
5. **Mint-once, then reuse.** `_write_private_key` refuses to overwrite, so a second start loads
   rather than rotating.
6. **Re-minting an expired pair is AUDITED, never silent** (owner ruling, 2026-08-22). Nothing
   re-mints today and `build_api_ssl_context` performs no expiry check, so an unrefreshed pair
   would serve an expired certificate every client rejects. *Silent* is the defect in replacing a
   key on disk, not *replaces*: an audited re-mint keeps this decision true without a human and
   leaves a trail. Timing (at startup versus inside the expiry warn window) is a build detail —
   both mutate disk identically, so the security question is settled for both.

**Storage:** beside the store database. That directory is already the engine's own writable
state, already operator-controlled via `--db` / `[store].path`, and is **not** operator-authored
configuration. *Rejected:* a new `[api].tls_generated_dir` setting — a knob for a question with
one sensible answer. *Rejected outright:* the engine writing `tls_cert_file` into the operator's
service TOML. An engine that edits operator configuration is a surprising side effect, and it was
not needed once the scheme stopped being conditional.

**Lifetime:** 365 days, inheriting the `cert self-signed` CLI default rather than inventing a
second lifetime for the same primitive.

## What of ADR 0143 survives

**Its analysis stands; only its decision is superseded.** 0143's diagnosis — that
`effective_https` gated two coupled concerns on one signal, and that a secure cookie over
cleartext http is dropped by Chrome and Safari and *breaks login* — is correct and is precisely
why this change is the better end state. Its `app.state.loopback` mechanism becomes vestigial
where the engine terminates TLS, because `effective_https` is now true on that bind.

It is not vestigial everywhere: the `tls_terminated_upstream` topology in decision 3 still
reaches the engine over plaintext, and 0143's http-safe subset is what covers it.

## Consequences

- An operator reaching the console for the first time gets a **trust interstitial** until the
  generated certificate is imported. `docs/TRAY.md` already documents that import.
- Every first-party client default becomes `https`. `service_toml_uses_tls` becomes vestigial.
- **No deployment axis** ([§0](../../CLAUDE.md)) — zero instances, so nothing is served in the
  clear today and no upgrade breaks anyone. The change is cheap now and gets dearer with every
  client that learns the scheme its own way.
