# ASVS packet C (transport) — vault handoff

**All three rows stay OPEN.** Their `Closing-act` is a scorecard re-score in the vault, which a
Builder cannot perform. Full per-row reasoning is in each item's `RE-VERIFIED 2026-09-06 (ASVS packet
C)` block in `docs/BACKLOG.md`; this page is the summary the vault holder asked for. It follows the
shape of `docs/ASVS-PACKET-B-CRYPTO-2026-09-06-FINDINGS.md`.

**Measurement note that applies throughout.** Every library fact was measured on the worktree venv
built from `requirements.lock`, not on the ambient interpreter. `cryptography` reports **50.0.1**,
which matches the lock pin exactly, so the packet B hazard (a box reporting 49.0.0 against a lock
pinning 50.0.1) did not recur here. Runtime: CPython 3.14.6 / OpenSSL 3.5.7.

| Item | Cell | What the verdict should become |
|---|---|---|
| #1175 | 12.1.2 | Stay **partial**. The row's largest gap is dead: #1317's owner-ruled strict positive allowlist landed and refuses at config load, so the CCM-8 acceptance the 2026-08-20 pass measured is gone. Limb 2 (strongest preferred) is still unchecked and invertible by a documented setting. The row's own "record precondition" is also dead — the apply gate now counts introduced glyphs, not presence. |
| #1176 | 12.1.5 | Stay **fail**, and the outcome label must read `fail` rather than any ceiling-is-partial phrasing. Four walls hold. The recorded residual is closed: the test now witnesses its own seam, proven red-first. Nothing about SNI concealment moved. |
| #1177 | 12.2.1 | Stay **partial**. The outbound limb is stronger than the row's own re-score banner says — two of the three escapes that banner names do not exist at HEAD. The client limb (the IDE extension) is unchanged and is what holds the cell short. |

## What was built

**One code change and one documentation correction. Both are small on purpose.**

1. **`tests/test_ech_egress.py` — the #1176 residual, closed.** The 2026-08-22 disclosure recorded
   that `test_both_refusal_sites_carry_the_same_message` passed under a plant deleting the
   `build_destination` refusal. Reproduced at HEAD before touching it. The mechanism the disclosure
   did not name: the test builds a SOAP destination, and the SOAP builder itself calls
   `egress_route_from_settings`, so the resolver raised the identical constant and the assertion
   could not tell the two sites apart. The seam arm now stands a spy in for the registered builder,
   so the raise is attributable to `build_destination` alone, and the test is parametrized over all
   three doubly-covered connectors — SOAP, FHIR, DICOMweb — rather than the one that exposed the
   blind spot. Re-planted, all three cases go red, each naming its own connector. A parametrized
   companion test is the spy's own positive control.
2. **`docs/DEPLOYMENT.md` — the #1177 cleartext note.** It told operators the cleartext off-loopback
   refusal keys on `enforcement = enforce`. True of the raw connectors, understated for the HTTP
   family, which ADR 0092 decision 5 floors back to REFUSE on a non-enforcing instance too. Stated
   once under the channel matrix, cross-referenced from the connector bullet.

## Measurements worth carrying, with their controls

| Claim | How it was established | Control that fired in the same run |
|---|---|---|
| #1317's allowlist landed and refuses at load | Ran the shipped `validate_tls_ciphers`: CCM-8, NULL, anonymous and CBC-SHA2 strings all refused | `ECDHE-RSA-AES256-GCM-SHA384` accepted, so it is not refusing everything |
| The order check is still missing | `ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384` accepted, resolving AES-128 first | The four refusals above |
| The IDE passes no cipher list | Zero `ciphers` / `secureContext` / `createSecureContext` across the tracked `ide/` tree | Four files matched `node:https` or `fetch(`; five `minVersion` hits |
| The apply gate no longer blocks a glyph-carrying residual | Executed `_introduced_banned`: keeping or reducing the glyphs is accepted | A payload adding one warning sign is refused, naming U+26A0 |
| No ECH API on the pinned runtime | Zero names containing "ech" in `dir(ssl)` and on a live context | Three module names and two context attributes containing "cipher" |
| `ech_egress` is unreachable from both authoring surfaces | `Rest(ech_egress=True)` raises `TypeError`; no `**kwargs` on the factories; `connections.toml` routes `[settings]` through the same factories | An invented key refused identically; `verify_tls` present |
| The HTTP-family cleartext refusal ignores the enforcement dial | REST and SOAP refuse on all four postures | MLLP, raw TCP and X12 build on the non-enforcing arm |
| `cleartext_accepted` is the one real escape | A declared cleartext REST hop builds on an enforcing PHI posture | The undeclared hop refuses in the same run |

## Two instrument defects found in the prior pass

**A grep with no control, on the file that mattered.** #1176's 2026-08-20 authoring-surface claim
cites "positive control 14 `verify_tls` hits in the same file". That holds for `config/wiring.py` and
fails for `config/connections_file.py`, which contains zero occurrences of `verify_tls` or even
`tls`. The absence claim on the second file was therefore uncontrolled. Re-measured by execution,
which is also a stronger claim than the grep was making.

**A cost priced against a migration that was never the cost.** #1177 proposes deleting the
`apiclient` non-loopback escape on the grounds that zero deployments make the removal free. The
removal is not free: under ADR 0172 that escape is the only expression of a `tls_terminated_upstream`
topology, and deleting it would leave the two-box bench rig with no posture. It was clamped to
unauthenticated reads on 2026-09-05 instead. Zero deployments removes migration cost, not design
cost.

## Deliberately not done

**Did not build the strength-ordering check or the IDE cipher pin (#1175).** PR 809 is open against
`config/tls_policy.py`'s suite assertions and CI configuration, and the `ide/` tree is held by
another session this cycle. Either build from this worktree would collide with work in flight, and
the row itself requires the IDE cipher pin and its docstring correction to land as one change.

**Did not build the #1317 allowlist.** It had already landed; the brief's instruction not to build it
still held for the right reason after re-measurement, not the one assumed.

**Did not touch `ide/` for #1177.** Validating `messagefoundry.engineUrl` at read and promoting the
target gate from a credential gate to a connectivity gate is the primary fix for that row's client
limb. Splitting it across two worktrees would produce exactly the half-landed gate the row warns
about.

**Did not de-glyph #1175's residual.** It lives in the vault scorecard, which this repository cannot
edit. It is also no longer a precondition: the gate that made it one now counts introduced glyphs
rather than testing presence.

## Checks

**Green:** `ruff check`, `ruff format --check`, `mypy` (strict), the backlog status check, and pytest
over every suite covering a touched file.

**Not run:** the full pytest suite did not finish inside the session. Hosted-runner-only legs were
never visible from this worktree and must be read on the PR.
