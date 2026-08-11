<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0139 — ECH egress sidecar: SNI hiding on outbound TLS for ASVS 12.1.5 (demand-gated)

- **Status:** Accepted (2026-07-20) — **Increment 1 (engine-side routing) built + verified**; the in-tree Go re-originator was written, then **retired 2026-08-10** by owner ruling (BACKLOG **#1011**); live ECH stays demand-gated. See *Implementation status* and *Disposition*.
- **Date:** 2026-07-20
- **Related:** [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) (transport security) · [ADR 0093](0093-pinned-internal-ca-trust-anchor.md) §3 (ECH/stdlib gap note) · ASVS-L3-ASSESSMENT-2026-07-20.md §3 (12.1.5 Fail) · ASVS-L3-RISK-ACCEPTANCE-REGISTER.md theme 7 · solutions research (`ASVS-L3-FAILS-SOLUTIONS-RESEARCH-2026-07-20.md`) · BACKLOG **#272**

---

## Implementation status

**Increment 1 — built + verified (commit `a0c336ce`): the engine-side routing + fail-closed plumbing only.**
- `transports/rest.py` — `ech_sidecar_url_from_settings` (an opt-in per-connection route to a **loopback** sidecar,
  reusing the ADR 0126 opener plumbing) + `egress_route_from_settings`, the single ECH-or-proxy resolver
  (mutually exclusive). Per-connection `ech_egress` / `ech_sidecar` settings. fhir/soap/dicomweb switched to
  the resolver (byte-identical when `ech_egress` is unset; smart/http_auth inherit via the threaded proxy).
- **Fail-closed:** sidecar down → the hop errors (no direct, SNI-leaking fallback); non-loopback / missing
  sidecar refused. Operator recipe: [`samples/ech-sidecar/`](../../samples/ech-sidecar/README.md).
- **Verified:** ruff + `mypy --strict` clean; 13 tests incl. a **stub-proxy behavioral test** proving egress
  routes THROUGH the sidecar and fails closed when it is down; 309 existing connector tests still pass.

**Honest limit — this increment does NOT itself originate ECH.** ECH lives in the ClientHello; a generic
proxy **tunnels** an `https://` destination (CONNECT), so the engine's own non-ECH TLS still reaches the
partner. Hiding the SNI requires the sidecar to **terminate the loopback hop and re-originate** a fresh
ECH-bearing TLS connection (over DoH). **Still deferred:** the cleartext-to-sidecar hand-off for `https`
destinations so the sidecar can terminate, native CPython ECH once OpenSSL 4.0 + CPython PR #135435 GA, and
any live ECH handshake exercised by an automated check. **Inert today regardless:** the 2026-07-20 DoH probe
found no partner endpoint publishes an `ECHConfig`.

## Disposition (2026-08-10) — the terminating re-originator was BUILT, then RETIRED

The *Implementation status* block above filed the terminating re-originator under *"Deferred (the real ECH
work)"*. That was wrong at HEAD and is corrected here: it was **written**, it lived in the tree, and it has
now been **removed by decision** rather than never attempted.

- **What existed.** `tools/ech-sidecar/` — a **stdlib-only Go** loopback re-originator (`main.go`, 312
  lines, + `go.mod` + `README.md`): resolves the destination's `ECHConfigList` from its DNS HTTPS record
  (RR type 65) over DoH, dials with `EncryptedClientHelloConfigList` set, never sets `InsecureSkipVerify`,
  refuses `CONNECT`, and fails closed twice over (no `ECHConfig` published, or `ECHAccepted == false` →
  refuse, never a silent non-ECH completion).
- **What proved it, and how far that goes.** A **recorded manual observation** against
  `crypto.cloudflare.com` (`/cdn-cgi/trace` reporting `sni=encrypted` through the sidecar, and `502` for a
  host publishing no `ECHConfig`). That is a real result and it settles the *"a working ECH client would
  require a third-party TLS stack"* claim — it did not. It is **not** a repeatable gate: no workflow ever
  ran it, and none does now.
- **Why it is retired (owner ruling, BACKLOG #1011).** Nothing built, tested, linted or version-pinned it —
  a grep for `setup-go|go build|go vet|golangci|GOPROXY|gofmt|GOTOOLCHAIN` across every workflow, `ci/`,
  `scripts/`, `.pre-commit-config.yaml` and `tests/` returned zero hits — and `pyproject.toml:21`'s
  `only-include` kept `tools/` out of both sdist and wheel, so it reached no user. Keeping it is a standing
  second-language obligation (a pinned toolchain, a build/test/lint leg, a signing and distribution answer)
  bought for an artefact with **no beneficiary**: no partner endpoint publishes an `ECHConfig`. The ASVS
  12.1.5 cell is `fail` either way — keeping it buys no cell and deleting it costs none.
- **Retrieval, so the work is not lost.** `git show 62fd628d:tools/ech-sidecar/main.go` (and
  `:tools/ech-sidecar/README.md` for the proof transcript). The tree was byte-identical from `62fd628d`
  until its deletion.
- **What replaces it.** Nothing in-tree, deliberately. The sidecar is **operator-supplied** and the
  contract it must satisfy is published at
  [`samples/ech-sidecar/`](../../samples/ech-sidecar/README.md); sing-box remains the off-the-shelf
  candidate, and the retired binary is a worked example of the same contract. The engine-side routing +
  fail-closed refusals (Increment 1) and `tests/test_ech_egress.py` are untouched by this ruling.
- **What would reverse it.** The build trigger below — a real partner endpoint begins publishing an
  `ECHConfig`. Reversal starts from the retrieval SHA plus the ownership costs listed above, taken
  deliberately.

## Context

ASVS 5.0 L3 requirement **12.1.5** (Encrypted Client Hello) is scored **Fail** in both postures: the
engine's outbound TLS clients (FHIR/REST/SOAP/SMART/DICOMweb/webhook) send a cleartext ClientHello whose
**SNI leaks the destination hostname** — a network observer on the external hop learns *which* partner/EHR
the engine talks to (metadata only; TLS still encrypts the payload — **no PHI content is exposed**).

Two verified facts (research + two local spikes) frame the decision:

1. **ECH is not reachable from the stdlib.** It is an **OpenSSL 4.0** feature (RFC 9849; first shipped 4.0
   Alpha 1, March 2026), absent from every 3.5.x release. A local `ctypes` symbol probe of CPython 3.14's
   bundled `libssl-3.dll` (OpenSSL 3.5.7) found **zero ECH symbols** — a shim is a dead end on this build.
   Stock CPython has no ECH either (issue #89730; PR #135435 open). It **is** buildable off-stdlib (Go
   `crypto/tls` since 1.23, rustls, sing-box), so "ECH is unbuildable from application code" is refuted, but
   "stdlib suffices" is confirmed false.
2. **There is no current beneficiary.** A live DoH type-65 probe on 2026-07-20 of the real partner-endpoint
   classes — Epic (`fhir.epic.com`, `open.epic.com`, `apporchard.epic.com`), Oracle Health/Cerner
   (`fhir-ehr.cerner.com`, …), athenahealth, Google Cloud Healthcare (`healthcare.googleapis.com`), SMART
   (`launch.smarthealthit.org`), 1upHealth — found that **none publishes even an HTTPS record**, let alone an
   ECH config (the `crypto.cloudflare.com` control confirmed the probe detects ECH correctly). ECH
   deployment is effectively Cloudflare-only. A client-side ECH sidecar built today would be **inert**.

The residual is metadata-only and low significance; it is a signed accepted residual (register theme 7).
This ADR records the chosen architecture for when a **partner endpoint begins publishing ECH configs** (the
register's re-score trigger) — not a decision to build now.

## Decision

**When the trigger fires, close 12.1.5 with an opt-in, per-connection, fail-closed ECH egress sidecar: a
Go/sing-box process that terminates the engine's outbound connection and re-originates a fresh ECH-bearing
TLS connection, discovering the ECHConfig via DNS HTTPS records over DoH/DoT. It is off by default and
enabled per partner; a non-negotiated ECH handshake fails closed (no silent downgrade). The disposition is
documented honestly as Pass-when-configured, applicable only to ECH-publishing (today: Cloudflare-fronted)
endpoints.**

Rationale for the components (all verified):
- **sing-box / Go stdlib** ships stable client ECH with **automatic HTTPS-RR discovery** and fail-closed
  semantics — the lowest-effort concrete path. No transparent "add-ECH" proxy exists (DEfO split-mode is
  server-side only), so the sidecar **must** terminate and re-originate.
- The **DNS half must ride DoH/DoT** (`dnspython` ≥2.1.0 or the sidecar's own resolver) or the hostname
  leaks in cleartext DNS anyway, defeating the purpose.

## Options considered

1. **Go/sing-box egress sidecar** — off-the-shelf, fail-closed, built-in DoH discovery. **CHOSEN.**
2. **Native CPython `ssl` ECH** (OpenSSL 4.0 + CPython PR #135435) — the clean in-engine path **once upstream
   lands**; a forked interpreter today. **Deferred** — adopt when CPython ships ECH.
3. **rustls binding** — stable ECH in the crate, but no mature Python binding ships it. **Rejected** (build-a-binding cost).
4. **curl `CURLOPT_ECH` via pycurl** — experimental, "DO NOT USE IN PRODUCTION", pycurl passthrough unverified. **Rejected.**
5. **ctypes/cffi shim over the bundled OpenSSL** — **impossible** on CPython 3.14 (libssl 3.5.7 exports no ECH symbols). **Rejected.**

## Consequences

**Positive** — moves 12.1.5 Fail → Pass-when-configured for ECH-publishing endpoints; fail-closed avoids a
false sense of protection.

**Negative / risks** — would put a **Go binary** inside an AGPL Python product (packaging, signing, update
story) *if the project ever shipped one*; the 2026-08-10 ruling avoids that cost by keeping the sidecar
**operator-supplied** (*Disposition*). Also: an extra egress hop to operate; **near-nil value today** (no
partner endpoint supports ECH — the probe must be re-run before any build); the DNS half requires DoH
configuration or the leak persists.

**Out of scope** — building it now (demand-gated, zero current beneficiary); server-side ECH; the in-engine
native path (revisit when OpenSSL 4.0 + CPython PR #135435 GA); 13.3.3 ([ADR 0138](0138-transit-bulk-crypto-provider-dek-out-of-engine-heap-for-asvs-13-3-3-demand-gated.md)).

## To resolve on acceptance

- [ ] **Re-run the DoH type-65 probe** of the deployment's actual egress allowlist — build only if a real partner now publishes ECH.
- [x] **Decide the sidecar and its packaging/signing** — resolved 2026-08-10 (#1011): the sidecar is **operator-supplied and not shipped**, so there is no wheel/installer packaging or signing question left to answer. sing-box and the retired reference implementation (*Disposition*) each satisfy the published contract.
- [x] **Define the per-connection opt-in config and fail-closed routing for non-ECH endpoints** — built in Increment 1 (`ech_egress` / `ech_sidecar`; a missing, non-loopback or `proxy_url`-paired sidecar is refused at construction, and a down sidecar errors rather than falling back). The **DoH resolver is the sidecar's**, by design — it is part of the contract, not engine code.
- [ ] Reassess against the native CPython path once OpenSSL 4.0 GA + PR #135435 land (may supersede the sidecar).
