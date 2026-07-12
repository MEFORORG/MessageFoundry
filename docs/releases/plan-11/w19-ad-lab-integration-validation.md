# PLAN-11 · Wave 19 · AD/domain-lab & integration validation (end-of-stack, gated)

> **Phase document** — appended 2026-07-12 as the final wave of [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md). It collects the work that **cannot be finished in the ruff/mypy/pytest loop** because it needs a live Active Directory domain rig and/or a real-backend integration environment. **This file is the maintainable source of truth for this wave's status.** Shared coordination rules and wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `ad-lab-integration-validation` |
| **Wave** | 19 (final — runs last) |
| **Status** | **○ Not started — GATED** |
| **Effort** | 13 (mostly lab + integration tests + runbooks, not new engine code) |
| **Backlog items** | #98 · #99(e) · #187 (Kerberos residual) · #224 · #127 · #65 · plus integration validation of the shipped/in-flight chunk (below) |
| **ADR** | #187 Kerberos residual moves **ADR 0079 Proposed → Accepted** on a green lab run; #98 closes the ADR 0068 §9 open items. |
| **Store schema / 3-backend** | No new schema — but this wave is where the store-touching builds get their **real SQL Server / Postgres** validation. |

## Gate — do NOT start until BOTH hold

1. **The AD/domain lab is provisioned.** The superset rig (see *The lab is a superset* below): **DC (AD DS) + AD CS + a gMSA + a domain-joined engine box + a domain-joined client + an IIS/ARR reverse proxy**, and — for the SQL-HA items — an optional **2-node SQL Server AlwaysOn AG across two subnets**. The owner has an AWS AD box not yet configured; a local test-server AD (or AD-in-a-container) is the alternative.
2. **The in-flight build chunk has merged** — Sessions A (#99 + #129), B (#170), C (#109 + #147) from the 2026-07-12 go-live-readiness chunk. This wave *validates* those against a real environment, so it runs after they land.

## Track 1 — AD/domain-lab-gated (needs the live domain)

| Item | What the lab validates | Status |
|---|---|---|
| **#98** | Kerberos EPA acceptor-enforcement **spike** (does pyspnego/SSPI enforce a client CBT under EPA?) + a domain-joined `GET /ui/sso` end-to-end smoke. Prep + runbook already shipped (#938, `docs/security/KERBEROS-EPA-SPIKE-RUNBOOK.md`). | Prep done; **execution AD-gated** |
| **#99(e)** | The end-to-end deployment smoke: gMSA-service engine + integrated SQL auth + gMSA-SPN Kerberos acceptor + reverse-proxy-mTLS front + domain-joined client. Proves the `(a)` installer preflight, `(b)` least-priv flip, `(d)` IIS/ARR reference, `(f)` docs that Session A ships in the loop. | Build in flight; **smoke deferred here** |
| **#187 (Kerberos residual)** | ADR 0079 — coordinate Kerberos SSO **session lifetime with the IdP** instead of minting an independent local session. The rest of #187 (MFA default, TOTP skew, WebAuthn) already shipped; this tail needs an AD/Kerberos IdP to verify end-to-end. **P1.** | 🚧 sole deferred tail |
| **Shipped-path real-world validation** | LDAPS + Kerberos **user-auth real bind** (built with mock LDAP); **#43** service-account store-connect proof; **#44** DPAPI machine-key read *as the gMSA*; **#100** AOAG `MultiSubnetFailover` reconnect (needs the SQL AG rig). All shipped — this is confirmation, nothing is blocked. | Confirmation pass |

## Track 1b — Windows-service lab, but NOT domain-gated

| Item | What it needs | Note |
|---|---|---|
| **#224** | Least-priv **virtual** service-account (`NT SERVICE\<name>`) installer default + the S4 ACL-ordering restructure. Rides the **`windows-service-smoke` CI leg**, no AD. | **Overlaps #99(b)** — reconcile: whichever of Session A's `-AllowLocalSystem` flip and #224 lands second must not re-implement the flip. Bundle here so the deployment-hardening validation is one pass. |

## Track 1c — AD-adjacent, mockable (domain only makes it realistic; keep demand-gate)

| Item | AD angle |
|---|---|
| **#127** | NTLM/Windows (Negotiate) proxy-credential auth via `pyspnego` — Basic/Digest are mockable; only the Windows-integrated path wants a domain-joined client + authenticating proxy. |
| **#65** | Outbound NTLM HTTP auth — same `pyspnego` story. |

## Track 2 — integration / real-environment testing of the built (or in-flight) chunk

These items are **built and unit-green**, but the unit loop can't exercise a real handshake / real backend / clock-driven soak. This wave gives them that pass. None of Track 2 needs AD (except #99, covered above) — it needs real servers, so it batches naturally with the lab stand-up.

- **#129** (expiry-only TLS, ADR 0094) — a real TLS handshake against a synthetic **expired-cert** server across the ~5 connectors (MLLP/FTPS/REST/SOAP/DICOM), plus the negative cases that MUST still fail: **wrong-hostname** and **broken-chain** with the flag on.
- **#170** (audit filter + CSV export) — **3-backend** validation on the real **SQL Server (win2025 CI leg)** + Postgres, not just SQLite: filter correctness, RBAC denial, PHI-safety, and the parameterized-injection negative under each backend.
- **#109 / #147** (credential-fault lane-stop + active-window scheduler, ADR 0095) — integration against a real **FTP/SFTP** server: a bad-credential lockout leaves the queue **un-errored** and stops the lane; plus a clock-driven start/stop **soak** over a scheduled window.
- **Prior-wave security tails worth a real pass** — **#200** transport-refusal residual (integration + audit-event on the live serve path), **#190** pinned-internal-CA **real-cert handshake** (ADR 0093), and **#123 / #153** resend / edit-and-resend **end-to-end across all three backends**.

## The lab is a superset — provision once, clear the batch

Standing up **#99(e)'s** domain rig simultaneously clears **#98** and **#187's Kerberos tail**, and confirms the already-shipped gMSA / integrated-SQL / DPAPI / LDAPS paths (#43/#44 + user-auth bind). Add the **2-node SQL AlwaysOn AG across subnets** and the same lab validates **#100**. **#224** rides a plain Windows-service-smoke leg and needs no domain at all. So one provisioning knocks out **three domain-gated items** and confirms **~four shipped ones** — that's the payoff that justifies the setup.

## Owned files / seams

Mostly **additive tests + runbooks + docs**, so low file-contention (it's the last wave regardless): `scripts/service/install-service.ps1`, `api/tls.py` (cert-store scope-out note), `auth/ldap.py`, `auth/service.py`, `api/security.py` (Kerberos SSO acceptor), `docs/OFF-LOOPBACK-DEPLOYMENT.md`, `docs/security/KERBEROS-EPA-SPIKE-RUNBOOK.md`, `docs/adr/0079-*`, and new `tests/integration/` + `harness/` scenarios.

## Dependencies

Gated on the lab **and** on the go-live-readiness chunk (Sessions A/B/C) merging. No cross-session file contention with earlier waves (all earlier waves have run by the time this one starts).

## Verification — Definition of Done

- The **domain-lab smoke passes** end-to-end (gMSA engine + integrated SQL + Kerberos SSO + reverse-proxy-mTLS + domain client); recorded in the deployment docs as the *first real validation* required before recommending the AD/SSO story to a customer.
- **ADR 0079** moves **Proposed → Accepted**; **#98** and **#187** banners flip with the lab-run evidence; the #98 spike verdict (does EPA enforce?) is recorded.
- The Track-2 integration/soak results are captured (a short `docs/testing/` run record), and the store-touching builds (#170, #123/#153) show green on the **SQL Server + Postgres** legs, not just SQLite.
- Placeholders only in every doc/test — no routable IP, real hostname/domain, or partner/site name (RFC 5737 doc IPs, RFC 2606 `*.example`, `DOMAIN\svc$`).

---
_Appended 2026-07-12 against `origin/main`. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
