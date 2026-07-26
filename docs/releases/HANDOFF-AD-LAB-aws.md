# Handoff — the AD / federation lab window, on the AWS boxes (2026-07-24)

> **Four backlog items, one booking.** #275 → #98, #99(e), #274. The runbook says to plan them
> **"as one window, or not at all"** — they share a single throwaway forest, and #275 hard-blocks two of
> the others.
>
> **The authority is [`docs/security/AD-FEDERATION-LAB-RUNBOOK.md`](../security/AD-FEDERATION-LAB-RUNBOOK.md)**
> (cells L0–L18) and its sibling [`KERBEROS-EPA-SPIKE-RUNBOOK.md`](../security/KERBEROS-EPA-SPIKE-RUNBOOK.md)
> §§1–2 for provisioning. **This document does not restate them.** It is the AWS-specific wrapper: what to
> stand up, in what order, what must not happen, and what "done" means per item.

## Claim it first

```powershell
pwsh -NoProfile -File scripts\coord\claim.ps1 -Take ad-lab-window -Note "AD/federation lab: 275, 98, 99e, 274"
pwsh -NoProfile -File scripts\coord\claim.ps1 -List
```

One claim covers the window; the items are inseparable in practice. (Free-text key — the `commit-msg`
gate only enforces numbered items, so this one is advisory, surfaced in every session's start banner.)

---

## ⛔ Non-negotiables — read before provisioning

- **Never stop, terminate, or tear down an EC2 instance without the owner's say-so.** Standing rule.
  This lab *adds* boxes; it does not touch the existing bench rig.
- **Write every artifact OFF instance-store.** A STOP/START wipes the instance-store volume (this has
  already cost work on the bench rig). The run record **is** the deliverable — put it on EBS or copy it
  off the box as you go.
- **Disposable LAB forest only — never point a step at production AD.**
- **A Domain Controller is a VM role, never a container.** On AWS that means a real EC2 Windows instance.
- **Placeholders only in anything committed.** RFC 2606 names (`mefor.lab`, `*.example`), RFC 5737 IPs
  (`192.0.2.0/24`, `198.51.100.0/24`), `DOMAIN\svc$`. **No routable IP, real hostname, domain, partner or
  site name, and no message bodies.** `forbidden-content` is a **blocking** CI context — scrubbing the L17
  run record is an explicit sub-step, not a formality.
- **Do not wire any of this to CI.** A domain-joined self-hosted runner executing repo code is a much
  larger blast radius than the existing mirror-gated `windows-service-smoke`. Hand-run it; commit the
  scrubbed record.
- **Do not build a third acceptance framework.** `messagefoundry/verify/` already owns the
  PASS/FAIL/SKIP/MANUAL contract; this extends it via `verify --section federation`.

---

## Boxes to stand up

| Box | Role | Notes |
|---|---|---|
| **A** | DC — throwaway forest `mefor.lab`, **plus the AD FS farm** | `Install-ADDSForest`; groups `mefor-ops`, `mefor-admins`; users `jdoe`, `asmith`, **and `psmith` configured passwordless / smartcard-required** (cell L9 needs it). AD FS needs a service-communication TLS cert — self-signed is fine for a throwaway lab. |
| **B** | Engine host, domain-joined, NSSM service | Engine bound loopback, `[api].public_origin = http://localhost:8765`. Browser runs here for pass 1. |
| **C** | Domain-joined client with **Chrome *and* Firefox** | Needed for the two-browser landing assertion (L7). **May be Box B** for pass 1 — one less instance. |

Optional and **not** needed for pass 1: AD CS, the IIS+ARR mTLS front (pass 2), an Entra tenant (pass 2).

**AD FS trust gotcha, worth knowing before you burn an hour on it:** trusting the AD FS cert *in the
browser is not sufficient* — the **engine** makes the back-channel token/JWKS fetches itself through
`auth/oidc_http.py`, which uses `ssl.create_default_context()`. That **does** read the Windows machine
store, so installing the AD FS CA into **Local Machine → Trusted Root is expected to be enough** and is
the first thing to try. Two traps: anchors are snapshotted when the context is built, so a cert trusted
*after* the engine starts needs a **restart**; and a cert in a *user* store is never seen. If trust still
fails, pin `oidc_tls_ca_cert_file` (pinned-**only** — that PEM becomes the entire anchor set for the hop).
**Do not reach for `truststore`** — deliberately not used (shared-context race, ADR 0142).

---

## Order of play

Run **L0** first (baseline, everything off) — every later cell diffs against it, and it is the
byte-identical-when-off proof.

```
L0  baseline
 │
 ├─ L1   #275 SPN defect ────────► HARD BLOCKER for L6 and the #99(e) cells
 │        confirmed if the acceptor principal reads HTTP/engine.mefor.lab/unspecified
 │        → fix #275 (split kerberos_spn into service/hostname at BOTH call sites)
 │        → do NOT thread channel_bindings until this passes
 │
 ├─ L2, L3, L5      #99(e)  gMSA logon · integrated SQL · Kerberos SSO
 ├─ L5a, L6         #98     out_token browser behaviour · the 2×3 EPA matrix
 └─ L6a → L18       #274    OIDC — L6a gates everything after it
```

**L6a is the pivot.** It is the first OIDC cell: confirm all three of (a) the loopback redirect URI is
accepted, (b) `code_challenge_method=S256` from a confidential client, (c) a custom `amr` rule lands in
the id_token. **Any failure → apply the fallback rig** (hostname + self-signed cert on the engine, and
record the EPA consequence) **before** L7. Discovering this at L7 costs a re-rig.

---

## What "done" means, per item

| Item | Cells | Done when |
|---|---|---|
| **#275** SPN defect | **L1** | Confirmed or refuted **on a real acceptor**. If confirmed, the fix is small: split `kerberos_spn` at the first `/` into `service=`/`hostname=` at **both** call sites. |
| **#99(e)** AD/gMSA smoke | **L2, L3, L5** (+ L7/L13 if pass-2 IIS+ARR runs) | Only sub-item (e) remains — (a)(b)(d)(f) are already on `main`, (c) is a documented stdlib scope-out, (g) shipped inside #274. |
| **#98** Kerberos EPA | **L6** (+ **L5a** recorded) | A **complete 2×3 matrix** where every verdict cell negotiated `kerberos` and the baseline accepted. Anything less **self-reports INCONCLUSIVE** — do not round up. If L5a is skipped, #98's banner must say `out_token` stays open. **Part (b) is conditional**: build the opt-in `tls-server-end-point` binding *only if* the acceptor enforces a client CBT. |
| **#274** federated SSO | **L6a → L18** | ADR 0142 flips **Proposed → Accepted** only when **L6a, L9 and L18** all report. |

### Three cells that can invalidate the architecture — record them verbatim

- **L9 — must be able to FAIL.** Step-up as `psmith` (passwordless/smartcard) is **expected to fail**: a
  simple bind cannot succeed for such an account, i.e. a permanent 403 on every step-up route. If it does
  fail, **the ADR's step-up advantage is void** — record the documented fallback and re-argue the
  architecture *before* flipping ADR 0142.
- **L18 — username collision.** A principal whose `preferred_username` local part matches a privileged
  on-prem sAMAccountName (`Administrator`) but whose UPN suffix is foreign. Must be refused with
  `username_domain_not_allowed`, **no LDAP lookup, no session**. This cell exists because a review found
  the unchecked-suffix path was a **live privilege-escalation route**, not a theoretical one.
- **L11 — the MFA-claim gate.** Sign in with MFA removed from the claim rule: expect
  `?e=sso_mfa_required` + audit `mfa_claim_missing`. The runbook calls this *the single most important
  cell in the matrix*.

### One measurement trap

**L15 (amplification bound)** must be measured with a **throwaway local listener that counts requests**,
or an engine-side fetch counter — **not** at the security group. VPC Flow Logs are per-ENI and
connection-grained, not HTTP-request-grained, so they cannot answer "≤1 fetch per interval".

---

## Why this window matters beyond the four items

Every serve-path TLS/proxy assertion in the suite today **monkeypatches `uvicorn.run` and checks
kwargs**, and `kerberos_principal` is `# pragma: no cover`. **The entire AD acceptor path is mock-seam
only.** This is its first real validation — and #275 is already a *suspected defect* that L1 exists to
confirm. Expect to find things; that is the point.

## Finish properly (L17)

`messagefoundry verify --report-md --report-json` + `GET /audit/export` for the run window → a short run
record under `docs/testing/`. **Scrub it first** — the raw output carries real usernames, the engine
hostname, and possibly message identifiers. Then demote the forest, remove the AD FS farm, delete any
Entra app registration — **and ask the owner before stopping or terminating any instance.**

Then update the four banners honestly, and release the claim:

```powershell
pwsh -NoProfile -File scripts\coord\claim.ps1 -Release ad-lab-window
```
