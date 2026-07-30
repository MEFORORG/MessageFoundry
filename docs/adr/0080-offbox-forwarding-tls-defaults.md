# ADR 0080 — Native TLS-syslog, default-on-when-configured, and a startup time-sync gate

**Status:** Accepted (2026-07-10)
**Deciders:** security working group
**Related:** sec-offbox-log (PR #357/#361/#363 — the syslog/SIEM forwarder + cross-backend `audit_log` off-box tee); [`docs/SECURITY.md`](../SECURITY.md) (Audit → Off-box forwarding), `docs/security/ASVS-L3-ASSESSMENT.md` (16.4.3 / 16.2.4 / **16.2.2**), [`docs/PHI.md`](../PHI.md) §7; ADR 0002 (API TLS exposure gate — the posture template)

---

## Context

Off-box log + audit forwarding already ships (`configure_logging()` installs an optional syslog/SIEM
forwarder, `emit_audit_tee()` tees every `audit_log` row through the same logger). The ASVS L3
assessment scored **16.4.3** (logs securely transmitted to a separate system) *Pass* on a built-
capability / deployment-delegated basis, but flagged three residuals for a follow-on:

1. **Plaintext transport.** `SyslogProtocol` was only `udp`/`tcp`; there is **zero `ssl`** in
   `logging_setup.py`. Securing the hop meant terminating TLS at a *local* forwarding agent (rsyslog/
   syslog-ng/Vector) or trusting a management network. That is a real deployment burden and an easy
   thing to skip.
2. **Opt-in default-off.** `forward_enabled` defaulted to `False`, so an operator who configured a
   collector (`forward_host`) but forgot the `forward_enabled = true` line got **no** off-box
   evidence — the exact failure mode off-box shipping exists to prevent, silently.
3. **No clock-sync assurance.** Cross-host log/audit correlation (ASVS **16.2.2**) assumes the engine
   host's clock is synchronized. Timestamps are emitted in UTC `Z`, but nothing checks the clock
   actually tracks a reference; a drifted host silently produces mis-correlated evidence.

This ADR ratifies the three deltas that close those residuals, each **secure-by-default with a
documented opt-out** (the owner's standing ruling).

## Decisions

### 1. Native `ssl`-wrapped TCP syslog (RFC 5425), not a delegated local agent

Add `protocol = "tls"`. A `tls` forwarder builds a TCP `SysLogHandler` whose connected socket is
wrapped with an `ssl.SSLContext` (`_TlsSysLogHandler` / `_build_tls_context` in
[`logging_setup.py`](../../messagefoundry/logging_setup.py)). This is chosen **over** delegating to a
local TLS agent because:

- It removes a mandatory external moving part from the secure path — an out-of-the-box `protocol =
  "tls"` ships log evidence encrypted with **no** sidecar to install, configure, or keep patched.
- The engine already terminates in-process TLS for its own API (ADR 0002 / WP-13a), so an in-process
  `ssl` context on an outbound socket is a known, reviewed pattern, not a new capability.
- Delegation stays available: an operator who *prefers* rsyslog/Vector still points `protocol = "tcp"`
  (or `udp`) at `127.0.0.1` and lets the agent add TLS. Native TLS is an **addition**, not a
  replacement — `udp`/`tcp` configs are byte-for-byte unchanged.

**Trust anchoring (secure-by-default).** `create_default_context(cafile=forward_tls_ca_file)` is used;
when a CA file is given, **only** that anchor is trusted (system roots are *not* loaded). An on-prem
SIEM almost always presents a private-CA / self-signed cert, and silently falling back to the public
CA bundle would let *any* publicly-trusted certificate impersonate the collector. So the validator
**requires `forward_tls_ca_file` when `protocol = "tls"` and verification is on**, with
`forward_tls_verify` (default **True**, hostname-checked) as the documented insecure opt-out
(`forward_tls_verify = false` → `CERT_NONE`, no CA file needed — for a lab / pinned-network only).
Optional mutual TLS via `forward_tls_client_cert` (a PEM cert+key chain).

**Availability posture preserved.** The `_FORWARD_TCP_TIMEOUT` (5 s) socket bound is set on the raw
socket *before* the handshake, so a collector that completes TCP but stalls the TLS handshake cannot
block the event-loop thread the engine logs from. A collector that is unreachable **or** presents an
un-verifiable certificate **at startup** raises `OSError` (`ssl.SSLError ⊂ OSError`) and is skipped
with a loud stdout warning — the engine starts without the forwarder, identical to the existing TCP
best-effort behavior. This deliberately favors **engine availability over guaranteed forwarding**
(the warning is the signal); a hard "refuse to start if the SIEM cert is bad" posture was rejected as
letting the SIEM become a single point of failure for intake.

### 2. Default-on when a collector is configured

`forward_enabled` becomes `bool | None` (default `None`). The model validator derives an unset value
from presence of a collector: `None ⇒ (forward_host is not None)`. So:

- **Set `forward_host`** → forwarding is **ON** by default (the common intent: "I pointed at a SIEM,
  ship there"). Best-practice-by-default.
- **`forward_enabled = false`** → explicit opt-out, honored even with a host set.
- **No `forward_host`** → forwarding **OFF**, and `configure_logging` installs only the stdout handler
  — **byte-identical to the pre-0080 default path** (the overwhelmingly common deployment).

A literal `forward_enabled = True` default is impossible: the pre-existing `forward_enabled ⇒
forward_host` rule (kept) would then make an unconfigured engine fail to start. The `None`-derivation
is the minimal change that flips the default *only* once a collector is named.

### 3. Startup time-sync gate — opt-in warn, opt-in fail-closed (ASVS 16.2.2)

Add `require_time_sync` (default **False**), `ntp_peer` (host, default `None`),
`time_sync_max_skew_seconds` (default 2.0), and `time_sync_fail_closed` (default **False**). Before
listeners start, `serve()` runs a small, fully-bounded SNTP probe (`query_sntp_offset`, stdlib UDP,
no new dependency, ~2 s timeout) against `ntp_peer` and compares |offset| to the threshold:

- Default (nothing configured) → **NO-OP**, byte-identical startup.
- `require_time_sync` + `ntp_peer` → **WARN loudly** on skew or on an unreachable peer; the engine
  still starts.
- `+ time_sync_fail_closed` → **REFUSE to start** (exit 2) on skew or on an unreachable peer.

**Why opt-in rather than default-on (the flag).** A blocking clock check has *nothing to compare
against* unless the operator supplies a reference peer — the engine cannot verify synchronization on
its own, and reaching out to a default public NTP server from a PHI host at every startup is an
unwanted, environment-inappropriate network egress. So the assurance is **operator-armed**: opt-in to
check, a further opt-in to fail-closed. This mirrors the "secure-by-default *where the engine can
enforce it*, delegated where it cannot" line already drawn for TLS termination (ADR 0002) and the
`audit_log` WORM residual.

## Opt-outs (summary)

| Control | Best-practice default | Opt-out |
|---|---|---|
| TLS transport | `protocol = "tls"` encrypts + verifies (CA-anchored, hostname-checked) | keep `protocol = "tcp"`/`"udp"`; or `forward_tls_verify = false` (unverified, insecure) |
| Default-on forwarding | setting `forward_host` turns forwarding ON | `forward_enabled = false` |
| Time-sync gate | none (opt-in) | leave `require_time_sync` unset (default); fail-closed is a further opt-in |

## Consequences

- **Positive:** a one-line `protocol = "tls"` + CA file gives an encrypted, authenticated off-box hop
  with no sidecar; operators who configure a SIEM get evidence off-box without a second flag; clock
  drift becomes detectable (and optionally start-blocking) for regulated deployments.
- **Negative / risk:** native TLS is a *synchronous* wrapped send from the event-loop thread (same as
  the existing TCP forward) — for a high-volume feed a local agent (`protocol = "tcp"` → loopback
  agent) remains the throughput-friendly choice; documented. A misconfigured SIEM cert degrades to
  "no forwarding + loud warning", which an operator must watch for (availability-over-forwarding, by
  design). The SNTP probe is unauthenticated (SNTP, not NTS) — adequate for a coarse drift check on a
  trusted management network, not a spoofing-resistant time source; noted as a residual.
- **Scope:** touches only the `[logging]` section, `logging_setup.py`, `__main__.py`, and docs. The
  `audit_log` off-box tee (`store/audit_tee.py`) inherits the TLS transport automatically — it ships
  through the same `messagefoundry.audit` logger / root handler, so no change there.

## Alternatives considered

| Alternative | Verdict | Why |
|---|---|---|
| Native `ssl`-wrapped TCP syslog (RFC 5425) | **Chosen** | Encrypted hop with no external agent; reuses the in-process-TLS pattern; delegation still available |
| Delegate TLS to a local rsyslog/Vector agent (status quo) | **Kept as an option, not the default** | Adds a mandatory sidecar to the secure path; fine for high-volume but shouldn't be the only way to encrypt |
| Trust system CA bundle for the collector | **Rejected** | Any public-CA cert could impersonate an on-prem SIEM; require an explicit CA anchor |
| Literal `forward_enabled = True` default | **Rejected** | Would make an unconfigured engine fail the `forward_enabled ⇒ forward_host` rule at startup |
| Default-on time-sync check against a public NTP pool | **Rejected** | Unwanted egress from a PHI host; the engine can't verify sync without an operator-chosen reference |
| Fail-closed time-sync by default | **Rejected** | A missing/unreachable peer would block intake; make it a deliberate further opt-in |

## References

- [`messagefoundry/logging_setup.py`](../../messagefoundry/logging_setup.py) — `SyslogForward`,
  `_build_syslog_handler` (udp/tcp/**tls**), `_TlsSysLogHandler`, `_build_tls_context`,
  `query_sntp_offset`.
- [`messagefoundry/config/settings.py`](../../messagefoundry/config/settings.py) —
  `SyslogProtocol.TLS`, `LoggingSettings` (`forward_enabled: bool | None`, `forward_tls_*`,
  `require_time_sync` / `ntp_peer` / `time_sync_*`), validators.
- [`messagefoundry/__main__.py`](../../messagefoundry/__main__.py) — `serve()` forwarder wiring +
  the startup time-sync gate.
- `docs/security/ASVS-L3-ASSESSMENT.md` — 16.4.3 / 16.2.4 /
  16.2.2 rows updated.

## Amendment (2026-07-17) — TLS forwarding instructed at exposure (ASVS 16.4.3, ADR 0115 / WP #243)

**Status:** Doc-only — no default changed. Off-box forwarding stays **off until a collector is
named** (`forward_host = None`), and when named the secure transport (`forward_protocol = "tls"`,
CA-anchored) stays an explicit operator choice over the plaintext `udp` default. This records the ADR
0115 treatment of 16.4.3: a global `forward_enabled` flip would fail an unconfigured engine (the
`forward_enabled ⇒ forward_host` rule), so 16.4.3 is **instructed, not flipped**.

`docs/security/OFF-LOOPBACK-DEPLOYMENT.md` §"Off-box
log/audit forwarding to your SIEM" now instructs setting `forward_host`, `forward_protocol = "tls"`
(explicitly not the plaintext UDP default), `forward_port`, and the required `forward_tls_ca_file`
(plus optional `forward_tls_client_cert` for mutual TLS). The secure-default machinery shipped in
this ADR (native RFC 5425 TLS, default-on-when-configured, CA-anchored verification) is unchanged;
WP #243 only adds the runbook instruction. ADR 0115 does not re-score.

## Amendment (2026-07-22) — the forwarding hop joins the #200 posture gradient

**Status:** Behaviour change — the plaintext default is now an *acknowledged* escape, not a silent one.

The 2026-07-17 amendment above left 16.4.3 "instructed, not flipped": the runbook told operators to
choose `forward_protocol = "tls"`, but nothing **enforced** it, and `udp` remained the default. That
made the forwarder the one PHI-adjacent egress path in the engine with **no posture gate at all** —
every transport-level cleartext hop had been brought under `insecure_hop_disposition` by #200 (ADR
0092), while a `[logging].forward_host` pointed at an off-box collector shipped the log + `audit_log`
evidence stream (PHI-**redacted**, but carrying usernames, connection names, message ids, client
addresses, and the tamper-evident audit chain) over cleartext UDP with only the operator's diligence in
the way.

`serve` now decides the forwarding hop through the **same** shared authority the transports consume
(`settings.forward_hop_disposition` → `tls_policy.insecure_hop_disposition`), **before**
`configure_logging` installs the handler, so a refused hop never emits a record. A hop counts as secure
only when it is TLS **with verification on**; plaintext `udp`/`tcp` and the `forward_tls_verify = false`
opt-out both go to the gradient — loopback ALLOW, attested ALLOW, synthetic ALLOW, non-enforcing PHI
WARN, enforcing PHI REFUSE.

**No new escape mechanism was invented.** The opt-out is the existing per-hop attestation shape, named
for its section: `[logging].forward_hop_attested` (+ `forward_hop_attested_reason`), validated by the
same shared rule as a connection's `tls_hop_attested`. The chosen-in-this-ADR delegation path is
explicitly preserved — a `udp`/`tcp` forward to `127.0.0.1` fronted by a local rsyslog/Vector agent is a
loopback hop and is never gated, so the throughput-friendly deployment is byte-identical.

**What this can break, and the migration.** An existing *enforcing PHI* instance forwarding plaintext to
an off-box collector will now refuse to start. That is the bug being fixed — it is exactly the cleartext
egress this ADR's decision 1 built native TLS to avoid — and the refusal names all three remedies:
`forward_protocol = "tls"` (+ `forward_tls_ca_file`), a loopback local agent, or the attestation. A
non-PHI / non-enforcing instance, a loopback collector, and an engine with no `forward_host` are all
unchanged. The availability posture of decision 1 is untouched: this gate decides *config*, and a
collector that is merely unreachable still degrades to "no forwarding + loud warning".
