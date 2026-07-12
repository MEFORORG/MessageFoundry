# ADR 0080 — Native TLS-syslog, default-on-when-configured, and a startup time-sync gate

**Status:** Accepted (2026-07-10)
**Deciders:** security working group
**Related:** sec-offbox-log (PR #357/#361/#363 — the syslog/SIEM forwarder + cross-backend `audit_log` off-box tee); [`docs/SECURITY.md`](../SECURITY.md) (Audit → Off-box forwarding), [`docs/security/ASVS-L3-ASSESSMENT.md`](../security/ASVS-L3-ASSESSMENT.md) (16.4.3 / 16.2.4 / **16.2.2**), [`docs/PHI.md`](../PHI.md) §7; ADR 0002 (API TLS exposure gate — the posture template)

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
- [`docs/security/ASVS-L3-ASSESSMENT.md`](../security/ASVS-L3-ASSESSMENT.md) — 16.4.3 / 16.2.4 /
  16.2.2 rows updated.
