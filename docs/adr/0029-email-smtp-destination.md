# ADR 0029 — Email (SMTP-send) outbound destination

- **Status:** Accepted (2026-06-27, built — PR #618)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-27
- **Consumes:** the pre-**Reserved** [docs/adr/README.md](README.md) row for **BACKLOG #23** ("Email/SMTP
  destination — **reserved** (#23); not yet authored"). The number was **earmarked `0024` in the original
  plan** before [ADR 0024](0024-smart-backend-services-token-provider.md) (SMART Backend Services) claimed
  it; `0029` is this ADR's settled number (the coordinator owns the registry — this ADR does **not** edit
  the README row).
- **Related:** BACKLOG #23 · [ADR 0001](0001-staged-pipeline-architecture.md) (staged queue + the
  at-least-once / count-and-log invariants an SMTP send must respect) ·
  [ADR 0022](0022-fhir-resource-codec-rest-client.md) (the **first non-HL7, stdlib-only HTTP destination** —
  the structural template `RestDestination` sets for a new outbound) ·
  [ADR 0024](0024-smart-backend-services-token-provider.md) (the SMART token provider — a **structural**
  template for a future XOAUTH2 credential provider, **not** a drop-in: it mints a *signed JWT*, not an
  OAuth bearer for IMAP/SMTP) · [ADR 0007](0007-gui-manageable-connections-toml.md) (transport-config-as-data
  — the EMAIL connector's settings are hand-/GUI-editable) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability / at-least-once; transforms pure, side effects in transports),
  §4 (pluggable connector registry), §7 (no ad-hoc deps), §9 ([PHI.md](../PHI.md)) ·
  [`transports/base.py`](../../messagefoundry/transports/base.py) `DestinationConnector` / `DeliveryError` /
  `register_destination` / `TestNotSupportedError` ·
  [`transports/rest.py`](../../messagefoundry/transports/rest.py) `RestDestination` (mirror) ·
  [`transports/smart.py`](../../messagefoundry/transports/smart.py) `SmartBackendTokenProvider` (Phase-2
  structural template only) ·
  [`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py) `send_plain_email` (the stdlib
  `smtplib`/`email` logic to lift) ·
  [`config/settings.py`](../../messagefoundry/config/settings.py) `EgressSettings` (the new `allowed_smtp`
  arm) · [`config/models.py`](../../messagefoundry/config/models.py) `ConnectorType` (the new `EMAIL` member) ·
  [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) `check_egress_allowed` /
  `_allowlist_for` (the fail-closed gate the new arm plugs into).

---

## Context

MessageFoundry has no email transport. A common integration ask — "fan a result/alert out as an email to a
clinician or a partner inbox", "deliver a report as an SMTP message" — has no home: a Handler can `Send` to
MLLP, raw TCP, File, REST/SOAP/FHIR, DATABASE, REMOTEFILE, DICOM(web), but not to a mailbox. Mirth and
Corepoint both ship an SMTP sender as a first-class destination; #23 closes that gap.

The engine already contains **working, reviewed, stdlib-only SMTP-send code** — it is just on the *alerting*
side, not the *data plane*. [`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py)
`send_plain_email(...)` builds an `email.message.EmailMessage`, opens `smtplib.SMTP(host, port, timeout=...)`,
**STARTTLS-by-default** (`if use_tls: smtp.starttls()`), optionally `login(...)`, and `send_message(...)`,
with an optional `allowed_hosts` egress allowlist gating the SMTP host. It is **standard library only**
(`smtplib` + `email.message`), matching the "no new dependency" stance the REST/SOAP/FHIR destinations take
([CLAUDE.md](../../CLAUDE.md) §7; [ADR 0022](0022-fhir-resource-codec-rest-client.md)). That is exactly the
minimal mechanism a data-plane EMAIL destination needs — but it lives in `pipeline/`, and a transport **must
not import `pipeline/`** (the one-way dependency rule, [CLAUDE.md](../../CLAUDE.md) §4). So the logic is
**lifted**, not imported.

The shape of a new outbound is already settled by [`transports/rest.py`](../../messagefoundry/transports/rest.py)
`RestDestination`, the first non-HL7 destination: a `DestinationConnector` subclass built from
`config.settings`, validating its config loud at construction (so a misconfiguration fails at
`check`/dry-run/start, not as a wire-time surprise), doing its **blocking** I/O off the event loop via
`asyncio.to_thread` inside `send(...)`, mapping failure onto `DeliveryError` (transient → the staged-queue
retries it), providing a no-data `test_connection`, and `register_destination(...)`-ing itself at import. The
EMAIL destination mirrors that template line-for-line — `smtplib` instead of `urllib`.

A full email *integration* would also want to **read** mail (IMAP/POP) as an inbound source, and modern
hosted mail (Microsoft 365, Google Workspace) has **deprecated SMTP/IMAP basic auth** in favour of
**OAuth2 `XOAUTH2`**. That is a materially larger surface (an inbound poll source on the ADR 0023 ingress
path, plus an OAuth credential provider with its own dependency dep-vet) and is **explicitly deferred** to a
Phase 2 (below). [`transports/smart.py`](../../messagefoundry/transports/smart.py) is named here only as a
**structural** template for that future provider (acquire → cache-with-expiry → inject per delivery, off-loop,
re-mint on a re-run so purity holds) — it is **not** a drop-in: it mints a *signed-JWT client assertion* for
SMART Backend Services, whereas M365/Google XOAUTH2 is a different OAuth flow yielding a different bearer,
fed to SMTP `AUTH XOAUTH2` rather than an HTTP `Authorization` header.

## Decision

**Build a Phase-1 outbound-only EMAIL destination — a `DestinationConnector` that sends one transformed
payload as a plain-text SMTP message — by lifting the minimal stdlib `smtplib`/`email` logic from
`send_plain_email`, mirroring `RestDestination`'s structure, gated by a new fail-closed
`[egress].allowed_smtp` allowlist.** Phase 2 (IMAP/POP read + M365/Google XOAUTH2) is deferred and out of
scope here.

### D1 — A new `ConnectorType.EMAIL` + an `EmailDestination(DestinationConnector)` in `transports/email.py`

Add `EMAIL = "email"` to `ConnectorType` ([config/models.py](../../messagefoundry/config/models.py)) and a new
`transports/email.py` holding `EmailDestination(DestinationConnector)`, registered with
`register_destination(ConnectorType.EMAIL, EmailDestination)` ([transports/base.py](../../messagefoundry/transports/base.py))
exactly as `RestDestination` registers itself — so the pipeline resolves it through the registry and **no
`pipeline/` code special-cases it** ([CLAUDE.md](../../CLAUDE.md) §4).

The connector is built from `config.settings` (already `env()`-resolved by the runner before construction,
like every other destination), validating loud at construction:

| Setting | Type | Default | Notes |
|---|---|---|---|
| `host` | str | — | SMTP server host. Required; a missing/empty value raises `ValueError` at construction (the `RestDestination` "requires a 'url'" pattern). |
| `port` | int | `587` | The STARTTLS submission port. `465` (implicit TLS) is the `SMTP_SSL` variant (§D3). |
| `sender` | str | — | `From:` address. Required. |
| `recipients` | list[str] | — | `To:` addresses. Required, non-empty. |
| `subject` | str | `""` | Static subject. (A per-message subject from the Handler is a follow-up — §"To resolve".) |
| `username` / `password` | str / str | `None` | Optional SMTP `AUTH`. `env()`-resolved secrets; **never** logged. |
| `use_tls` | bool | `true` | **STARTTLS by default** (§D3). |
| `insecure_tls` | bool | `false` | The existing `MEFOR_ALLOW_INSECURE_TLS`-gated dev escape (§D3). |
| `timeout_seconds` | float | `30.0` | Socket timeout. |
| `encoding` | str | `utf-8` | Body encoding (`EmailMessage.set_content`). |

The payload the Handler produced is the **email body**. The connector is content-agnostic about the payload
(an HL7 string, a JSON/XML report, plain text) — it sets it as the message body via
`EmailMessage.set_content(payload)`; rendering the payload into a human-readable report is the Handler's job,
not the transport's (the same division `RestDestination` keeps — the Handler shapes the body, the transport
moves it).

### D2 — `send()` lifts the stdlib `smtplib`/`email` core, off-loop, mapping failure → `DeliveryError`

`async def send(self, payload: str) -> DeliveryResponse | None` runs the blocking SMTP exchange off the event
loop via `asyncio.to_thread` (the `RestDestination.send` → `_post` shape) and returns **`None`** — a one-way
delivery (SMTP submission has no application reply to capture, so there is no `DeliveryResponse`, exactly like
File). The synchronous core is the **lifted** `send_plain_email` body — build an `EmailMessage`
(`Subject`/`From`/`To`/`set_content`), `with smtplib.SMTP(host, port, timeout=...) as smtp:`,
`if use_tls: smtp.starttls()`, optional `smtp.login(...)`, `smtp.send_message(msg)` — **copied into
`transports/email.py`, not imported** from `pipeline/alert_sinks.py` (the one-way dependency rule forbids a
transport importing `pipeline/`; the alert sink keeps its own copy). `smtplib`'s failure modes
(`SMTPException`, `OSError`/`TimeoutError` on connect, an auth failure) are caught and re-raised as
`DeliveryError` (transient) so the **staged-queue retries** it with backoff — the transform stays **pure**
(message in → message out), and the SMTP send is the **side effect** that lives in the transport, retried
at-least-once like every other one-way destination ([CLAUDE.md](../../CLAUDE.md) §2, [ADR 0001](0001-staged-pipeline-architecture.md)).

> **At-least-once / idempotency.** A retry **re-sends** the email, so a transient failure *after* the server
> accepted but *before* the connector saw success can produce a duplicate message — the standard one-way
> at-least-once caveat (identical to REST/MLLP/File: "the receiving endpoint must be idempotent",
> [rest.py](../../messagefoundry/transports/rest.py) module docstring). A mailbox has no idempotency key, so
> this is **documented, accepted** — operators size their alerting/reports accordingly; a rare duplicate
> email is preferable to a dropped one, and dropping would break the count-and-log invariant.

### D3 — STARTTLS by default + the existing `insecure_tls` escape; no credentials over cleartext

`use_tls=True` is the **default**, so the connector issues `STARTTLS` before `AUTH`/data — the same posture
`send_plain_email` already takes (`if use_tls: smtp.starttls()`) and the same TLS-by-default stance every HTTP
destination takes. Disabling TLS (`use_tls=false` / plaintext) is **refused unless** the explicit, project-wide
dev escape `MEFOR_ALLOW_INSECURE_TLS` is set (`insecure_tls_allowed()` /
[config/settings.py](../../messagefoundry/config/settings.py) `INSECURE_TLS_ESCAPE_ENV`), and is **logged
loudly** when allowed — byte-identical to the `verify_tls=false` / `refuse_cleartext_credentials` handling in
`RestDestination`. In particular, **SMTP `AUTH` credentials are never sent over an un-encrypted channel**: a
`username`/`password` with `use_tls=false` and no escape raises at construction (the
`refuse_cleartext_credentials` rule, lifted in spirit). Port `465` (implicit TLS) maps to `smtplib.SMTP_SSL`
in place of `SMTP`+`STARTTLS`; both honour the same escape.

### D4 — A new fail-closed `[egress].allowed_smtp` allowlist arm (deny-by-default aware)

Add `allowed_smtp: list[str] = []` to `EgressSettings` ([config/settings.py](../../messagefoundry/config/settings.py),
beside `allowed_mllp`/`allowed_http`/`allowed_db`/…), wire it into the `_split_list` `field_validator` (so
`MEFOR_EGRESS_ALLOWED_SMTP=host1,host2` works like the siblings), and **arm the gate** in
[pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py):

- `_allowlist_for(ConnectorType.EMAIL, egress)` returns `egress.allowed_smtp` (so `deny_by_default` refuses an
  EMAIL destination with no allowlist, exactly as it does for every other type).
- `check_egress_allowed` grows an `elif dest.type is ConnectorType.EMAIL and egress.allowed_smtp:` branch that
  reads `host` (+ optional `port`) and refuses (raises `WiringError`) a destination whose SMTP host is not on
  the list — the `_mllp_egress_allowed(host, port, egress.allowed_smtp)` host[:port] matching the MLLP/TCP/DB
  branches already use. Empty list = unrestricted (today's opt-in default), checked against the resolved
  (`env()`-substituted) destination at config load/reload/start.

This makes EMAIL a **first-class egress citizen**: an SMTP destination is bounded by the same fail-closed,
opt-in, deny-by-default-aware allowlist as MLLP/HTTP/DB egress, so a fat-fingered or hostile mail host can't
exfiltrate PHI to an arbitrary relay ([PHI.md](../PHI.md); the `EgressSettings` contract). The connector's own
construction-time `host` check (the `allowed_hosts` parameter `send_plain_email` already carries) is the
defense-in-depth inner gate; `[egress].allowed_smtp` is the authoritative config-load gate, consistent with
how the alert SMTP sink keeps its own `[alerts].smtp_allowed_hosts` separate from the data-plane allowlist.

### D5 — `test_connection` = connect + EHLO + NOOP (no message sent)

Override `test_connection` (the `RestDestination._probe` analog, off-loop via `asyncio.to_thread`) to probe
the server **without delivering**: open `smtplib.SMTP(host, port, timeout=...)`, `STARTTLS` if `use_tls`,
optionally `login(...)` so a credential error surfaces, then `EHLO`/`NOOP` and quit. Reachability/auth success
returns; a connect/TLS/auth failure raises `DeliveryError` for `POST /connections/{name}/test`. (It does **not**
fall back to `TestNotSupportedError` — an EMAIL destination is a dial-out with a real resource to probe, like
REST/MLLP, not a listen source.) The probe sends **no** `MAIL FROM`/`DATA`, so no real email is ever sent by
a connection test.

### What this must not break

- **One-way dependency direction** ([CLAUDE.md](../../CLAUDE.md) §4). `transports/email.py` imports only
  stdlib (`smtplib`, `email.message`) + `transports/base.py` + `config/`; it **does not** import `pipeline/`
  (hence the *lift*, not an import, of `send_plain_email`). `pipeline/alert_sinks.py` keeps its own copy
  unchanged — the alert sink and the data-plane transport are deliberately independent.
- **No new dependency** ([CLAUDE.md](../../CLAUDE.md) §7). Pure standard library; `pyproject.toml` /
  `requirements.lock` are untouched.
- **Transforms stay pure; the side effect lives in the transport** ([CLAUDE.md](../../CLAUDE.md) §2). The
  Handler returns a `Send`; the SMTP exchange happens only in `EmailDestination.send`, off-loop, retried by
  the queue — at-least-once like every one-way destination.
- **Fail-closed egress is preserved, not regressed.** EMAIL plugs into the existing `EgressSettings` /
  `check_egress_allowed` / `_allowlist_for` machinery; it does not invent a parallel gate, and
  `deny_by_default` covers it automatically once `_allowlist_for` knows the type.
- **PHI safety** ([PHI.md](../PHI.md)). The email body is PHI (it is the message); it goes only on the wire to
  the allowlisted server, **never** to a log. Errors name the redacted host + SMTP failure class only — never
  the body, the recipients' PHI, or the `password`.

## Phase 2 — IMAP/POP inbound read + M365/Google XOAUTH2 (DEFERRED, out of scope)

Recorded here so the boundary is explicit; **nothing below is built in this slice.**

- **An inbound EMAIL *source*** (poll IMAP/POP, hand each message to the ingress path) needs the
  payload-agnostic inbound-poll machinery and is a **poll source** (`polls_shared_resource = True`,
  leader-gated like the DATABASE/REMOTEFILE poll sources) — and, for a request/response-free protocol, an
  ingress decode path. It rides whatever the ADR 0023 inbound-listener / ingress work settles, not this ADR.
- **XOAUTH2 for Microsoft 365 / Google Workspace.** Both have deprecated SMTP/IMAP *basic* auth; production
  use needs OAuth2 `XOAUTH2`. A future credential provider would follow `smart.py`'s **structural** shape
  (acquire → cache-with-expiry → inject per delivery off-loop, re-mint on a re-run so purity holds) but is a
  **different flow** (an OAuth bearer fed to SMTP/IMAP `AUTH XOAUTH2`, not a signed-JWT client assertion in an
  HTTP header) and would require its **own dependency dep-vet** (an OAuth/MSAL library, or a hand-rolled
  stdlib flow) — **explicitly out of scope here**, to be decided in its own ADR. Phase 1 ships username/
  password `AUTH` (over STARTTLS), which works against self-hosted/relay SMTP and any server still permitting
  basic auth.

## Consequences

**Positive** — Closes the Mirth/Corepoint email-destination gap (#23) with a small, additive,
**stdlib-only** connector that reuses already-reviewed SMTP logic and mirrors `RestDestination` line-for-line,
so there is one outbound mental model. EMAIL is a first-class egress citizen (the same fail-closed
`[egress].allowed_smtp` / `deny_by_default` gate as MLLP/HTTP/DB), TLS-by-default with the project-wide dev
escape, and queue-retried at-least-once. Zero change to existing connectors; `pyproject.toml` /
`requirements.lock` untouched.

**Negative / risks** — At-least-once means a retry can **duplicate** an email (no idempotency key on a
mailbox) — documented and accepted, the standard one-way caveat. A second copy of the `smtplib`/`email` core
now exists (`transports/email.py` lifted from `pipeline/alert_sinks.py`'s `send_plain_email`); the duplication
is **deliberate** (the one-way dependency rule forbids the transport importing `pipeline/`), and the two are
small and independently testable — but a future SMTP-protocol fix must touch both (a known, accepted
two-site coupling, like the alert-event lockstep set elsewhere). The new `allowed_smtp` arm must be wired into
`_split_list`, `_allowlist_for`, and `check_egress_allowed` together, or `deny_by_default` would fail-open for
EMAIL — pinned by the egress-parity tests.

**Out of scope / deferred** — IMAP/POP inbound read, M365/Google XOAUTH2, and the OAuth dependency dep-vet
(all Phase 2, their own ADR). HTML/multipart bodies and attachments (Phase 1 is plain-text `set_content`);
a per-message subject/recipients from the Handler (static config in Phase 1 — see below).

## Options considered

1. **Lift `send_plain_email` into a new `EmailDestination`, mirror `RestDestination`, gate via a new
   `[egress].allowed_smtp` arm — CHOSEN.** Smallest additive surface; reuses reviewed stdlib SMTP logic;
   one outbound mental model; first-class fail-closed egress. Matches #23's scope.
2. **Import `send_plain_email` from `pipeline/alert_sinks.py` into the transport.** Rejected: a transport
   importing `pipeline/` violates the one-way dependency rule ([CLAUDE.md](../../CLAUDE.md) §4) — the lift is
   the price of that boundary.
3. **Move the shared SMTP core down into `transports/` (or a neutral util) and have *both* the alert sink and
   the new destination import it.** Rejected **for this slice** (a larger refactor touching the reviewed alert
   path); a de-duplication follow-up could relocate the core to `transports/email.py` and have the alert sink
   import *up* into a transport util — left as a possible later cleanup, noted in "To resolve".
4. **Add EMAIL but skip the egress allowlist (rely only on the connector's own `host` check).** Rejected:
   leaves SMTP fail-open under `deny_by_default` and inconsistent with every other PHI-bearing egress; the
   `[egress]` gate is the authoritative one.
5. **Build IMAP/POP + XOAUTH2 now (full email integration).** Rejected for this slice: materially larger
   (an inbound poll source on the ADR 0023 path + an OAuth dependency dep-vet) — Phase 2, its own ADR.

## To resolve on acceptance

- [ ] **`465` implicit TLS vs `587` STARTTLS.** Confirm Phase 1 supports both (`SMTP_SSL` for `465`, default
  `587`+`STARTTLS`) and that `use_tls=false` + the `insecure_tls` escape are the only plaintext path.
- [ ] **Static vs per-message subject/recipients.** Phase 1 takes them from config; confirm whether a Handler
  may override `subject`/`recipients` per message (via the `Send` payload or a small structured payload
  contract) or whether that is a follow-up.
- [ ] **Plain-text only vs multipart/attachments.** Confirm Phase 1 is plain-text `set_content` only
  (HTML/multipart/attachments deferred), and whether the ADR 0028 base64 carriage is in scope for an
  attachment later.
- [ ] **De-duplication of the SMTP core (Option 3).** Decide whether to relocate the shared `smtplib`/`email`
  logic to `transports/email.py` and have the alert sink import *up* into it (a transport util the engine may
  import), or keep the two copies — and pin the decision so the two-site coupling is intentional.
- [ ] **`allowed_smtp` host[:port] semantics.** Confirm the SMTP egress entry matches on `host` (any port) or
  `host:port`, consistent with `allowed_mllp`/`allowed_tcp`, and that it is checked against the resolved
  (`env()`-substituted) `host`.
- [ ] **`test_connection` auth probe.** Confirm the probe should `login(...)` (surfacing a bad credential) vs
  EHLO/NOOP only (reachability without auth), and that it sends no `MAIL FROM`/`DATA`.
