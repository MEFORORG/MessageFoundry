# ADR 0154 — Synchronous captured-downstream-reply and intake authentication for the inbound HTTP listener (the ADR 0023 deferred tail)

- **Status:** **Accepted (2026-07-31) — owner-ratified at revision 5. Authorises INCREMENT A ONLY; increment A is BUILT and merged (2026-08-01, `f2ef0ea9`). Increment B remains unauthorised.**  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-07-30 (rev 1–4), 2026-07-31 (rev 5, ratified)
- **⚠️ What acceptance does and does not authorise.** "Accepted" normally means *build may start*. Here it
  is **scoped**, because rev 4 split the build and that split is part of what was ratified:
  - **Increment A — `intake_auth` + the D7 peer-control gate (D6, D7), plus the three incidental listener
    defects — is AUTHORISED and may start now.** It closes a live hole: `check_http_tls_exposure` returns
    early on truthy `tls`, so an off-loopback `Http(tls=True)` listener binds a PHI intake socket with no
    peer identity requirement, and `tests/test_exposed_with_tls_passes` currently pins that as passing.
    Acceptance criteria: **AC-11 … AC-16, AC-19**, plus **AC-17**.
  - **Increment B — the synchronous captured-downstream reply (D1–D5, D8) — is NOT authorised yet.** It
    remains deferred until a customer exists whose partner semantics can shape it. It carries roughly 70 %
    of this document's complexity and effectively all of its concurrency risk, and there is no one to
    serve. Do **not** read this Accepted status as a green light for `reply_from`. Acceptance criteria
    **AC-1 … AC-10 and AC-18** are specified but dormant.

  Building increment B requires a further owner decision, not merely a reading of this line. The design is
  ratified; the *schedule* is deliberately partial.
- **Revision 5 — every open item resolved, on one principle.** The owner confirmed there are **no deployed
  instances of MessageFoundry**: no production installs, no installed base, nobody to upgrade. That single
  fact settles the six remaining `To resolve on acceptance` items, because every one was a trade between
  *the clean answer* and *not disturbing existing users* — and the second half of that trade does not
  exist. The resolutions therefore all run the same way: **take the strict, clean option now, because this
  is the cheapest it will ever be.**
  - The peer-control gate **refuses** rather than warns (D7). A bare `tls`+`tls_ca_file` — "any cert this
    CA ever signed", no subject binding — is an ineffective control and is treated as none. Rev 3 softened
    this to a warning to avoid an "upgrade cliff"; there is no upgrade path, so that reasoning is
    withdrawn. It also removes an internal inconsistency, since AC-16 always specified refusal.
  - The `source_ip_allowlist` floor stays `/8` IPv4 and `/32` IPv6 — now justified on its merits
    (`10.0.0.0/8` is a legitimate private scope; `0.0.0.0/0` is not) rather than on compatibility.
  - All three additive methods are adopted — `reply_wait_state`, `record_message_event`,
    `SlidingWindowRateLimiter.would_allow`. Each exists because a shipped primitive genuinely cannot serve
    the need, and with no installed base a new store or limiter method disturbs nothing.
  - A message with **two rows naming `reply_from` is refused** at check time rather than resolved by
    "highest `response_seq` wins".
  - The `gzip, chunked` framing gap is **filed separately as engine issue #98**, so a real defect is not
    gated behind an ADR still in Proposed.

  **The general lesson, recorded because it caused real errors in this document's own drafting:** this
  engine *looks* mature — 0.3.x on PyPI, a large ADR corpus, a capacity certification, HA design, an
  ASVS L3 self-assessment — and that appearance repeatedly induced reasoning about an installed base that
  does not exist: a "forcing customer migration" in rev 1–3, an "upgrade cliff" in rev 3. Neither was real.
  **Until there are deployments, backward compatibility is not a constraint and must not be argued as
  one.** Every lab figure is likewise lab-measured, never field-observed.
- **Revision 4 — priority correction, no design change.** The owner confirmed on 2026-07-30 that **there
  is no committed customer and no migration date**. Revisions 1–3 described the proxy-API shape as "the
  forcing case … a real migration" whose two halves were both "not optional for that feed" — language that
  read as a commitment and would have misled a later reader into treating a prospect's shape as a
  deadline. That framing is corrected in Context, and a new **Increments** section splits the *build* (not
  the ADR) so the live security defect in D6/D7 ships now rather than waiting on a speculative feature
  that carries the document's entire concurrency risk. The acceptance criteria already fell along that
  seam, so nothing was renumbered and no decision changed. This also settles open item 1: with nobody to
  disappoint, increment 1 is acceptable without `capture_error_responses`, which becomes an ordinary
  roadmap item rather than a release gate.
- **Revision 3 — what changed and why.** Revision 2 was itself audited (8 agents, four hostile lenses,
  each followed by a refutation pass). Its factual base held up well — 31 claims confirmed correct, and
  the adversarial stage **refuted** the audit's own headline finding (two auditors claimed the new
  transform-side `rendezvous.fail` re-created the multi-handler defect; it does not, because this ADR
  states in four places that every in-process signal is a *latency hint*, never an authoritative
  turn-ender). Eight real problems survived, and revision 3 fixes them:
  1. **D3's terminal set omitted `PROCESSED`** — the single most likely misconfiguration (a Router that
     simply does not route to `reply_from`) still burned the full `reply_timeout`. Terminality is now
     defined **by exclusion** (`not in (RECEIVED, ROUTED)`) so the table is total by construction.
  2. **D3 never inspected the captured row's `outcome`**, so two of D5's nine outcomes (`empty`,
     `rejected`) were unreachable by the only decision procedure the ADR specifies.
  3. **The mandatory global rate-limit arm re-created the exact defect revision 2 diagnosed** — one
     attacker could `429` the authenticated partner pre-ingress and uncounted. It is now consulted only
     for peers with no successful authentication in the window.
  4. **D4's escalated FIFO / `max_attempts` refusals could not fire**: they read declared fields that
     default to `None` (inherit), not the resolved `[delivery]` values.
  5. **The `422` rationale was backwards** — the shipped path *does* persist an `ERROR` message, so it is
     a post-record refusal, not a pre-ingress one. Count-and-log holds because the row exists.
  6. **D8 had no acceptance criterion at all**; AC-18 and AC-19 added, AC-7 extended to the intake-auth
     and `ack_after` refusals.
  7. Five factual errors introduced by revision 2 corrected (`403` is already mapped; five
     `_LOOPBACK_HOSTS` copies across **two** contents, not three; **eighteen** existing alert event
     types, not fourteen; `_strip_header_control_chars` strips rather than rejects and cannot satisfy
     AC-9; `safe_text` *partially* redacts JSON rather than leaving it untouched).
  8. A stale-premise sweep of ADR 0023, which still described the `connection_event` log as
     OFF-by-default in six places — the very premise this change corrected in ADR 0021.
- **Revision 2 — what changed and why.** Revision 1 was validated against the tree by a 17-agent
  fact-check (195 claims: 160 supported, 19 partial, 15 contradicted, 1 not-found) plus three
  adversarial design lenses. The factual base held — **all four alleged live defects are real**, and
  defect 1 was reproduced by *executing* `_status_line`/`build_response`. The **design did not**: six
  fatal defects were found, two of them independently by two lenses. None of them appeared in
  revision 1's own `To resolve on acceptance` list. Revision 2 repairs all six, rewrites four
  rationales that rested on false premises, corrects nine miscounts and mis-citations, and answers
  all thirteen of revision 1's open questions inline. The load-bearing changes:
  1. **D3's `rows exist, none for reply_from → fail immediately` is deleted.** It returned a wrong
     `502` for any multi-handler message — a degradation to *wrong*, which falsified this ADR's
     central claim. Replaced with a message-status terminality test.
  2. **The routing early-fail is split across two stages.** The router worker emits only
     `ROUTED`/`UNROUTED`; `FILTERED`/`NOT_DEPLOYED` are decided a stage later by the store finalizer,
     so AC-4 was unimplementable where revision 1 put the hook.
  3. **The peer-EOF race is gated.** It fired deterministically for a `Content-Length`-less POST — a
     shipped, supported request shape — aborting 100 % of those turns.
  4. **The rate limiter gains a read-only `would_allow`.** As specified it capped the intake socket at
     10 *requests*/min/peer and dropped the 11th authenticated message pre-ingress, uncounted.
  5. **`constant_time_match` gains an empty-credential precondition.** Without it,
     `sha256(b"") == sha256(b"")` authenticated a request presenting *no credential at all*.
  6. **Auth moves ahead of the body read.** Revision 1 placed it after `_read_request`, which reads
     the body — letting an anonymous peer command 256 × 16 MiB ≈ 4 GiB of heap before a credential
     byte was examined.
- **Related:** [ADR 0023 §D3/§D4.3](0023-inbound-http-listener.md) (**the parent** — this consumes its two
  named deferrals, "block-on-captured-downstream-reply (the SOAP-envelope seam)" and "Authentication on the
  intake socket", and closes two of its **eight** `To resolve on acceptance` items; the `202`
  respond-with-receipt first slice built in 0.2.10 is untouched) ·
  [ADR 0013 §"capture + correlate" / Increment 1](0013-query-response-orchestration.md) (the **only**
  mechanism this reply may read — the immutable `response` artifact written by `complete_with_response`;
  **explicitly not** [Increment 2 re-ingress](0013-increment-2-reingress-design.md), which *is* built and
  stays untouched) · [ADR 0016](0016-synchronous-x12-request-response.md) (the **prior art** and the
  outbound twin — "'synchronous on one socket' is a *transport implementation detail*, never a new staged-queue
  shape"; its `## What is explicitly OUT of scope` excluded the inbound listener, which is precisely this ADR) ·
  [ADR 0021](0021-inbound-ack-nak-capture-response-sent.md) (the `kind` discriminator sharing the `response`
  table under the `\x1fack:` sentinel this reply must filter out. **Note: its document says the per-inbound
  `connection_event` log is OFF-by-default; the shipped default is ON** — see D6 and the open items) ·
  [ADR 0004 §2/§4/§6](0004-payload-agnostic-ingress.md) (payload-agnostic ingress; §6's "a non-HL7 *source*
  **owns its own receive-time response** … that **lives in the source connector**" is why the HTTP status is
  decided in `transports/`, not `pipeline/`) ·
  [ADR 0002 §0](0002-phase2-transport-security-and-strong-auth.md) (the off-loopback exposed gate + per-listener
  TLS — **confidentiality**, orthogonal to the **authentication** gate added here) ·
  [ADR 0003 §1/§3/§4](0003-non-hl7-transports-database-rest-soap.md) (secrets from `env()`/`MEFOR_*` only;
  the connector-owned-listener constraint; stdlib-first HTTP) ·
  [ADR 0001](0001-staged-pipeline-architecture.md) (ACK-on-receipt, at-least-once, the staged handoff) ·
  [ADR 0031](0031-startup-connection-fault-isolation.md) (a refused/misconfigured inbound degrades one
  connection) · [ADR 0037](0037-multi-process-sharding-l3.md) + [ADR 0073](0073-ownership-scoped-recovery-single-consumer-lanes.md)
  (engine shards partition by **inbound connection**, but outbound lane ownership is rendezvous-hashed —
  the reason the committed row, not an in-process signal, is authoritative) ·
  [ADR 0066](0066-pooled-stage-claimers.md) (`claim_mode="pooled"` is the **default**, so the notify hook must
  live on the shared per-item path) · [ADR 0083](0083-mtls-client-certificate-identity.md) (the cert→principal
  mapping this hoists to a neutral leaf; its uvicorn-peercert blocker was **since solved by a shipped shim**, so
  it is historical context, not a live constraint) · [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) +
  [ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) +
  [ADR 0153](0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md) (the `HopPosture`
  keying the new auth gate, and the "loopback starts byte-identical" discipline) ·
  [ADR 0150](0150-client-address-on-audit-entries.md) (`record_audit(client=…)` — this is its first
  engine-internal writer) · [ADR 0057](0057-inline-step-a-fast-path.md) (⛔ DO NOT PROMOTE — explicitly *not*
  the mechanism here) · [ADR 0132](0132-per-endpoint-alternate-windows-credential-for-file-unc-shares-win32-ctypes-no-pywin32-no-impersonation-privilege.md)
  (`File(credential_password=…)` — the `env()`-only-at-the-factory precedent copied verbatim in shape) ·
  BACKLOG #7 (inbound web-service listener — this closes "SOAP sync-reply" and "intake-auth" from its deferred
  tail; "routing-metadata" and the #20/#24 facades stay open) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (ACK-on-receipt + count-and-log + at-least-once), **§4** (pluggable connector
  registry; the one-way `transports/ ↛ api/` dependency rule — **§4 only; revision 1 mis-cited this as §2/§4**),
  §8 (payload-agnostic ingress; `ack_after=delivered` planned-not-built), §9 (PHI never logged at INFO+),
  §12 (no FastAPI inside the engine packages) ·
  [`transports/http_listener.py`](../../messagefoundry/transports/http_listener.py)
  `HttpSource`/`_on_client`/`_serve_one`/`_read_request`/`build_response`/`_status_line`/`_respond`/`HttpReceiptHandler` ·
  [`transports/base.py`](../../messagefoundry/transports/base.py) `SourceConnector`
  (`on_connection_event`/`content_type`/`processed_ledger` — the runtime-injection precedent)/`InboundHandler`/
  `DeliveryResponse`/`RESPONSE_OUTCOMES`/`peer_ip_allowed` ·
  [`transports/mllp.py`](../../messagefoundry/transports/mllp.py) `_mllp_ssl_context(server=True)`
  (already `CERT_REQUIRED` when `tls_ca_file` is set)/`_set_tcp_nodelay` ·
  [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)
  `_start_inbound_unsafe`/`_make_http_handler`/`_handle_inbound_http`/`_process_delivery_item`/
  `_router_worker`/`_transform_worker`/`_make_connection_event_sink`/`check_http_tls_exposure`/
  `_inbound_insecure_bind_permitted`/`_wake_lane` ·
  [`store/base.py`](../../messagefoundry/store/base.py) `enqueue_ingress`/`complete_with_response`/
  `correlate_response`/`outbox_for`/`route_handoff`/`transform_handoff`/`record_connection_event`/`record_audit` ·
  [`store/store.py`](../../messagefoundry/store/store.py) `_maybe_finalize_message` (the sole authority for
  `FILTERED`/`NOT_DEPLOYED`) · [`config/wiring.py`](../../messagefoundry/config/wiring.py)
  `Http()`/`inbound()`/`_SECRET_SETTING_KEYS`/`resolve_env_settings`/`EnvRef` ·
  [`auth/ratelimit.py`](../../messagefoundry/auth/ratelimit.py) `SlidingWindowRateLimiter` ·
  [`netaddr.py`](../../messagefoundry/netaddr.py) (the neutral-package-root leaf precedent this ADR reuses) ·
  [`docs/CONNECTIONS.md`](../CONNECTIONS.md) (`REST-IN`/`SOAP-IN` rows + the "†" deferral paragraph this
  retires)

---

## Context

ADR 0023 built a connector-owned inbound HTTP/1.1 listen source
([`transports/http_listener.py`](../../messagefoundry/transports/http_listener.py), `HttpSource`,
`ConnectorType.HTTP`, shipped 0.2.10) and deliberately built **only** the cheap half of the response
question: the body is committed to payload-agnostic ingress and a `202 Accepted` carrying the engine
`message_id` goes back the instant the commit lands — MLLP's AA-on-receipt, in HTTP clothes. Its own
module docstring says so: *"Only the cheap, correct `202`-respond-with-receipt path is built."*

It named two things it would not build, and this ADR is both of them.

**(a) The synchronous captured-downstream reply.** ADR 0023 §D3, verbatim:

> "A SOAP web service (and some synchronous FHIR operations) must return the **downstream partner's actual
> reply** in the HTTP response body, not a receipt — request → route → call an outbound → return *its* answer.
> That is precisely the **ADR 0013 Increment 1 capture seam** … correlating the inbound `message_id` to the
> captured `response` row and blocking the HTTP request until the reply is captured (bounded by a per-inbound
> timeout → `504`/`202`-fallback). … It is **explicitly the ADR 0013 capture seam (Increment 1), NOT
> Increment 2 re-ingress**."

**(b) Request authentication on the intake socket.** ADR 0023 §D4.3, verbatim:

> "A web-service receiver that is exposed needs request auth (an API key / mTLS client cert / bearer)
> **distinct from the admin API's session RBAC** … This is a **per-inbound `settings` concern** (the secret
> from `env()`/`MEFOR_*`, never the TOML — ADR 0003 §1), shaped here as a follow-on knob, not the first slice."

**The motivating shape is a prospect's, and there is no committed customer.** A prospect runs Corepoint as
a **proxy API**: their customers call an endpoint, the engine forwards the call to a Salesforce instance,
and the customer receives Salesforce's answer in the same HTTP turn — over an authenticated socket, because
those customers are external. Today MessageFoundry can accept the POST and can call Salesforce, but it can
only answer `202` and it performs no credential verification at all. That is (a) + (b), together.

**State this plainly, because it sets the priority of everything below: as of 2026-07-30 there is no
customer waiting on this and no migration date.** The proxy-API shape is a credible design driver and it is
why the two halves are specified together — but it is a *prospect's* shape, not a commitment, and this ADR
should not be read as carrying a deadline. The two halves consequently have very different justifications,
and the build order in "Increments" below follows from that difference rather than from the prospect.

**The invariants that bound the design.** Quoting [CLAUDE.md](../../CLAUDE.md) §2 verbatim:

> "**Count-and-log invariant (do not break):** **every received message is persisted before the ACK** (status
> `RECEIVED` at the ingress stage), so inbound counts still reflect the true received volume and nothing is
> accepted-and-dropped. The ACK now means **receipt-and-persistence, not a final disposition**."

> "**Reliability invariant (do not break):** … The inbound connection is ACKed **only after** the raw message
> is durably committed to the **ingress** stage (**ACK-on-receipt**…). … At-least-once now relies on a re-run
> re-deriving identical output, so **routers and transforms must be pure** (message in → message out, no
> external side effects)."

And §4: *"**Dependency direction is one-way:** `pipeline/ transports/ parsing/ store/ config/` never import
`api/`."* §9: *"**Never log full message bodies at INFO or above.** Full payloads go only to the secured
store, never to the general log."* §12: *"Don't import PySide6 (or FastAPI) inside the engine packages."*

**The tension, stated precisely.** ADR 0013's central rule is that *"the capture must never participate in
deriving routing/transform output during the same run that produced it — a router/transform reads a
**committed prior** response, never one being produced now."* A naive reading of (a) looks like exactly that
violation: block the turn that produced the message on the reply that message produces. It is not, and the
distinction is the whole design: **the waiter is the source connector, not a pure stage.** No Router and no
Handler ever sees the reply; nothing the reply contains feeds any transform; re-running any stage re-derives
identical output because the reply is never an *input*. What blocks is a socket, outside the pipeline,
reading a row that has already committed. ADR 0016 settled the mirror-image case with a sentence this ADR
adopts wholesale: *"the synchronous read produces the non-deterministic value once, inside the transport; the
asynchronous machinery only ever reads it back from an immutable row."*

**What does not exist yet, and must therefore be invented.** There is **no per-message completion signal
anywhere in the engine**. `complete_with_response`
([`store/base.py`](../../messagefoundry/store/base.py)) commits the capture and raises nothing a listener
could hear; the runner's only signalling is `_wake_lane(stage, key)` — a per-`(stage, lane)` `asyncio.Event`
worker wakeup that carries no message identity, and which *drops* a wake for a lane another engine shard owns
(the documented wake gap). `correlate_response(message_id)` is a plain poll-shaped store read.

**On the intake side, stated precisely** (revision 1 overstated this and the correction matters, because it
is the same fact D7's gate turns on): a listen source configured `tls=True, tls_ca_file=…` **does** already
perform chain-level, deny-by-default intake authentication — `_mllp_ssl_context` sets `ssl.CERT_REQUIRED` and
`HttpSource` applies the same context, so a peer without a cert chaining to that anchor is refused at the
handshake. What is genuinely absent is (i) **any subject or principal binding** — `tls_ca_file` today means
*"any cert this CA ever signed"* — and (ii) **any credential mechanism at all**: `HttpSource` never inspects
a request header for authentication purposes, never reads `writer.get_extra_info("ssl_object")`, and `Http()`
([`config/wiring.py`](../../messagefoundry/config/wiring.py)) exposes eleven settings, none of them auth.

**And there is a live hole worth naming.** `check_http_tls_exposure`
([`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)) returns early the moment
`settings["tls"]` is truthy. So `Http(port=…, tls=True, tls_cert_file=…)` on `[inbound].bind_host = 0.0.0.0`
binds a PHI intake socket with **no peer identity requirement whatsoever** and passes every gate cleanly.
This is not a theoretical reading of the code: `tests/test_exposed_with_tls_passes` **pins that exact
configuration as passing**. `DicomScpSource.__init__` ([`transports/dicom.py`](../../messagefoundry/transports/dicom.py))
already refuses the analogous DIMSE configuration, and its in-code comment states the composition rule this
ADR adopts: the peer-control guard is *"the AUTHENTICATION analog of `check_dimse_tls_exposure`'s cleartext
bind guard (which is the orthogonal CONFIDENTIALITY guard)"*. HTTP has the confidentiality guard and lacks
the authentication one.

## Decision

**Add two per-inbound `Http()` capabilities, both opt-in and both default-off: (1) a bounded
block-on-captured-downstream-reply mode in which the listener returns bytes read out of an already-**committed**
ADR 0013 `response` row — never an in-flight `DeliveryResponse` — selected by naming the authoritative outbound
in `reply_from`; and (2) intake authentication (API key / bearer / mTLS subject) as a peer control on the
connector, its secret from `env()`/`MEFOR_*` only, with a new posture-keyed start-time gate refusing an
off-loopback HTTP listener that has no *effective* peer control.** Neither changes the `202` receipt semantics,
the `InboundHandler` contract, or any store schema. Two additive store surfaces are required and are named
explicitly in D3 and D8 rather than being denied.

### Increments — the two halves ship separately, and the security half does not wait on a customer

The two capabilities are specified in one ADR because they share a listener and were deferred by one
parent (ADR 0023). They are **not** of equal urgency, and bundling their *build* would hold a live defect
hostage to a speculative feature.

| | Driver | When |
|---|---|---|
| **Increment A — intake auth + the peer-control gate** (D6, D7) | A **live defect in shipped code.** `check_http_tls_exposure` returns early on truthy `tls`, so an off-loopback `Http(tls=True)` listener binds a PHI intake socket with no peer identity requirement — and `tests/test_exposed_with_tls_passes` pins that configuration as passing. This is wrong today, in any such deployment, with or without a customer. | **Now.** Independent of the prospect. |
| **Increment B — the synchronous captured-downstream reply** (D1–D5, D8) | The prospect's proxy-API shape. Roughly 70 % of this document's complexity and effectively all of its concurrency risk: the multi-handler terminality test, the rendezvous, the throughput envelope and the `max_connections` interaction. | **When a customer exists,** so their partner's real error and latency semantics shape it rather than a guess. |

The acceptance criteria already fall along this seam, so the split costs no renumbering and no design
change: **AC-11 … AC-16 and AC-19** cover increment A, **AC-1 … AC-10 and AC-18** cover increment B, and
**AC-17** (dependency boundaries) spans both.

The one genuine coupling is the `_read_request` → `_read_head`/`_read_body` split (D5, D6). It lands in
**increment A**, because authenticating *before* buffering a 16 MiB body is a requirement of the auth work
itself, not of the reply work.

Deferring increment B also defers its headline gap — `capture_error_responses` (see the open items). With
no customer to disappoint, a fixed-JSON `502` on a partner rejection is a documented limitation rather than
a broken promise, and the knob is better designed against a real partner's error semantics than in advance.

### D1 — The committed row is the sole authority for the returned bytes; every in-process signal is a latency hint

This is the load-bearing inversion, and everything else follows from it.

The blocked HTTP turn **never** observes a `DeliveryResponse`, never receives a reply payload through an
in-process channel, and never reads a row before `complete_with_response` has committed. It returns bytes
decrypted out of a `response` row via `correlate_response(message_id)`. An in-process rendezvous exists
**purely to collapse poll latency**, and it carries only a *reference* — `(destination_name, response_seq)` —
never a body. That shape makes "committed-only" **structural rather than a discipline**: there is no payload
in the signal to accidentally return.

The consequence is that every hostile topology degrades to *slower*, never to *wrong*:

| Situation | Behaviour |
|---|---|
| Capturing outbound lane owned by another engine shard (ADR 0037/0073 rendezvous hashing) | signal never fires; the poll finds the committed row |
| Active/passive HA — listener and capturing worker are the **same** process by construction (the graph runs on the leader only) | signal fires; poll is the backstop |
| `claim_mode="pooled"` (the default, ADR 0066) vs `per_lane` | the hook sits on the shared per-item path, so both fire |
| Signal races *ahead* of the waiter arming | harmless — the first unconditional read already sees the row |
| Rendezvous full / signal raises | swallowed; the poll is unaffected |

**This claim is only true because of the D3 revision.** Revision 1 asserted it while carrying a wait-loop
branch that returned a wrong `502` for any multi-handler message. A design that answers "failed" for a
request the engine then delivers successfully has degraded to *wrong*. The branch is deleted in D3; the
claim above is restored on that basis, not asserted over it.

Two freshness facts keep the proof short, and both are properties of code already in the tree:

1. `enqueue_ingress` mints a fresh `uuid4().hex` and `response.message_id REFERENCES messages(id)`, so the
   `response` set for this id is **provably empty at arm time**. There is no baseline to capture, no
   `since_seq` to carry, and no ABA hazard.
2. **Routing is co-located with the listener by construction.** ADR 0037 partitions engine shards by *inbound
   connection*, so the ingress/router/transform workers for this inbound and the socket holding the caller are
   in the same process. Only the **outbound lane** may live elsewhere. That is what licenses an
   always-reliable in-process *early-fail* on the **router's** disposition (D3) while still requiring the
   store to be authoritative on delivery. Note the narrowed scope: co-location licenses a reliable signal on
   `UNROUTED` only, because `FILTERED`/`NOT_DEPLOYED` are not router dispositions at all.

**One store-visibility fact, verified, that revision 1 did not state.** There is **no isolation window**
between the outbox row flipping to `done` and the `response` row becoming readable: the flip and the
`INSERT` commit in the **same transaction** on all three backends, and every read helper takes a fresh
snapshot. The "`done` ⟹ read `correlate_response`" step is therefore sound — but only for the
`complete_with_response` path. A plain `mark_done` (a non-capturing success) also produces `done` with no
`response` row, which D3 must and now does distinguish.

### D2 — The seam: a fourth runner-injected attribute, taking the already-committed `message_id`

`transports/` may not import `store/` or `pipeline/`, so the wait arrives the way every other engine service
reaches a connector — as a runtime-injected attribute on `SourceConnector`, defaulting to `None`, exactly like
`on_connection_event` / `content_type` / `processed_ledger`
([`transports/base.py`](../../messagefoundry/transports/base.py), injected in `_start_inbound_unsafe`):

- a frozen `InboundReply` declaration in `transports/base.py` carrying a **semantic outcome**
  (`reply` | `empty` | `rejected` | `failed` | `no_route` | `timeout` | `degraded` | `purged` |
  `shutting_down`), an optional `bytes` body and an optional captured content type — **no HTTP status**;
- `SyncReplyResolver = Callable[[str], Awaitable[InboundReply]]`, taking the **committed `message_id`**;
- `SourceConnector.sync_reply: SyncReplyResolver | None = None`.

**Taking the committed `message_id` as its only input is the design's strongest structural statement of
ACK-on-receipt:** the sync path *physically cannot run* before the body is durable, because its argument does
not exist until `enqueue_ingress` returns. `_handle_inbound_http` is untouched; `InboundHandler`
([`transports/base.py`](../../messagefoundry/transports/base.py)) is untouched, so MLLP/TCP are unaffected;
and an inbound without `reply_from` takes the byte-identical shipped path.

**The resolver arms the rendezvous itself, as its first action.** Revision 1 required arming "after
`enqueue_ingress` returns and before `_wake_lane(Stage.INGRESS, …)`" — two sites that are only ever adjacent
*inside* `_handle_inbound_http`, at three separate places (binary, non-HL7 text, HL7). That contradicted this
ADR's own promise that `_handle_inbound_http` is untouched, and left the armed entry ownerless between the
`pipeline/` frame that armed it and the `transports/` frame that would disarm it. Arming inside the resolver
makes arm and disarm the same `try`/`finally` in one frame, and costs nothing: D1's race table already
establishes that a signal arriving before the arm is harmless, because the first unconditional read sees the
committed row anyway.

**The resolver returns an outcome, not a status.** The outcome→HTTP mapping lives in
`transports/http_listener.py`, preserving ADR 0004 §6 (*"a non-HL7 source **owns its own receive-time
response** … that **lives in the source connector**"*) — the same division of labour as today, where the runner
returns a `message_id` and the listener decides that means `202`.

**Early slot reclamation is gated, not unconditional.** Revision 1 raced the resolver against a peer-EOF read
so a vanished client would free its `max_connections` slot immediately. On a request/response socket that is
unsound: EOF on the read side means *the request is over*, not that the caller left — the caller is on the
write side, waiting. Worse, it is **deterministic**, not racy: the shipped `_read_request` accepts a
POST/PUT/PATCH with no `Content-Length` and reads the body **to EOF**, so the reader is already at EOF before
the race arms, and every such turn would be aborted before it began. The EOF race is therefore armed **only**
when the request carried a `Content-Length` (so the body read did not consume to EOF), and EOF alone is not
treated as abandonment — it must coincide with a failed zero-byte write probe on the writer. `reply_timeout`
already bounds the slot; the reclamation optimisation may not cost correct turns to get it.

Cancelling the resolver cancels only an *observer*: the message stays committed, keeps flowing, and its reply
still lands in `response`.

### D3 — The wait loop: poll message status + outbound state, read `correlate_response` exactly once, fail fast only on proven-terminal cases

A new stdlib-asyncio-only `ReplyRendezvous` (`pipeline/reply_wait.py`), keyed on
`(message_id, destination_name)` so a foreign destination's capture cannot wake the waiter into a
permanently-set-event spin. It is armed by the resolver on entry and disarmed in a `finally`.

**The authoritative read is a new metadata-only store method,
`reply_wait_state(message_id, destination_name)`**, returning `(message_status, [(status, response_seq_hint)])`
for the `reply_from` outbound rows. This is an additive read helper, not a schema change. Revision 1 polled
`outbox_for`, which is wrong on two counts: it is `SELECT *` and **decrypts `last_error` and pulls the full
PHI ciphertext every tick** (so it is not "metadata-only" as claimed, and it is unacceptable in a hot poll
loop for the same reason `get_message` was rejected), and it is scoped to `stage='outbound'`, so it
structurally **cannot see a pending `routed` row** — which is precisely the state the deleted branch
misread.

Each tick:

| Observed | Action |
|---|---|
| a `reply_from` row is **`done`** *via capture* | **one** `correlate_response(message_id)` read; filter `kind == "response"` **and** `destination_name == reply_from`; take `max(response_seq)`; then map the captured row's **`outcome`** field: `accepted` → `reply`, `no_reply` → `empty`, `rejected`/`unparseable` → `rejected` |
| a `reply_from` row is `done` but **no qualifying `response` row** (a plain `mark_done`, or retention nulled the body) | `purged` if the row exists with a null body, else `failed` — distinguished, not conflated |
| **every** `reply_from` row is terminal-failed (**`dead`** or **`cancelled`**) and none is `done` | **fail immediately** (`failed`) |
| `messages.status` is **terminal** — defined as **anything other than `RECEIVED` or `ROUTED`**, which therefore includes `PROCESSED` — **and** no qualifying `response` row exists | **fail immediately** (`no_route`) |
| a `reply_from` row is `pending`/`inflight`, **or** the message is still `RECEIVED`/`ROUTED` | keep waiting |
| no `reply_from` row yet and the message is still `RECEIVED`/`ROUTED` | **keep waiting** — a sibling handler may simply not have transformed yet |

**The terminal set is defined by exclusion (`not in (RECEIVED, ROUTED)`), never by enumeration**, and that
is a correctness requirement rather than a stylistic preference. An enumerated list
(`UNROUTED`/`FILTERED`/`NOT_DEPLOYED`/`ERROR`) silently omits **`PROCESSED`** — and `PROCESSED` is exactly
what the finalizer sets when a *sibling* handler delivered successfully and the `reply_from` Send was
declined, filtered out, or never emitted by a code-first Handler. `FILTERED`/`NOT_DEPLOYED` are reachable
only when **no** queue rows remain at all, so the moment one sibling delivers, the terminal status is
`PROCESSED`. Under an enumerated set the single most likely misconfiguration — a Router that simply does
not route to `reply_from` — falls through to "keep waiting" and burns the full `reply_timeout`, which is
precisely the residual D4 delegates to this loop. Defining terminality by exclusion makes the table total
against `MessageStatus` **by construction**, so a future enum value cannot reopen the hole.

**Why the last row is the most important line in this revision.** Revision 1 read "rows exist, none for
`reply_from`" as "routing finalised and excluded us → fail immediately". That is unsound, because outbound
rows for one message are **not produced in one transaction**: `route_handoff` inserts one `stage='routed'`
row **per selected handler**, and `_transform_worker` claims and commits them **one at a time**, with a full
user transform between. So an ordinary two-handler message — handler A archives to a File outbound, handler B
proxies to `reply_from` — deterministically shows a non-empty outbound set containing no `reply_from` row for
as long as B sits behind A on the ROUTED lane. Revision 1 answered `502`; the engine then delivered
successfully and captured exactly the reply the caller was owed. The store's own code names this trap
verbatim: *"a sibling handler's routed/outbound rows may still be in flight, so per-handoff disposition math
would be order-dependent and wrong"* — the finalizer is the single disposition authority. **The wait loop
must not do disposition math on a partial row picture.** It now asks the message's own status instead.

`cancelled` is the fifth outbox status, reachable by an operator running `cancel_queued` on the lane while a
caller is blocked. Revision 1's four-status table matched none of its branches, so the caller burned the full
`reply_timeout` for a message the operator had already terminated.

Backoff ramps 25 ms → 250 ms; finer buys nothing, because `claim_mode` defaults to `pooled` with a 0.25 s
sweep interval.

**The `dead` branch remains the most operationally valuable line in this ADR.** `RestDestination` raises
`NegativeAckError(permanent=True)` on a non-retryable partner 4xx (excluding 408/429) and the worker routes it
straight to `dead_letter_now` with no retry and **no `response` row** — so without this branch, a Salesforce
validation error costs the caller a full `reply_timeout` of silence. One narrowing, verified: a
`credential_fault` permanent failure releases the row to `PENDING` rather than `dead`, so it is covered by the
`pending` wait branch and bounded by `reply_timeout`, not by the fast-fail. That is stated rather than
implied.

**Rejected: polling `get_message` as a terminal fence.** `get_message` decrypts the raw PHI body — unacceptable
in a poll loop. `correlate_response` decrypts every row including ADR 0021 `ack_sent` rows, so it is read
**once**, only after the state read proves a capture committed.

**Two signals, both hints, both fail-safe — and they sit at two different stages:**

- **Delivery** — one synchronous `rendezvous.signal(message_id, destination_name)` immediately *after*
  `complete_with_response` **returns**, beside the existing `_wake_lane(Stage.RESPONSE, reingress_to)` in
  `_process_delivery_item`'s success branch. That site is shared by the per-lane worker and the pooled
  dispatcher, so a per-lane-only hook would be **dead by default**. It is an `Event.set()`: it cannot raise
  into, delay, or un-succeed a delivery — the ADR 0013 rule that *capture must never un-succeed an already
  successful `send()`* extends unchanged to the notify.
- **Terminal disposition** — `rendezvous.fail(message_id, reason)` from **two** sites, because one is not
  enough:
  - `_router_worker`'s disposition path on **`UNROUTED`** — the *only* disposition it produces
    (`disposition = MessageStatus.ROUTED if names else MessageStatus.UNROUTED`). Co-located with the
    listener, so this arm is genuinely reliable.
  - `_transform_worker`'s post-`transform_handoff` path on the **zero-delivery** and **declined-only**
    branches, which is where `FILTERED` and `NOT_DEPLOYED` are actually decided (by
    `_maybe_finalize_message` inside the store, reading the `not_deployed` signal `transform_handoff` wrote).

  Revision 1 hooked all three at the router and called the result *"reliable, not best-effort"*. Two of the
  three are **not observable there and never can be** — "the handler filtered this message" and "every Send
  was declined as not-deployed" are facts about *transform output*, which the router structurally cannot
  know. The practical cost of that error was severe: a filtering Handler or a not-deployed `reply_from`
  produces **no outbound rows at all**, so the poll would sit in its "still routing → wait" branch for the
  full 30 s and answer `504` for a message the engine finished in milliseconds — and at `max_connections`
  scale, one such misconfiguration converts 256 slots × 30 s into a listener-wide `503` storm.

A store read that raises is caught, logged with `safe_exc`, and mapped to the `degraded` outcome. Never a
`500`, never a killed connection.

### D4 — The per-inbound surface, and offline validation that fails with no store

On `Http()` ([`config/wiring.py`](../../messagefoundry/config/wiring.py)):

| setting | default | meaning |
|---|---|---|
| `reply_from` | `None` | **presence is the mode switch**; names the outbound whose captured reply is the HTTP body |
| `reply_timeout` | `30.0` | bounds the block (seconds) |
| `reply_on_timeout` | `"504"` | `"504"` or `"202"` — ADR 0023 §D3 pre-authorised both |
| `reply_content_type` | `"passthrough"` | `"passthrough"` (echo the captured `content-type`) or a literal MIME |
| `reply_on_empty` | `"204"` | `"204"` or `"200"` — an escape hatch for toolchains that mishandle a bodyless `204` |
| `reply_write_timeout` | `30.0` | bounds the response drain |

**One knob, not two.** A separate `sync_reply: bool` would admit a half-configured state (mode on, no target)
that can only fail at runtime.

**Offline validation** — must fail in `messagefoundry check` / dry-run **with no store**, and identically
through the `connections.toml` desugar because it runs the same factories. Per-connection facts in
`build_inbound_connection`; cross-registry edges in `build_check_registry`, beside the existing `reingress_to`
check:

- `reply_from` names a **deployed** outbound in `registry.outbound` → else `WiringError`;
- that outbound has `capture_response=True` → else `WiringError`;
- when `reply_content_type="passthrough"`, `"content-type"` is in that outbound's `capture_response_headers`
  allow-list → else `WiringError`. **Guarded by a capability check first:** `capture_response_headers` exists
  on only 3 of the 8 outbound factories, so this must be skipped (not crash) for a capturing outbound that
  has no such allow-list, and `passthrough` must then be refused with a clear message rather than an
  `AttributeError`;
- **`reply_from` + an effective `ordering` of FIFO → `WiringError`**, and **`reply_from` + an effective
  `max_attempts` of `None` → `WiringError`**. **The predicate must read the *effective* value, not the
  declared one.** `OutboundConnection.ordering` defaults to `None` (= inherit) and `retry` defaults to
  `None` (no `RetryPolicy` object at all); resolution to FIFO / retry-forever happens in the
  RegistryRunner from `[delivery]`. A literal `ordering == FIFO` / `retry.max_attempts is None` test
  therefore **passes cleanly for the overwhelmingly common shape** — the exact shape this refusal exists
  to catch. State it as `ordering in (None, FIFO)` and `retry is None or retry.max_attempts is None`, and
  either thread the `[delivery]` defaults into `build_check_registry` or move this pair to
  `build_check`/start where the runner has already resolved them. Revision 1 made the second a WARN and
  did not mention the first. Both are refusals
  because together they make the feature's headline use case unserviceable: `ordering` defaults to **FIFO**,
  which drains one message at a time and **blocks the head on failure**, and `max_attempts` defaults to
  `None` (retry forever). So N concurrent HTTP callers do not get N concurrent downstream calls — they
  serialise behind a single lane bounded by one partner round-trip — and one transiently-failing head
  message holds the lane until an operator purges it, timing out **every** concurrent and subsequent caller.
  "Retry forever" and "the caller gave up 30 s ago" are not merely incoherent; they are a total outage with
  a config-shaped cause;
- **the intake-auth settings are validated too**, which revision 1 omitted entirely:
  `intake_auth="mtls_subject"` requires `tls=True` **and** `tls_ca_file` **and** a non-empty
  `intake_client_subjects` → else `WiringError` (otherwise the SSLContext never requests a client cert,
  `getpeercert()` returns empty, and deny-by-default `403`s 100 % of traffic with no start-time error);
  `intake_auth in ("api_key", "bearer")` requires a non-`None` `intake_api_key` → else `WiringError` (an
  unset value is not an env-resolution failure, so `resolve_env_settings` does not catch it);
- **WARN** (never refuse) when `owner_shard_of_destination(reply_from, …)` is not the listener's engine shard,
  naming both the added poll latency **and the read-pool cost** (see the envelope in D5);
- `reply_from` **+** `ack_after=DELIVERED` → `WiringError`.

**Moved out of the offline list:** `supports_response_capture is False`. It is a **store-capability** fact,
so it cannot be evaluated "with no store"; it belongs at `build_check`/start. Two secondary corrections: the
shipped precedent raises `RuntimeError`, not `WiringError` — the caller catches it and calls `_record_failed`,
which is what actually delivers ADR 0031 isolation — and the existing `getattr` default is `True`, i.e.
fail-open, which this check must not silently inherit.

**Not statically provable:** that a code-first Router actually routes to `reply_from`. That residual is the
runtime fast-fail in D3, not a start-time error, and the ADR says so rather than implying a guarantee.

### D5 — Outcome → wire, and the listener deltas that follow

Every row maps to exactly one D2 outcome, and every D2 outcome has exactly one row. Revision 1's table had
two rows with no outcome and one that needed a body it might not have.

| Outcome | Condition | HTTP | Body |
|---|---|---|---|
| `reply` | captured `accepted` | `200` | partner reply verbatim |
| `empty` | captured `no_reply` | `204` (or `200` per `reply_on_empty`) | none |
| `rejected` | captured `rejected` / `unparseable` | `502` | partner reply verbatim |
| `failed` | outbound row `dead`/`cancelled` (the common partner-4xx case) | `502` | fixed non-PHI JSON + `message_id` |
| `purged` | captured row exists, body nulled by retention | `502` | fixed non-PHI JSON |
| `no_route` | `UNROUTED` / `FILTERED` / `NOT_DEPLOYED` | `reply_on_timeout` status, **immediately** | fixed JSON |
| `timeout` | `reply_timeout` expired | `504` (default) / `202` | `{"status":"timeout","message_id":…}` |
| `degraded` | store read raised / rendezvous full | configured fallback | fixed JSON |
| `shutting_down` | listener stopped mid-block (D2/AC-9) | `503` + `Retry-After` | fixed JSON |

`degraded` is its own outcome, not folded into `timeout`, because D8's SLO series
`rate(timeout)/rate(total)` is *the proxy API's error budget* — counting engine store errors as partner
timeouts would silently corrupt the one metric an operator pages on.

**Outside the outcome table, because it happens before the resolver exists:** a handler returning `None`
yields **`422`** on the sync path only. Today it yields "`202` without a `message_id`", which is a lie to a
proxy client. The shipped `202` path keeps today's behaviour exactly.

**This is a *post-record* refusal, not a pre-ingress one, and the distinction matters for count-and-log.**
`_handle_inbound_http` returns `None` only *after* `record_received(status=MessageStatus.ERROR, …)` has
already persisted the message — that write **is** the count-and-log mechanism, not its absence. So
count-and-log holds here because the row **exists** and carries `ERROR`, not because nothing was written.
Only the intake-auth refusal is genuinely pre-ingress (it happens before the handler runs at all). An
earlier draft of this ADR asserted "no ingress row was written, so there is nothing to count" for the
`422`; that was wrong on the shipped path and is corrected here.

**Content-Type is partner-controlled and must be validated.** The guard lives **inside `build_response`**,
not at the sync-reply call site: `build_response` joins headers with `"\r\n"`, its own `content_type`
parameter is the chokepoint, and leaving it unguarded means the `#20` FHIR facade and `#24` DICOMweb receiver
named as future consumers inherit the hole. Validate `content_type` and every `extra_headers` name and value
there with `re.fullmatch` (never a `$`-anchored `match`, which accepts a trailing newline) over an explicit
ASCII token class. **Reject, do not strip** — and note that the existing `_strip_header_control_chars`
helper cannot be reused for this: it contains no regex and it *removes* offending characters rather than
refusing the value, which would silently reshape a partner's Content-Type instead of failing the turn.
AC-9 requires refusal, so the validation is a new `re.fullmatch` guard and the existing helper stays where
it is. Additionally
sanitise **at capture**, so a hostile header never reaches the store. This gets its own test; it is not left
to review discipline.

**No status passthrough in increment 1.** `DeliveryResponse` has no status field and `RestDestination` stuffs
`f"HTTP {status}"` into free-text `detail`. Parsing that back out would make a display field load-bearing.
(Revision 1 justified this by calling `detail` "`safe_text`-scrubbed"; it is not — scrubbing applies only on
the ADR 0021 `ack_sent` path, and the capture path passes `detail` through untouched and merely encrypts it.
The rejection stands on the field being untyped free text, which is the honest reason.) A typed
`DeliveryResponse.status_code` plus an additive nullable `response.status_code` column is increment 2.

**Listener deltas** ([`transports/http_listener.py`](../../messagefoundry/transports/http_listener.py)):

- `_read_request` is **split into `_read_head` and `_read_body`** so authentication can run between them
  (D6). This is the single largest listener change and it is a prerequisite, not a nicety.
- `_status_line`'s reason-phrase map gains `204, 401, 422, 429, 502, 503, 504` (`403` is already mapped
  and needs no addition). **`503` is a live defect
  today** — already emitted at capacity and serialised as `HTTP/1.1 503 OK`, reproduced by executing the
  shipped code; it is fixed here and must not be read as a sync-reply regression.
- `build_response` gains an `extra_headers` parameter (with the CR/LF rejection guard above) and a
  `bytes`-body sibling; `204` suppresses entity headers.
- `_respond` gains a **bounded** drain (`reply_write_timeout`) — it now carries a partner-sized PHI body to a
  possibly slow reader; today it drains unbounded.
- `HttpSource` calls `_set_tcp_nodelay` as `MLLPSource` does.
- `stop()` gains an explicit **pre-close drain phase**: set a draining flag the rendezvous observes, wake
  every waiter with `shutting_down`, let each `_serve_one` write its `503` + `Retry-After` through the
  **still-open** writer under a sub-budget of `_CLIENT_SHUTDOWN_GRACE`, and only then run today's
  close-writers → bounded `wait_closed()` → cancel sequence. Revision 1 promised the `503` while also
  promising the existing ordering; those are mutually exclusive, because `stop()` closes every client writer
  *before* it waits, and `_write_safely` swallows the resulting `OSError` — so the demoted caller would have
  seen a bare connection reset, not the `503` the HA argument depends on. Explicitly **not** a `504` during
  an HA demotion, which would lie about a message the new leader is about to deliver.
- `build_response`'s docstring assertion *"No PHI is ever placed in a response body here"* is **knowingly
  retired for the reply path only** and rewritten with the replacement rule. Revised, not quietly falsified.

**Note that three of these deltas change the shipped `202` path**: the `503` reason-phrase fix, `TCP_NODELAY`,
and the `_read_request` split. AC-8's "unchanged" is therefore scoped to the **response body and status
semantics** of a `reply_from`-less inbound, not to every byte on the wire. Saying so is the honest form of
the claim.

**Bounding is three independent clocks**: `receive_timeout` (read only, unchanged) + `reply_timeout` (the
block) + `reply_write_timeout` (the drain). `self._active` already spans all of `_serve_one`, so
`max_connections` is the in-flight-block budget and its refusal is **pre-ingress** (`503`, nothing committed,
no duplicate-call hazard).

**The published throughput envelope is not `max_connections × reply_timeout`.** That figure ignores two
tighter constraints: (a) the `reply_from` lane's own concurrency — with `ordering=UNORDERED` now required by
D4, this is the lane's parallelism, and sustained throughput cannot exceed it regardless of how many sockets
are blocked; and (b) the store read pool — on SQLite, reads share a **fixed pool of four** connections with
the admin API, console, retention and alert sweeps, so 256 waiters at the 250 ms backoff floor demand
~1,000 pooled reads/s. The published envelope is
`min(lane_concurrency, f(read_pool_size, poll_period), max_connections)`, and the poll period is floored as a
function of live waiter count so the load is self-limiting. `max_waiters` on the rendezvous remains a
leak/DoS backstop resolving to `degraded`, not a second refusal point.

### D6 — Intake auth is a peer control on the connector, not admin RBAC

Framing first, because it decides everything downstream: an intake credential authorises **submitting a
message on this inbound**. It is a sibling of `source_ip_allowlist`. It mints no `Identity`, carries no
`Permission`, opens no session, and never reaches into `auth/` or `api/`. It authorises *submitting*; it never
authorises *reading*.

**Modes** (`intake_auth: "none" | "api_key" | "bearer" | "mtls_subject"`, default `"none"`), with
`intake_api_key` / `intake_api_key_next` (`EnvRef` only), `intake_api_key_header` (default `x-api-key`),
`intake_client_subjects`, `intake_auth_health` (`"require"` | `"allow"`, default `"require"`),
`intake_auth_rate_limit` (default 10 **failed attempts**/min/peer) and `intake_auth_rate_limit_global`
(default 60 failed attempts/min across all peers).

All three modes ship. `api_key` is what most partners actually send; `bearer` is what SOAP/REST toolchains
default to; `mtls_subject` is the one that closes a real posture problem, because `tls_ca_file` today means
*"any cert this CA ever signed"* with **no subject binding at all**. `intake_api_key_next` is the difference
between rotating a partner key with an outage and rotating it without one.

**Secret resolution needs zero new plumbing.** `env()`-only enforced at the factory (the
`File(credential_password=…)` shape, ADR 0132); `resolve_env_settings` already runs over HTTP inbound settings,
so `MEFOR_VALUE_*` overlay and loud-failure-on-missing are free. `intake_api_key`/`_next` join
`_SECRET_SETTING_KEYS` — the single source of truth for `/metadata` redaction **and** `graph --json` — and stay
**out** of `_NON_ROTATABLE_SECRET_SETTING_KEYS`, which auto-enrols them in the ASVS 13.3.4 rotation
fingerprinter and trips `tests/test_secret_rotation_inventory.py` until documented. That is a required
companion change and a free operator win. `intake_client_subjects` is topology, not a secret, and stays
readable. **`SecretProvider`/Vault is not threaded into connectors here** — that is its own ADR.

**Comparison lives in a new pure package-root leaf, `messagefoundry/credential.py`** — the
[`netaddr.py`](../../messagefoundry/netaddr.py) precedent, whose docstring already states this exact rationale
("so both the transports (which must not import the API) and the API (which must not import the transports)
can depend on it"). It holds:

- `constant_time_match(presented, configured)` — `hmac.compare_digest` over **fixed-width SHA-256 digests of
  both sides** (so the credential's *length* cannot leak by timing), with an explicit **precondition that it
  returns `False` for an empty or absent `presented` value and for an empty or `None` `configured` value,
  checked before any digesting.** This precondition is load-bearing, not defensive coding:
  `sha256(b"") == sha256(b"")`, so without it a request presenting **no credential at all** authenticates
  whenever `intake_api_key_next` is unset — which is the default, because rotation is opt-in. Revision 1
  cited `auth/totp.py`'s ASVS 11.2.4 drift guard while dropping the very precondition that makes it safe
  (`totp.py` validates the candidate's length and shape *before* entering the no-break loop).
  The `UnicodeEncodeError` guard on the encode step is retained: on an unauthenticated path a raise would
  `500` and **skip the audited-refusal branch**. (Note that once both sides are digested, `compare_digest`
  itself can no longer raise `TypeError` — the guard belongs at the encode, and revision 1 conflated the two
  precedents.)
- `cert_name_candidates` / `client_cert_principal`, **hoisted from** the existing `_cert_name_candidates` and
  `client_cert_principal` in [`api/security.py`](../../messagefoundry/api/security.py) (already pure and
  deny-by-default, but unreachable from `transports/` because that module imports `fastapi`), with
  `api/security.py` re-importing from the leaf so the two planes cannot drift.

The accumulator iterates only over **configured, non-empty** keys with **no early return**, mirroring the
ASVS 11.2.4 drift guard; when `intake_api_key_next` is unset, a fixed dummy digest is compared so the
comparison count stays constant.

**Placement — between the head read and the body read.** Header modes run in `_serve_one` after `_read_head`
and **before** `_read_body` (the D5 split). Revision 1 placed them "between the request-parse and the method
dispatch", but `_read_request` is not a header parse: it reads the request line, the headers **and the entire
body** in one call, bounded only by `max_body_bytes` (16 MiB default). With `max_connections=256` that let an
anonymous peer command ~4 GiB of resident heap — transiently ~2× on the no-`Content-Length` path, where
`_read_to_eof` accumulates a chunk list and then joins it — before a single credential byte was examined, and
the `429` could not shed it because the limiter was consulted at the same post-parse point. The shipped code
already gets this ordering right for its other DoS guard: the `max_connections` refusal is pre-parse in
`_on_client`. mTLS runs in `_on_client` via `writer.get_extra_info("ssl_object").getpeercert()`, which is
already pre-read. Worth stating as an architectural asymmetry: ADR 0083's blocker was that stock uvicorn does
not surface the peer certificate to the ASGI scope — **`HttpSource` owns its own socket, so mTLS-as-identity
is strictly *easier* here than on the admin API.** Auth is per-request, not per-connection, by construction,
because `build_response` hardcodes `Connection: close`.

**The rate limiter is consulted read-only, and charged only on failure.** `SlidingWindowRateLimiter.allow()`
is check-**and**-record — it appends on every call, and every existing caller consumes it per *attempt*. So
injecting it as a predicate consulted "before any comparison", as revision 1 specified, would have made
`intake_auth_rate_limit=10` a hard **10-requests-per-minute-per-peer throughput cap**: the 11th correctly
authenticated message from the prospect's partner would take a `429` and, being a pre-ingress
refusal, would not even be counted — silent, uncounted message loss on the feature's motivating happy path.
This ADR therefore requires an additive read-only `SlidingWindowRateLimiter.would_allow(key)` (prune and
compare, no append), consulted before comparison, with `allow(key)` called **only on the failure branch**.
A successful authentication consumes no budget. The limiter is runner-owned and injected as a **synchronous
predicate**, so `transports/` gains no `auth/` edge; it is in-process and non-distributed — under HA only the
leader binds (effectively global), under engine sharding each shard counts separately, so the effective
ceiling is N × limit for N shards, and the ADR says so. A **global** arm is required — aggregate refusal volume from many source addresses is otherwise
unbounded, and each refusal drives a `record_audit` write that takes the store-wide lock and does a
`SELECT … ORDER BY id DESC LIMIT 1` before inserting, a global serialisation point shared with every
operator PHI-access audit write. **But the global arm must never refuse a peer that has already
authenticated in the window.** `SlidingWindowRateLimiter` refuses on the global bucket *regardless of
key*, so a naive global arm hands one attacker a denial-of-service against the prospect's
correctly-authenticated partner: ~1 bad request/second exhausts the shared budget, `would_allow(key)`
then returns `False` for **every** peer, and the partner's valid message is refused `429` pre-ingress
and therefore **uncounted** — which is verbatim the silent-loss defect this ADR diagnoses in revision 1,
merely relocated from the per-peer arm to the global one. The global bucket is therefore consulted
**only** for peers with no successful authentication recorded in the current window. The tree already
makes this distinction and must be followed rather than re-derived: `allow_reauth_attempt` scopes its
limiter the same way for the same reason.

**Health probes are inside the gate by default** (`intake_auth_health="require"`), with an explicit `"allow"`
opt-out. An unauthenticated liveness probe on a PHI intake socket is a free "is MessageFoundry up, and where"
oracle. Nothing *shipped* changes, because `intake_auth` defaults to `"none"` — but this **is** a breaking
change for any operator who enables `intake_auth` with an existing load-balancer check on `GET`/`HEAD`, and
it ships documented as such in the release notes, not as a footnote.

**Wire shapes.** Missing and wrong credentials take the **same** path — `401`, one fixed body, no oracle, with
`WWW-Authenticate: Bearer` in bearer mode. A valid mTLS chain whose subject is not allow-listed is **`403`**
(authorization, not authentication). A rate-limit trip is **`429`** + `Retry-After`, refused **before** any
comparison.

**An auth failure is a pre-ingress refusal**: no ingress row, a synchronous 4xx, count-and-log intact because
nothing was accepted. It reuses the existing `HttpRequestError` arm.

**Three audit channels:**

1. `logger.warning` with peer host and mode only — always. Never the credential, not a prefix, not a length.
2. A tamper-evident **`audit_log`** row through a runner-injected sink (the `ConnectionEventSink` shape, so
   `transports/` stays store-free) calling `record_audit(action="intake.auth_failed", channel_id=<inbound>,
   client=<peer_ip>, detail=<scrubbed>)`. This is the **first engine-internal writer of `client=`** (ADR 0150),
   and the docstring's *"NULL means 'no client was in scope'"* is exactly why — here one demonstrably is.
   Fail-soft, and **rate-limited independently** of the other two channels (one row per peer per window)
   because of the global-lock cost above.
3. The existing `connection_event` with new kinds `intake_auth_failed` / `auth_subject_denied` /
   `auth_rate_limited`.

**Why `audit_log` rather than `connection_event` alone — corrected rationale.** Revision 1 argued that
`_make_connection_event_sink` "returns `None` unless the inbound opts in", so an auth failure would be
*invisible by default*. **That is backwards.** The sink is live by default for every inbound: the master
switch `[diagnostics].connection_events` defaults to `True`, the per-connection flag inherits it, and the
sink returns `None` only when capture has been explicitly turned **off**. (ADR 0021's document says
OFF-by-default and is stale; `docs/PHI.md` records "**`connection_event` table — DEFAULT ON**" and
`tests/test_phi_logging_inventory.py` pins it.) The `audit_log` row is therefore justified on its actual
merits, which are sufficient: `connection_event` is **operator-disableable diagnostics**, while `audit_log`
is a **tamper-evident hash chain** that an operator cannot silently switch off — and an authentication
refusal on a PHI intake socket belongs in the record that survives someone turning diagnostics off.

### D7 — A separate, posture-keyed peer-control gate that does *not* read `--allow-insecure-bind`

A new `check_http_intake_auth(source, name, *, posture)` in
[`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py), called from
`_start_inbound_unsafe` immediately after `check_http_tls_exposure`. It refuses an off-loopback HTTP listener
that has no **effective** peer control.

**The predicate is strength-based, not presence-based.** Revision 1 accepted any of `source_ip_allowlist`,
`intake_auth != "none"`, or `tls + tls_ca_file` — and each has a trivially worthless satisfying instance:
`source_ip_allowlist = ["0.0.0.0/0"]` passes (`peer_ip_allowed` parses with `ip_network(entry, strict=False)`
and there is no minimum-prefix rule anywhere), and `tls + tls_ca_file` passes while being the very control
D6 describes as empty — *"any cert this CA ever signed"*. A gate satisfied by controls that authenticate
nobody is theatre. The predicate is therefore:

- `intake_auth in ("api_key", "bearer")` with a configured secret; **or**
- `intake_auth == "mtls_subject"` with `tls_ca_file` and a non-empty `intake_client_subjects`; **or**
- a `source_ip_allowlist` in which **every** entry has a prefix length at or above a documented floor
  (`/8` for IPv4, `/32` for IPv6 — generous, but it excludes `0.0.0.0/0` and `::/0`).

`tls + tls_ca_file` **alone** no longer satisfies the gate; it satisfies the *confidentiality* gate, which is
a different question. A configuration that fails the strength test is treated exactly like one with no peer
control at all — **refused** under `posture.enforcing and posture.is_phi`, warned otherwise — and is not
given a softer landing for having a control that does not work. There is no installed base to protect:
**MessageFoundry has no production deployments**, so nobody is running a CA-only client-cert listener that
this would break. Strictness costs nothing today and never gets cheaper — the only moment a weak
configuration can be stopped from becoming established practice is before anyone depends on it. An earlier
draft softened this to a warning plus a `security_loosenings` row "so the upgrade path is not a cliff";
there is no upgrade path, and that reasoning is withdrawn. This also removes an internal inconsistency,
since AC-16 always specified refusal.

Three deliberate choices:

- **A separate function, never folded into `check_http_tls_exposure`.** That gate returns early whenever `tls`
  is truthy — precisely the case an authentication requirement most needs to cover, and precisely what
  `tests/test_exposed_with_tls_passes` pins today.
- **Runner-side, with the trade-off stated honestly.** Revision 1 justified this by claiming the constructor
  form (DICOM's) "does not fire at `messagefoundry check`". **That is exactly backwards**: the constructor
  *does* run at check time; the runner-side placement in `_start_inbound_unsafe` is the one that does
  **not**. The real reasons to prefer runner-side are that it is posture-keyed (a constructor cannot warn on
  a lab box and refuse on production PHI) and unit-testable without a bind. Because check-time coverage is
  genuinely lost, `build_check_registry` gains a **parallel offline arm** that applies the same predicate
  without a posture, emitting a warning — so `messagefoundry check` still surfaces the problem.
- **It ignores `allow_insecure_bind` entirely.** Handing a *cleartext* escape hatch the power to also waive
  *authentication* is a category error. The gate is posture-keyed only: refuse under `posture.enforcing and
  posture.is_phi`, warn otherwise, and `posture is None` (a direct/embedding call) never becomes a new
  refusal. A raise is a `WiringError` → ADR 0031 isolation, never an engine crash.

Loopback binds stay **byte-identical** (ADR 0148 GIVEN 1). The deviation registers in `security_loosenings`
and gets a `docs/SECURITY-LOOSENING.md` row. **The completeness floor in
`tests/test_security_posture_defaults.py` does not cover this and must be extended:** it iterates only
boolean settings fields, so it could never fire for a per-inbound connector deviation. Revision 1 leaned on
it as the safety net that would catch an unregistered loosening; that net has a hole exactly where this ADR
needs it. The gate uses the CIDR-aware `tls_policy.is_loopback_hop_host` rather than minting another
`_LOOPBACK_HOSTS` frozenset; there are **five** same-named copies across **two** distinct contents in the
tree (revision 1 said three copies and two semantics), and reconciling them stays out of scope — but the
count is now stated correctly so the follow-on is scoped from a true baseline.

**The composition rule, stated once and prominently: TLS is confidentiality; intake auth is authentication.**
Enabling auth is never an argument for relaxing `check_http_tls_exposure`, and TLS being on is never a reason
to skip auth.

### D8 — Observability sized to a 2 a.m. page, and nothing more

- **`message_events`** — `reply_returned` (`dest=`, `seq=`, `outcome=`, `status=`, `waited_ms=`) and
  `reply_timeout` (`dest=`, `waited_ms=`, `fallback=`), `safe_text`-scrubbed and encrypted; names and counts
  only, never a body fragment. `reply_timeout` joins the audit-floor event set — it is the one row that
  explains a customer complaint. `tests/test_phi_logging_inventory.py` forces the matching `docs/PHI.md` §7
  rows to ship with them.

  **This requires one new public store method**, and the ADR says so rather than claiming otherwise: `_event`
  is **private** to each concrete backend and called only inside store-owned transactions; there is no public
  message-event writer on the `QueueStore` protocol, and neither `pipeline/` nor `transports/` can reach it.
  So this adds `record_message_event(...)` implemented on all three backends, plus two members of the `Final`
  `MESSAGE_EVENT_KINDS` frozenset and one of `_AUDIT_FLOOR_EVENTS`. Revision 1 promised "no store method"
  while requiring this; the promise is corrected rather than the feature dropped, because `reply_timeout` is
  the single most valuable diagnostic row in the design.
- **`connection_event`** — `reply_timeout`, `at_reply_capacity`, plus the three auth kinds; and the
  already-emitted-but-undocumented `idle_timeout` kind gets documented in the store's kind list while we are
  in there.
- **Metrics** — `messagefoundry_http_sync_replies_total{connection,outcome}` (the SLO series:
  `rate(timeout)/rate(total)` **is** the proxy API's error budget, which is why `degraded` is a distinct
  outcome label), `messagefoundry_http_sync_reply_wait_seconds{connection}` (answers *"is p99 approaching
  `reply_timeout`?"* **before** the pager), `messagefoundry_http_sync_reply_waiters{connection}`.
- **Alerting — reuse `saturation`, do not mint a new reason.** Revision 1 deferred a `sync_reply_degraded`
  AlertSink reason as costing "a protocol method plus every sink implementation plus the ADR 0014 rule
  vocabulary". That overstates it — `_ALERT_EVENT_TYPES` already carries eighteen event types (and the
  AlertSink surface twenty methods), so adding one is routine — but the
  right answer is still not to add one, because **`saturation` already exists and is the correct fit**. The
  fallback revision 1 named was wrong: `queue_buildup` and `message_stall` fire on *lane backlog*, which may
  never appear when the failure is listener-side (sockets blocked, lane healthy). `at_reply_capacity` feeding
  `saturation` covers the actual failure mode.
- **Console** — no new page. `reply_from`/`reply_timeout` are non-secret, so `/metadata` renders them in full,
  and the message-detail `GET /messages/{id}/responses` already shows the captured reply that *became* the
  HTTP body.

### What this must not break

- **One-way dependency (CLAUDE.md §4).** No `api/` import enters `transports/`, and none enters `pipeline/`.
  The blocking wait is a runner-injected awaitable; the rate limiter is injected as a synchronous predicate;
  the credential comparison and the cert→principal mapping move to a neutral package-root leaf
  (`messagefoundry/credential.py`, the [`netaddr.py`](../../messagefoundry/netaddr.py) precedent) rather than
  being imported out of `api/security.py`. `transports/` also gains no `store/` or `pipeline/` import — clean
  today but **unguarded**, so this ADR extends the dependency-boundary test with a `transports/`-scoped arm.
- **ACK-on-receipt (ADR 0001, CLAUDE.md §2).** The block happens strictly **after** the ingress commit,
  enforced structurally, because the resolver's only argument is the `message_id` that `enqueue_ingress`
  returns.
- **Count-and-log (CLAUDE.md §2).** Nothing is accepted-and-dropped on any path. A `504`, a `202` fallback, a
  `502`, or a cancelled wait all leave a committed message that keeps flowing and is dispositioned by the
  finalizer + AlertSink. **The HTTP status is never a second disposition channel.** The two refusals are
  of *different* kinds and both are sound: the intake-auth refusal is **pre-ingress** — it accepts nothing,
  so there is nothing to count — while the `422` on a `None` handler return is **post-record**, where the
  message has already been persisted with status `ERROR` and is therefore counted. The rate limiter's
  read-only consultation, and its global arm never refusing an already-authenticated peer, are what keep
  the pre-ingress refusal from silently swallowing authenticated traffic.
- **At-least-once + re-run purity (ADR 0001/0013).** No Router or Handler sees the reply; nothing derived from
  it feeds any stage. Only a **committed** `response` row is ever returned. No new `Stage` value, no
  stage-aware primitive touched, no second writer on any `(stage, lane)`, and no store transaction held
  across the HTTP turn *between* polls. The capture XOR (`mark_done` **or** `complete_with_response`, one
  transaction, all three backends) is untouched, and the notify cannot raise into it.
- **The wait loop never does disposition math.** It reads the message's own status and the `reply_from` rows'
  own states; it never infers a disposition from which *other* destinations' rows have appeared. The
  finalizer remains the single disposition authority.
- **PHI (CLAUDE.md §9).** The returned body is the partner's reply decrypted out of the encrypted `response`
  table — it is PHI. **Structural rule, not a redaction promise:** reply-derived bytes are never passed to
  any exception, log call, `connection_event.reason`, or `message_events.detail`; the resolver returns an
  `InboundReply` and the listener may report only the *outcome enum*, `dest`, `seq` and `waited_ms`. This is
  deliberately stronger than "route it through `safe_exc`", because `safe_exc`/`safe_text` is an
  **HL7-shaped** redactor — its patterns are HL7 segment runs, `| ^ ~ &` density, date runs and
  capitalised-name runs — and this ADR's new payload class is JSON/SOAP-XML/FHIR, which matches none of them.
  A Salesforce error body is only *partially* redacted — `safe_text`'s date-run and capitalised-name-run
  patterns are content-shaped and do fire inside JSON, but its HL7-structural patterns cannot, so
  identifiers such as an MRN in a JSON field pass through. Partial redaction is not a PHI control, which
  is why the rule here is structural rather than a reliance on scrubbing. Refusal and timeout bodies
  stay fixed non-PHI JSON. Captured headers stay opt-in **by name** via `capture_response_headers`. No
  credential material — not a prefix, not a length — enters a log, a `connection_event.reason`, or an audit
  `detail`.
- **No new web-framework dependency (ADR 0023 D1, ADR 0003 §4, CLAUDE.md §12).** Everything here is stdlib:
  `asyncio`, `hmac`, `hashlib`, `ssl`, `re`. No FastAPI, no uvicorn, no aiohttp, no `httpx`, no new
  `pyproject.toml` entry, no re-lock.
- **The ADR 0002 exposed gate.** `check_http_tls_exposure` is unchanged and unweakened. Intake auth is a
  **second, orthogonal** gate; neither may be used to argue the other away. The new gate is posture-keyed and
  refuses to read `--allow-insecure-bind`. Loopback binds start byte-identical.
- **HA active/passive.** Under HA the graph runs on the leader only, so listener and capturing worker are the
  same process by construction. A demotion mid-block writes a `503` + `Retry-After` **through the pre-close
  drain phase** (D5) — **never** a `504`. `leader_gate` stays ignored and `polls_shared_resource` stays
  `False`.
- **Windows teardown discipline (#55).** `stop()` keeps close-listener → drain-blocked-waiters →
  actively-close-established-clients → bounded `wait_closed()`, all inside `_CLIENT_SHUTDOWN_GRACE`. A blocked
  wait is a plain cancellable task with no lock, so it cancels cleanly; the rendezvous is drained on stop so
  no waiter outlives the source. `_respond` in fact *gains* a bound it lacks today.
- **ADR 0031 per-connection fault isolation.** Every new refusal raises `WiringError`/`ValueError` at start
  and degrades **that one connection**, never the engine.

## Acceptance Criteria

> EARS form; each linked (`→`) to its test/fixture. `messagefoundry adr-analyze` checks each `→` resolves.
> The sync-reply tests land in `tests/test_inbound_http_sync_reply.py` and the intake-auth tests in
> `tests/test_inbound_http_intake_auth.py` — deliberately **not** `tests/test_http_auth.py`, which is the
> existing *outbound* OAuth2/Digest suite, and not `tests/test_inbound_http_source.py`, which pins the
> shipped `202` slice.

- **AC-1** — WHERE an inbound HTTP listener declares `reply_from`, WHEN a peer POSTs a body, THE SYSTEM SHALL
  commit the body to the **ingress** stage **before** it begins waiting, and SHALL return the downstream
  partner's reply only from a `response` row that `complete_with_response` has already committed.
  → `tests/test_inbound_http_sync_reply.py::test_reply_body_is_the_committed_response_row`
- **AC-2** — WHEN more than one captured reply exists for a message, THE SYSTEM SHALL select the highest
  `response_seq` for `destination_name == reply_from` with `kind == "response"`, and SHALL NOT return an
  ADR 0021 `ack_sent` row or another destination's reply.
  → `tests/test_inbound_http_sync_reply.py::test_selects_latest_seq_for_reply_from_and_ignores_ack_sent`
- **AC-3** — IF the wait exceeds `reply_timeout`, THEN THE SYSTEM SHALL return `504` (or `202` when
  `reply_on_timeout="202"`) AND SHALL leave the message committed and still flowing, with its disposition
  decided only by the finalizer — the HTTP status SHALL NOT act as a disposition.
  → `tests/test_inbound_http_sync_reply.py::test_timeout_returns_504_and_message_keeps_flowing`
- **AC-4** — IF the `reply_from` outbound row reaches `dead` or `cancelled`, THEN THE SYSTEM SHALL fail the
  HTTP turn immediately; AND IF the router produces `UNROUTED`, THE SYSTEM SHALL fail immediately from the
  **router** worker; AND IF the transform stage produces `FILTERED` or `NOT_DEPLOYED`, THE SYSTEM SHALL fail
  immediately from the **transform** worker — not after `reply_timeout`.
  → `tests/test_inbound_http_sync_reply.py::test_terminal_states_fail_fast_at_the_correct_stage`
- **AC-5** — WHERE the in-process rendezvous signal never fires (an engine shard owns the capturing outbound
  lane), THE SYSTEM SHALL still return the committed reply by polling the store, differing only in latency.
  → `tests/test_inbound_http_sync_reply.py::test_reply_returned_without_any_in_process_signal`
- **AC-6** — WHEN a message routed to **two or more handlers** has its non-`reply_from` handler transform
  first, THE SYSTEM SHALL continue waiting rather than concluding the message was excluded, and SHALL return
  the `reply_from` reply once it commits.
  → `tests/test_inbound_http_sync_reply.py::test_multi_handler_sibling_row_does_not_fail_the_wait`
- **AC-7** — WHEN a `reply_from` inbound is wired against an outbound that is absent, not deployed, lacks
  `capture_response=True`, resolves to an **effective** `ordering` of FIFO, or resolves to an **effective**
  `max_attempts` of `None`; OR WHEN it declares `ack_after=DELIVERED`; OR WHEN `intake_auth="mtls_subject"`
  is set without `tls`+`tls_ca_file`+a non-empty `intake_client_subjects`, or `intake_auth` is `api_key`/
  `bearer` without a configured `intake_api_key` — THE SYSTEM SHALL refuse at `messagefoundry check`
  **with no store**, isolating that connection (ADR 0031) without crashing the engine. The `ordering` and
  `max_attempts` arms SHALL be evaluated on the resolved `[delivery]` values, not on the declared
  (`None` = inherit) fields.
  → `tests/test_inbound_http_sync_reply.py::test_reply_from_offline_validation_refuses`
  → `tests/test_inbound_http_intake_auth.py::test_intake_auth_offline_validation_refuses`
- **AC-8** — THE SYSTEM SHALL leave every inbound without `reply_from` unchanged in response body and status
  semantics: the same `202` receipt, the same `InboundHandler` contract, and no new store read on that path.
  → `tests/test_inbound_http_source.py::test_respond_with_receipt_on_ingress`
- **AC-9** — WHILE a reply is being returned, THE SYSTEM SHALL NOT log the reply body at INFO or above nor
  place it in any exception, `connection_event.reason` or `message_events.detail`, SHALL bound the response
  drain by `reply_write_timeout`, and SHALL reject a captured `Content-Type` containing CR or LF **inside
  `build_response`** rather than emitting it into the header block.
  → `tests/test_inbound_http_sync_reply.py::test_reply_body_never_logged_and_content_type_is_validated`
- **AC-10** — WHEN the listener is stopped while a request is blocked on a downstream reply, THE SYSTEM SHALL
  wake the waiter, write a `503` + `Retry-After` **through the still-open writer**, and complete teardown
  inside the bounded shutdown grace without hanging (the #55 Windows discipline).
  → `tests/test_inbound_http_sync_reply.py::test_stop_drains_blocked_wait_with_503_within_grace`
- **AC-11** — WHERE `intake_auth` is set, IF a request presents a missing, empty or incorrect credential,
  THEN THE SYSTEM SHALL refuse with `401` **before any request body byte is read** and before any ingress row
  is written, using an identical response for missing and wrong, and SHALL compare in constant time without
  raising on a non-ASCII credential.
  → `tests/test_inbound_http_intake_auth.py::test_missing_wrong_and_empty_credentials_are_indistinguishable_401`
- **AC-12** — WHERE `intake_api_key_next` is **unset**, WHEN a peer presents no credential, THE SYSTEM SHALL
  refuse with `401`; AND WHERE `intake_api_key_next` is set, WHEN a peer presents either the current or the
  next key, THE SYSTEM SHALL accept it, so a partner key rotates without an outage.
  → `tests/test_inbound_http_intake_auth.py::test_absent_credential_401_and_dual_key_rotation_accepts_both`
- **AC-13** — WHERE `intake_auth` is set, WHEN a peer sends N successful authenticated requests exceeding
  `intake_auth_rate_limit` within the window, THE SYSTEM SHALL accept all of them — the budget SHALL be
  charged only on failed attempts.
  → `tests/test_inbound_http_intake_auth.py::test_successful_auth_never_consumes_rate_budget`
- **AC-14** — WHERE `intake_auth="mtls_subject"`, IF a client presents a certificate valid for the configured
  CA whose subject/SAN is not in `intake_client_subjects`, THEN THE SYSTEM SHALL refuse with `403`
  (deny-by-default), distinct from the `401` authentication refusal.
  → `tests/test_inbound_http_intake_auth.py::test_valid_chain_unlisted_subject_is_403`
- **AC-15** — WHEN an intake-auth refusal occurs, THE SYSTEM SHALL write a tamper-evident `audit_log` row
  carrying the peer address and SHALL NOT place the credential, any prefix of it, or its length into any log,
  `connection_event.reason`, or audit `detail`.
  → `tests/test_inbound_http_intake_auth.py::test_auth_failure_audited_without_credential_material`
- **AC-16** — WHERE an HTTP listener binds off-loopback with no **effective** peer control (no sufficiently
  narrow `source_ip_allowlist`, no `intake_auth`, and no `mtls_subject` binding), THE SYSTEM SHALL refuse at
  start under an enforcing PHI posture and warn otherwise, independently of `check_http_tls_exposure` and
  without consulting `--allow-insecure-bind`; a bare `tls`+`tls_ca_file` SHALL NOT satisfy the gate; a
  loopback bind SHALL start unchanged.
  → `tests/test_inbound_http_intake_auth.py::test_offloopback_without_effective_peer_control_refused_by_posture`
- **AC-17** — THE SYSTEM SHALL add **no** `api/` import to `transports/`, **no** `store/` or `pipeline/`
  import to `transports/`, and **no** new web-framework dependency; the sync-reply and intake-auth paths SHALL
  resolve through `build_source`/the injected attributes with no `pipeline/` special-casing beyond the existing
  `ConnectorType.HTTP` handler switch.
  → `tests/test_dependency_boundaries.py::test_engine_packages_never_import_api_console_or_gui`
  (extended with a `transports/`-scoped arm)
- **AC-18** — WHEN a sync reply returns or times out, THE SYSTEM SHALL write the matching `message_events`
  row (`reply_returned` / `reply_timeout`) through the new `record_message_event` store method on all
  three backends AND increment the labelled metric, carrying names, counts and `waited_ms` only and **no
  fragment of the reply body**; AND the `reply_timeout` kind SHALL be present in the audit-floor event set
  with its `docs/PHI.md` §7 row.
  → `tests/test_inbound_http_sync_reply.py::test_reply_events_and_metrics_carry_no_body`
  → `tests/test_phi_logging_inventory.py`
- **AC-19** — WHERE `intake_auth` is set, WHEN an unauthenticated peer exhausts the global failed-attempt
  budget, THE SYSTEM SHALL continue to accept requests from a peer that has already authenticated
  successfully within the window — a global rate-limit trip SHALL NOT refuse an authenticated partner.
  → `tests/test_inbound_http_intake_auth.py::test_global_limit_trip_does_not_deny_authenticated_peer`

## Options considered

1. **Committed-row-authoritative wait: an injected `SyncReplyResolver` taking the committed `message_id`,
   polling a metadata-only state read with an in-process rendezvous as a pure latency hint, plus intake auth as
   a per-inbound peer control behind a separate posture-keyed gate. CHOSEN.** It is correct under every
   engine-shard, HA, claim-mode and race configuration because the store is the authority; it adds no `Stage`
   and no schema change; it keeps the wire decision in the source connector per ADR 0004 §6; and it closes the
   unauthenticated-off-loopback-intake hole without touching the confidentiality gate. It costs two additive
   store read/write methods, which this revision states rather than denies.
2. **An in-process `asyncio.Future` keyed by `message_id`, carrying the reply payload, as the authority.**
   Rejected: correct only when the capturing outbound lane happens to be owned by the listener's engine shard.
   ADR 0073 hashes lane ownership and `_wake_lane` already documents dropping cross-shard wakes. Carrying the
   payload in the signal also puts an uncommitted value one bug away from the wire.
3. **Poll-only, with no in-process signal at all.** Rejected as the *shipped* shape, not as incorrect: it is
   the fallback path here, but on its own it pays full poll latency on every reply and a full `reply_timeout`
   on every misroute.
4. **Return the `DeliveryResponse` straight out of `send()` before `complete_with_response` commits.**
   Rejected: it is exactly ADR 0013's forbidden "a reply being produced in the same run", and ADR 0023 §D3
   names it explicitly — *"a blocked-and-returned reply must be the **committed** captured one, never a
   not-yet-sent one"*.
5. **Route the captured reply back as a new inbound message (ADR 0013 Increment 2 re-ingress).** Rejected:
   ADR 0023 §D3 forbids it in terms, twice. Increment 2 *is* built, and its availability does not repeal the
   constraint.
6. **Build `ack_after=delivered` as the general mechanism and let HTTP be its first user.** Rejected for this
   increment: `AckAfter.DELIVERED` governs *when the engine's own receipt is sent*, for every transport; this
   defers *a different artifact*, per-inbound, HTTP-only, and bounded. `ReplyRendezvous` is deliberately
   transport-agnostic so that work can reuse it.
7. **A new `ConnectorType` (or a per-facade socket) for the synchronous listener.** Rejected: ADR 0016 §Q6
   shows a new type silently skips the egress arm that gates the existing one, and ADR 0023 Option 5 already
   rejected per-facade sockets.
8. **Terminate intake auth only at the WP-15 reverse proxy.** Rejected as the *only* answer: it is a valid
   deployment and stays supported, but the prospect **is** the proxy, and an engine that cannot
   authenticate its own PHI intake socket has no answer for the direct-bind case.
9. **Intake auth as a constructor `ValueError` (the `DicomScpSource` shape).** Rejected for the *gate*, not the
   idea — but on narrower grounds than revision 1 claimed. The constructor form **does** fire at
   `messagefoundry check`; what it cannot do is key off posture (warn on a lab box, refuse on production PHI)
   or be unit-tested without a bind, and an unconditional refusal would break existing off-loopback
   `Http(tls=True)` deployments on upgrade. D7 recovers the lost check-time coverage with a parallel offline
   arm.
10. **Reuse the admin `auth/` plane (sessions, `Identity`, `Permission`, RBAC) for intake.** Rejected: ADR 0023
    §D4.3 requires the two be distinct, `transports/` may not import `auth/` or `api/`, and an intake principal
    that could be mistaken for an operator identity is a privilege-escalation shape.
11. **Relay the partner's HTTP status code by parsing `DeliveryResponse.detail`.** Rejected: `detail` is an
    untyped free-text display field, so making it load-bearing would break the moment its formatting changed.
    A typed `status_code` is increment 2.
12. **Use the ADR 0057 inline Step-A fast path to do routing and delivery inside the HTTP turn.** Rejected:
    it carries a ⛔ DO NOT PROMOTE banner, ships permanently default-OFF at a measured +0 % throughput, and its
    gate requires `AckAfter.INGEST`.

## Consequences

**Positive** — Increment A closes a live hole on its own schedule: an off-loopback `Http(tls=True)` listener
authenticates nobody today, and the peer-control gate plus `intake_auth` fix that whether or not the
proxy-API prospect ever signs. Increment B then makes the proxy-API shape expressible: a partner calls an
authenticated MessageFoundry endpoint and receives the downstream system's answer in the same HTTP turn,
with the whole exchange counted, logged, dispositioned, and stored exactly like every other message. It closes both of ADR 0023's named
deferrals and two of its eight open items, and it retires the "†" deferral paragraph in
[`docs/CONNECTIONS.md`](../CONNECTIONS.md). It adds **no** `Stage` value and no schema change — the reply
rides `correlate_response` as it ships, at parity on SQLite, PostgreSQL and SQL Server. Because the committed
row is authoritative, the feature is correct under engine sharding, HA failover, both claim modes and signal
races. Intake auth closes a real, currently-live hole — an off-loopback `Http(tls=True)` listener has no peer
identity requirement today, and a shipped test pins that configuration as passing — gives mTLS an actual
authorization decision, supports outage-free key rotation, and auto-enrols its secrets in the existing
rotation inventory. Three incidental defects get fixed on the way: the malformed `HTTP/1.1 503 OK` status
line, the unbounded success-path drain, and the missing `TCP_NODELAY`.

**Negative / risks** — A blocked request holds one of `max_connections` (256) slots and one asyncio task for
its whole life. The real throughput envelope is
`min(lane_concurrency, f(read_pool_size, poll_period), max_connections)` — narrower than
`max_connections × reply_timeout`, and on SQLite the four-connection read pool is shared with the admin API,
console, retention and alert sweeps, so a large waiter population is a store-load question, not only a socket
question. The **caller's view and the engine's view diverge**: a caller told `504` may still have their
non-idempotent POST delivered minutes later, and a caller retry mints a **new `message_id`** and a **second
downstream call** the engine cannot deduplicate (that needs a partner-side idempotency key). The ADR 0013
crash window is **inherited, not closed**. `build_response`'s "no PHI in a response body" property is
genuinely retired for the reply path, and the existing `safe_exc` redactor does **not** cover the new payload
class — which is why the PHI rule here is structural (never pass reply bytes to a log/exception) rather than
a redaction promise. Intake auth introduces the engine's first credential verification outside `auth/`, so
the empty-credential precondition, the constant-time comparison, the non-ASCII guard, and the no-oracle
refusal must be right; its rate limiter is in-process and per-shard (N × limit for N shards), and it requires
an additive `would_allow` on `SlidingWindowRateLimiter`. Enabling `intake_auth` **breaks existing
load-balancer health checks** by default. The new peer-control gate can refuse a configuration that starts
today, so it warns outside an enforcing PHI posture — and it deliberately no longer accepts a bare
`tls_ca_file` as a peer control, which is a second upgrade-path consideration. Three pre-existing listener
gaps will be blamed on this work unless named up front: `Expect: 100-continue` is unhandled (.NET/SOAP stacks
— exactly the prospect profile — stall to a `408`), `max_header_bytes` above 64 KiB is not honoured because
`asyncio.start_server` is called without `limit=`, and chunked request bodies are refused (a literal
`Transfer-Encoding: chunked` is rejected, though a legal `gzip, chunked` falls through to a read-to-EOF —
worth its own look, as that asymmetry is a request-smuggling shape).

**Out of scope / deferred** — **Relaying the partner's error body and status code.** `RestDestination`
captures only `accepted`/`no_reply`; a partner 4xx raises `NegativeAckError(permanent=True)`, dead-letters,
and writes **no** `response` row — so a Salesforce validation message cannot reach the caller in increment 1
(they get a fixed-JSON `502`). **With no committed customer this is a documented limitation rather than a blocker** (rev 4; it would be a serious gap for a live proxy API, and increment B is deferred until one exists): a
proxy API that is correct only when the partner succeeds is not a Corepoint replacement for that feed. Full
parity needs an outbound-side `capture_error_responses` knob plus a typed `DeliveryResponse.status_code` and
an additive nullable `response.status_code` column, as an ADR 0013 amendment. **ADR 0013 Increment 2
re-ingress** — untouched and still forbidden here. **`ack_after=delivered`** stays planned-not-built.
**Routing metadata** stays open: increment 1's shape is **one `Http()` inbound per proxied endpoint**.
**Fan-out semantics** for a message routed to several capturing outbounds beyond "name one in `reply_from`" —
note that D3 now tolerates sibling handlers correctly, but multiple rows sharing `destination_name ==
reply_from` (two handlers both sending to it, or a `resend_to`) still resolve to "highest `response_seq`
wins", which is defined but not designed. **Keep-alive / connection reuse** — `Connection: close` stays
hardcoded. **`SecretProvider`/Vault for connector secrets.** **Serving a WSDL.** **The `#20` inbound FHIR
facade and `#24` DICOMweb receiver.** **Reconciling the five `_LOOPBACK_HOSTS` copies** — the new gate picks
the CIDR-aware predicate; the others are left as found.

## To resolve on acceptance

> Revision 1's thirteen questions are **answered** below, with the evidence that decided each. What remains
> open is listed after them, and is materially different from what revision 1 thought it was unsure about.

**Answered in this revision:**

1. **Relaying the partner's error body — does it block? NO, because there is nobody to block.** The
   dead-row premise is verified in both halves: a partner 4xx raises `NegativeAckError(permanent=True)`,
   dead-letters, and writes no `response` row, so the caller gets fixed JSON rather than the partner's
   message. For a *live* proxy API that would be a serious gap, since a partner validation error is a
   routine business outcome rather than an exception. **But the owner confirmed there is no committed
   customer** (rev 4), so this is a documented limitation, not a broken promise. `capture_error_responses`
   becomes an ordinary roadmap item, best designed against a real partner's error semantics rather than
   guessed at now. Revisions 1–3 answered this "YES, it blocks the migration"; that answer was built on a
   migration that does not exist.
2. **Health probes inside the gate — confirmed `require`.** Verified shipped behaviour: GET/HEAD return a
   static non-PHI `200` with no ingress row. It ships as a **documented breaking change**, not a footnote.
3. **`sync_reply_degraded` AlertSink reason — do not add one; reuse `saturation`.** The deferral was right,
   the reason was wrong: `queue_buildup`/`message_stall` fire on lane backlog and can stay silent while the
   listener saturates.
4. **The `422` on a `None` handler return — confirmed**, and moved out of the outcome table, since it fires
   before the resolver exists.
5. **`204` for a captured `no_reply` — confirmed**, with a `reply_on_empty` escape hatch, because the ADR's
   own forcing profile (.NET/SOAP toolchains) is the population most likely to mishandle a bodyless `204`.
6. **Finite `max_attempts` — REFUSE, not warn; and `ordering=FIFO` must also refuse.** This reverses
   revision 1. FIFO is the default, drains serially and blocks the head on failure; `max_attempts=None` is
   the default and retries forever. Together they make N concurrent callers queue behind one lane and let a
   single stuck message time out every caller until an operator intervenes.
7. **Cross-shard `reply_from` — confirmed warn, never refuse.** The store-authoritative poll is genuinely
   correct cross-shard. The warning now names the **read-pool** cost, not just latency.
8. **Inbound analogue of `refuse_cleartext_credential_hop` — ADD it.** The function is real, posture-keyed,
   already reused by `soap.py`/`smart.py`, and lives in `transports/`, so the mirror needs no new import
   edge. Guarding credentials leaving but not arriving is the harder position to defend.
9. **`intake_auth_rate_limit` — 10/min/peer confirmed as the *failed-attempt* budget**, matching the shipped
   `login_rate_limit_per_ip`. Requires the additive read-only `would_allow`, and a **global** arm mirroring
   `login_rate_limit_global = 60`. Per-shard counting accepted, stated as N × limit.
10. **`_LOOPBACK_HOSTS` drift — reconcile separately**, but the premise is corrected: **five** copies across
    **three** content variants, not three and two. Separately, `tests/test_security_posture_defaults.py`'s
    completeness floor cannot fire for a per-inbound connector deviation and must be extended here.
11. **Repair ADR 0023's dangling links — in this commit.** Both filenames are genuinely absent. Counts
    corrected: ADR 0023 has **eight** open items, and the split is **seven** arrows naming
    `tests/test_http_source.py` plus **one** naming `tests/test_architecture_layers.py`.
12. **ADR 0013's and ADR 0021's stale headers — amend both in this commit.** And a third staleness matters
    more: ADR 0021 documents its `connection_event` log as OFF-by-default while the **shipped default is
    ON**, which is what falsified revision 1's D6 audit rationale.
13. **Docs to update on build** — as listed, plus: any `BACKLOG.md` edit must carry a valid status banner or
    `tests/test_backlog_status_check.py` fails, so retiring BACKLOG #7's deferred tail is not a trivial doc
    touch-up.

**All resolved as of rev 5 — see the header note for the through-line.**

- [x] **Sequencing `capture_error_responses`.** ~~Blocking prerequisite, or fast-follow?~~ **rev 4:**
  neither. With no committed customer it is a normal roadmap item, and increment B — where it would land —
  is itself deferred until a customer exists. Revisit when one does.
- [x] **The `reply_wait_state` read — YES, add it.** `outbox_for` is `SELECT *`, decrypts `last_error` on
  every tick, and is scoped to `stage='outbound'` so it structurally cannot see a pending `routed` row —
  the state D3 must distinguish. A metadata-only read on three backends is additive, touches no schema,
  and there is no installed base for a new store method to disturb.
- [x] **`record_message_event` as a public store method — YES, add it.** `_event` is private with no public
  writer on the `QueueStore` protocol, so `reply_timeout` — the row this ADR calls its single most valuable
  diagnostic — is otherwise unwritable from `pipeline/`. Dropping to `connection_event` alone would trade a
  tamper-evident, operator-undisableable record for a diagnostics stream an operator can switch off.
- [x] **The peer-control strength floor — `/8` IPv4, `/32` IPv6, and REFUSE rather than warn.** The floor
  stands on its merits, not on compatibility: `10.0.0.0/8` is a legitimate private-network scope and
  refusing it would be wrong, while `0.0.0.0/0` and `::/0` are excluded. A bare `tls`+`tls_ca_file` does
  not satisfy the gate and is refused under an enforcing PHI posture like any other ineffective control —
  see D7. There is nothing deployed to break.
- [x] **`would_allow` on `SlidingWindowRateLimiter` — YES, add it.** The shipped `allow()` is
  check-**and**-record with no read-only peek, so a pre-comparison consultation charges every request and
  turns the failed-attempt budget into a throughput cap. Reshaping the intake path around the mutating
  `allow` instead would mean charging successful authentications, which is the defect, not a workaround
  for it.
- [x] **Multiple rows sharing `destination_name == reply_from` — REFUSE the configuration.** "Highest
  `response_seq` wins" is defined but not designed, and silently picking one of two captured replies to
  return to a caller is the kind of ambiguity that produces an unreproducible support ticket. Refuse at
  check time (two handlers both sending to `reply_from`, or a `resend_to` targeting it) and revisit only
  with a real fan-out requirement. Nothing is deployed that this refusal could break.
- [x] **The `gzip, chunked` read-to-EOF asymmetry — filed separately.** Verified against the source and
  raised as engine issue **#98**: the check tests `transfer-encoding` for exact equality with `"chunked"`,
  so a legal multi-token value falls through to `_read_to_eof`. It is a pre-existing listener defect
  unrelated to this design, and gating it behind an ADR still in Proposed would delay a real fix. The two
  remaining pre-existing gaps this ADR names — `Expect: 100-continue`, and `max_header_bytes` above 64 KiB
  not honoured because `asyncio.start_server` is called without `limit=` — are recorded in #98 and remain
  unfiled.

**Nothing in this ADR now awaits an answer.** It was ready for the owner to accept or reject, and the
owner ratified it at revision 5 — the status line above records that. (This paragraph previously ended
"the status line stays **Proposed** because ratification is the owner's, not the author's", which was
true when it was written at revision 4 and contradicted the header from revision 5 onward.)
