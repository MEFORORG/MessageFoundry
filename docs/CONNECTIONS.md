# Connections — naming convention & settings

A **Connection** is an endpoint that *receives* (inbound) or *sends* (outbound) messages. This doc
defines how connections are **named** and what **settings** each kind supports today, with a
Mirth/NextGen Connect parity reference for what's planned.

## Naming formula

```
[CONNECTION TYPE]_[PARTNER]_[MESSAGE TYPE]
```

- **CONNECTION TYPE** — the transport + direction code (table below).
- **PARTNER** — the trading partner / system on the other end (e.g. `ACME`, `Epic`, `Test`).
- **MESSAGE TYPE** — the HL7 message code carried (`ADT`, `ORM`, `ORU`, `SIU`, `DFT`, `MDM`, `VXU`, …),
  or `MIXED` / `ALL` when a connection isn't message‑type‑specific.

Example: **`IB_ACME_ADT`** = inbound MLLP from ACME carrying ADT. The shipped sample uses partner
`Test`: **`IB_Test_ADT`** (inbound MLLP) → **`FILE-OUT_Test_ADT`** (outbound file).

### Connection‑type codes

The **Built?** column is read off the **connector registry** — the `register_source` /
`register_destination` calls in [`transports/`](../messagefoundry/transports/) — not maintained by hand.
**Seventeen** connector types are registered today (`ConnectorType`,
[config/models.py](../messagefoundry/config/models.py)): MLLP, TCP, HTTP, FILE, REMOTEFILE, X12,
DATABASE, REST, SOAP, FHIR, DIMSE, DICOMWEB, EMAIL, DIRECT, TIMER, LOOPBACK, PT. Every one of them has a
settings section under [*Settings*](#settings--whats-supported-today) below.

| Code | Direction | Transport | Mirth equivalent | Built? |
|------|-----------|-----------|------------------|--------|
| `IB` | inbound | MLLP listener | MLLP/TCP Listener | ✅ |
| `OB` | outbound | MLLP sender | MLLP/TCP Sender | ✅ |
| `IBC` | inbound | MLLP listener (low/intermittent traffic) | — | ✅ * |
| `OBC` | outbound | MLLP sender (persistent link) | — | ✅ * |
| `FILE-IN` | inbound | folder poll | File Reader | ✅ |
| `FILE-OUT` | outbound | folder write | File Writer | ✅ |
| `TCP-IN` | inbound | raw TCP listener (configurable framing) | TCP Listener | ✅ |
| `TCP-OUT` | outbound | raw TCP sender (configurable framing) | TCP Sender | ✅ |
| `X12-IN` | inbound | raw TCP listener, ISA/IEA-framed X12 EDI | TCP Listener (X12) | ✅ |
| `X12-OUT` | outbound | raw TCP sender, X12 EDI (verbatim) | TCP Sender (X12) | ✅ |
| `SFTP-IN` | inbound | SFTP poll | File Reader (SFTP scheme) | ✅ (`Sftp()`, `[sftp]` extra) |
| `SFTP-OUT` | outbound | SFTP write | File Writer (SFTP scheme) | ✅ (`Sftp()`, `[sftp]` extra) |
| `FTP-IN` | inbound | FTP / FTPS poll | File Reader (FTP scheme) | ✅ (`Ftp()`, stdlib) |
| `FTP-OUT` | outbound | FTP / FTPS write | File Writer (FTP scheme) | ✅ (`Ftp()`, stdlib) |
| `SOAP-IN` | inbound | SOAP endpoint | Web Service Listener | ~ receive-only † |
| `SOAP-OUT` | outbound | SOAP client | Web Service Sender | ✅ |
| `REST-IN` | inbound | HTTP endpoint | HTTP Listener | ✅ (`Http()`, ADR 0023) † |
| `REST-OUT` | outbound | HTTP client | HTTP Sender | ✅ |
| `DB-IN` | inbound | DB poll | Database Reader | ✅ (SQL Server + generic ODBC) |
| `DB-OUT` | outbound | DB write | Database Writer | ✅ (SQL Server + generic ODBC) |
| `FHIR-IN` | inbound | FHIR REST endpoint (server facade) | (FHIR Listener) | ⏳ planned (BACKLOG #20) |
| `FHIR-OUT` | outbound | FHIR REST client | (FHIR Sender) | ✅ |
| `DICOM-IN` | inbound | DICOM C-STORE SCP listener | DICOM Listener | ✅ (ADR 0025 Phase 1) |
| `DICOM-OUT` | outbound | DICOM C-STORE SCU + C-ECHO sender | DICOM Sender | ✅ (ADR 0025 Phase 2) |
| `DICOMWEB-OUT` | outbound | DICOMweb STOW-RS store/send | (DICOMweb Sender) | ✅ (ADR 0025 Phase 2) |
| `SMTP-OUT` | outbound | SMTP email send | SMTP Sender | ✅ (`Email()`/`SMTP()`, ADR 0029) |
| `DIRECT-OUT` | outbound | Direct-Project S/MIME over SMTP | — | ✅ (ADR 0085, outbound only) |
| `TIMER-IN` | inbound | clock-driven source (interval / cron) | — | ✅ (ADR 0011) |
| `LOOP-IN` · `PT-*` | inbound | internal re-ingress — a captured reply (`Loopback()`) / a pass-through hop (`PassThrough()`) | Channel Reader | ✅ (ADR 0013) |
| `JMS-IN` / `JMS-OUT` | in/out | JMS queue consumer/producer | JMS Listener/Sender | ⏳ planned |
| `MAIL-IN` | inbound | POP3/IMAP mailbox poll | Email Reader | ⏳ planned |

\* **`IBC`/`OBC`** use the *same* MLLP transport as `IB`/`OB`; the `C` is a **monitoring hint**: for
these, "waiting for connection" is the *normal, healthy* state (a low‑traffic feed or a persistent
link that idles), so the Monitor shouldn't flag them. (The Monitor health rule that honors this is not
yet implemented — the suffix documents intent today.)

† **`REST-IN`** and **`SOAP-IN`** (non-HL7 inbound *sources*). The two halves these rows once awaited are
both built now: the **payload-agnostic ingress** contract ([ADR 0004](adr/0004-payload-agnostic-ingress.md) —
an inbound's `content_type` selects the HL7 path vs. a `RawMessage` route) *and* the **inbound HTTP
listener** it needed ([ADR 0023](adr/0023-inbound-http-listener.md) — `Http(...)`, below), so a partner
can `POST` a JSON / XML / SOAP-envelope / FHIR body today and a Handler un-wraps it. **Request
authentication on the intake socket has since shipped** ([ADR 0154](adr/0154-synchronous-captured-downstream-reply-and-intake-authentication-for-the-inbound-http-listener-adr-0023-deferred-tail.md)
increment A): `intake_auth` — API key, bearer or mTLS subject — now joins the per-connection IP
allowlist, TLS/mTLS and the off-loopback exposed gate as a peer control. The **SOAP-specific** half of
`SOAP-IN` — the *synchronous* envelope reply — shipped with increment B (`reply_from`: the HTTP turn
blocks on the named outbound's captured, committed reply). Routing on HTTP method/path/headers remains
deferred (the Handler sees the body). For this listener's current state, settings and remaining gaps,
[`Http(...)`](#http-web-service-listener--http-inbound-only-adr-0023) below is the single authority —
this note is a pointer, not a second copy of that status.

## Authoring a connection

Connections are declared in a config module (see [samples/config/adt.py](../samples/config/adt.py)).
Worked example for **`IB_ACME_ADT`**:

```python
from messagefoundry import MLLP, Send, handler, inbound, outbound, router

inbound("IB_ACME_ADT", MLLP(port=2576), router="acme_adt_router")  # listens on [inbound].bind_host
outbound("OB_EPIC_ADT", MLLP(host="epic-host", port=6661))

@router("acme_adt_router")
def route(msg):
    return ["acme_adt"] if msg["MSH-9.1"] == "ADT" else []   # non-ADT → UNROUTED

@handler("acme_adt")
def handle(msg):
    # filter / transform here
    return Send("OB_EPIC_ADT", msg)
```

> Connection names are plain strings, so hyphens and mixed case (e.g. `FILE-OUT_Test_ADT`) are fine.
> Router/Handler **names** are not connections and don't follow the formula.

### Connections as data — `connections.toml` (ADR 0007)

A connection's **transport config** (type + settings + the inbound's `router` binding + delivery
knobs) may instead live as **data** in an optional `connections.toml` next to the `*.py` modules — so
it can be edited by hand *and* from the VS Code connection editor. **Routing/transform *logic* stays
code-first** (`@router`/`@handler` in `.py`). The loader merges TOML connections into the **same**
registry the factories produce, so the runtime, validation, and egress gating are identical:

```toml
# connections.toml — transport config as data; logic stays in .py.
# Secrets/peers use an env() reference ({ env = "key" }), never inline.
[[inbound]]
name      = "IB_ACME_ADT"
transport = "mllp"
router    = "acme_adt_router"   # binds a router declared in a .py module
bind_address        = "0.0.0.0"                     # optional: override [inbound].bind_host here
source_ip_allowlist = ["10.0.0.0/8", "192.0.2.7"]   # optional: only these peers may connect (MLLP/TCP)
  [inbound.settings]
  port = 2576
  [inbound.metadata]                                # optional operator labels (API-surfaced, not routing)
  owner   = "integration-team"
  runbook = "https://wiki/acme-adt"

[[outbound]]
name      = "OB_EPIC_ADT"
transport = "mllp"
  [outbound.settings]
  host = { env = "epic_host" }            # resolved per environment (environments/<env>.toml)
  port = { env = "epic_port", cast = "int" }
  [outbound.metadata]
  owner = "integration-team"
```

- The `transport` maps to the same factory — eleven are reachable as data (`mllp`/`tcp`/`http`/`file`/
  `timer`/`rest`/`database`/`database_poll`/`soap`/`sftp`/`ftp`) and **the factory is the schema**; at
  least an unknown transport/key/router fails loud at load (`messagefoundry check`), exactly like a bad
  `inbound()` call. The factory's parameter **types** are part of that schema too: a `[settings]` value
  of the wrong kind — `port = "2576"`, `persistent = "yes"` — is refused at load naming the setting and
  the type it wanted. A quoted TOML value is always a string, so write the number or `true`/`false`
  without quotes. An `env()` reference is also accepted, but give it a `cast` for a non-string setting:
  an environment value arrives as text and an **uncast** ref hands the connector that text. An inline
  `default =` is held to the setting's type here, because a default is **not** converted by `cast`.
  **A numeric cap reads the text `"0"` exactly as it reads the number `0`** (BACKLOG #1872): where a
  cap documents `None`/`0` as "disabled" or "unlimited", `"0"` and an empty value disable it too. On
  those caps, and on the pacing rates and bursts, a negative or `nan` is refused at load in either
  spelling. The one cap with no "off", the HTTP listener's `max_header_bytes`, refuses `0` in either
  spelling. Not every numeric setting has the negative refusal yet: at least DICOM `max_pdu_size`,
  `max_associations` and `timeout_seconds` do not.
  A setting whose type is a **table** or an **array** — `headers`, `odbc_params`,
  `capture_response_headers`, `proxy_no_proxy` — is held to its shape, so `headers = 5` is refused;
  where the entries have a readable type it is held to those too, one level in, so
  `headers = { X-Key = 5 }` is refused naming the entry key, and a bad array item is named by index.
  Write an array as `["a", "b"]`; a bare string is not an array, even where one string is all you
  want. The entry check is **not** a guarantee that every value in a table was examined — an `env()`
  reference written inside one is left to the connector's own rules. An `env()` reference written as
  an array **item** is refused at load, in code and in this file, because only a top-level setting
  is resolved: it may stand for a whole array, never for one item of it. (`http`'s
  `intake_client_subjects` refuses a whole-array `env()` too, today.) No refusal ever repeats the
  value — a `[settings]` value can be a credential, and the message reaches the operator log and the
  support bundle.
  The remaining connectors (`X12`/`FHIR`/`DICOM`/`DICOMweb`/`Email`/`Direct`/
  `Loopback`/`PassThrough`) are **code-first only** today — declare them in a `.py` module. A name
  declared in **both** a `.py` module and `connections.toml` is a hard error (no silent shadowing).
- **Edit it two ways, same file:** by hand, or via `messagefoundry connection list|upsert|remove`
  (comment/format-preserving, validate-before-persist with rollback) — which is what the **VS Code
  connection editor** shells (the gear on a data-authored connection opens the form; a code-authored
  one opens its `.py`). `env()` secrets are never written inline.
- **A GUI/CLI save preserves every read-schema field** (#234, 2026-07-16): the write schema is
  derived-and-pinned against the read schema (a parity test guards the drift in CI), so an editor
  save round-trips `schedule`/`shard`/`source_ip_allowlist`/`metadata`/… instead of silently
  stripping them; an **unknown posted key fails loud** per direction, never dropped. Saves stay
  **full-replace** per table (an upsert omitting a key deletes it — deliberate; the IDE forms
  compensate by merging the posted fields over a save-time fresh `connection list`), and the form
  writers **refuse a name collision** — a create/clone saved under an existing connection's name is
  an error, not a silent overwrite (the keyboard-wizard path is the filed residual, BACKLOG #240).

### Decomposing by role (connections / routers / handlers / transforms)

Names resolve **globally** across the config dir — an inbound names its router, a router returns
handler name(s), a handler `Send`s to outbound name(s), all wired by **string**, with no enclosing
"channel" object. So *where* each declaration lives is an authoring choice the engine neither sees nor
cares about: it globs every `*.py` (`_*` skipped) and `connections.toml`, and merges them into **one**
registry. A single feed can therefore be **split by role across separate files** instead of bundled
into one monolithic module.

> **Flat dir, prefixed files.** `load_config` globs `*.py` **non-recursively**, and helpers /
> `connections.toml` / `codesets/` all resolve at the top level — so decomposition means **prefixed
> flat files** (e.g. `IB_400_router.py`), **not** a `feeds/IB_400/` subdirectory (those aren't loaded).

**Recommended for a ported / non-trivial feed — the per-feed "Hybrid" layout.** Split one feed's four
concerns across four artifacts, named after the inbound so they sort and read together:

```
connections.toml            the feed's connections as DATA (transport + the inbound's router binding)
<INBOUND>_router.py         @router    — Corepoint "E Process": decides forwarding (+ filtering)
<INBOUND>_handler.py        @handler   — Corepoint "E Child": filter → delegate → Send (kept THIN)
_<feed>_transforms.py       the field-level transform steps the handler delegates to (a `_`-helper,
                            skipped as a feed but imported by the handler — the loader resolves it)
```

- **Connections → `connections.toml`** puts the transport config (and the inbound `router=` binding)
  on the GUI-/hand-editable data surface (ADR 0007) — or keep them in an `<INBOUND>_conn.py` if you
  prefer all-Python. Either way the *logic* stays code-first.
- **Transforms → a `_`-prefixed helper** keeps the Handler a thin *filter → delegate → Send*; the many
  field manipulations a ported Corepoint child accumulates live in the helper as small, reviewable,
  unit-testable functions rather than a wall of inline code. Shared helpers are imported from siblings
  (the loader skips `_*` as feeds but resolves them as imports).

A **runnable worked example** ships in [`samples/config/`](../samples/config/): `IB_DEMO_ORU` is
authored exactly this way — the connections in [`connections.toml`](../samples/config/connections.toml),
[`IB_DEMO_ORU_router.py`](../samples/config/IB_DEMO_ORU_router.py),
[`IB_DEMO_ORU_handler.py`](../samples/config/IB_DEMO_ORU_handler.py), and
[`_demo_oru_transforms.py`](../samples/config/_demo_oru_transforms.py).

**Alternative — group by area/partner** (fewer files; best when a handler is *shared* across feeds):
put several routers in `routers_<area>.py` and shared handlers in `handlers_<partner>.py` (Corepoint
"E Child" reuse — one handler named by multiple routers). A **trivial** feed (a passthrough with no
real transform) is also fine as a **single module** — the shipped `IB_ACME_ADT.py` /
`IB_RTE_ELIGIBILITY.py` samples show that form; reach for the split when a feed grows a router *and*
non-trivial transform logic.

A **router fans out** by returning multiple handler names (`return ["to_a", "to_b"]`); a **single
handler fans out** by returning multiple `Send`s (`return [Send("OB_A", msg), Send("OB_B", msg)]`) —
a list is the idiom shown throughout these docs, but **any non-`str` iterable** delivers the same
`Send`s (a tuple, a set, or a generator that `yield`s them). An **empty** one (`return []` /
`return ()`) is the filter: nothing is delivered and the message is logged `FILTERED`.

A Handler returns a `Send`, a `SetState`, a `SetMeta`, an iterable of those, or `None` — **and
nothing else**. Returning the message itself, `msg.encode()`, a `dict`, or a `(name, message)` tuple
is an authoring error: the engine raises, naming the handler and the type, and the message is
`ERROR`/dead-lettered and replayable. It is never silently `FILTERED`, which would be
indistinguishable from a Handler that deliberately declined it.
Namespace router/handler names uniquely (e.g. by site/partner) — `messagefoundry check` flags a
duplicate name (across **any** of these files) and an inbound that binds a router that doesn't exist.

> **Prefer a list, tuple or generator — they have an order; a `set` does not.** Fan-out is delivered
> in iteration order, and a `set`'s iteration order is not defined: it varies from process to process
> (`Send` hashes on its fields, and string hashing is seeded per process). Two `Send`s to the **same**
> outbound therefore queue in an arbitrary relative order, and a re-run after a crash — a different
> process — can queue them in a different one, so a `set` gives up both FIFO order between siblings and
> the identical-output-on-re-run property the staged pipeline leans on (CLAUDE.md §2). Which `Send`s
> are delivered is unaffected. **Use an ordered container whenever order matters.**
>
> A **generator** Handler delivers exactly like a list, but its body runs *after* the execution tracer
> behind `dryrun --trace` (and the Test Bench that reads it) has detached. That invocation's trace
> record therefore carries no executed lines and no sends, marked `"lazy_result": true` so the omission
> is declared rather than read as a handler that did nothing; the run's message-level `sends` are still
> exact. Return a list or tuple if you want the handler's body traced line-by-line.

> **Transforms & HL7 escaping.** Writing a **component/subcomponent** (`msg["PID-5.1"] = value`)
> stores `value` as a literal: HL7 delimiters in it (`^ ~ & |`) are **escaped** so they stay data
> (`"O^Brien"` remains one component, not two). To build *multiple* components, write the whole
> field (`msg["PID-5"] = "DOE^JANE"`) — its separators are taken as structure. A value containing a
> segment separator (CR/LF) is **rejected** (it would inject a segment downstream). Reads return the
> unescaped value, so a write→read round-trips. The message's own `MSH-2` encoding characters are
> used throughout, so custom-delimiter messages are handled correctly.

## Settings — what's supported today

> **Read this before you turn TLS on for an *outbound* connection.** The engine performs **no
> certificate revocation checking** — stdlib `ssl` exposes no OCSP/CRL fetch and the engine deliberately
> attempts none — so on the **shipped default** (a PHI-classified instance at
> `[security].enforcement = enforce`) a **verifying** outbound TLS hop to a **non-loopback** host is
> **refused at construction** (`messagefoundry check` / dry-run / reload / the `serve` pre-flight), not
> merely warned. **At least nine** hops carry that gate — the connection-level ones are
> **MLLP-over-TLS, REST, SOAP, FHIR, DICOMweb (https), EMAIL/SMTP, and a connection's SMART token
> endpoint**, and since BACKLOG #2193 **the DICOM C-STORE SCU with `tls=true`, an FTPS upload, a
> `Direct()` relay that sets a `username`, and an https `FhirLookup` read**, plus some that are not
> connections at all: the **PostgreSQL store hop**, the
> **`[logging]` TLS syslog forwarder**, and the **OIDC token and JWKS legs**, which are checked when
> `serve` builds the auth service rather than by `messagefoundry check`. Read it as "at least these" rather than as a covered estate
> (SDS-3.6); the count moved from seven with [ADR 0173](adr/0173-tls-peer-revocation-checking-and-ocsp-stapling-across-terminating-and-originating-surfaces.md)
> §4.3 and each gated hop names itself when it refuses. On a stock instance that means `MLLP(..., tls=True)`, an
> `https://` `Rest()`/`Soap()`/`FHIR()`/`DICOMweb()` destination and an `Email()` STARTTLS relay are all
> refused **once they point off-box** — including the worked examples below, which are written to show
> the connector, not to pass the posture. So are `DICOM(..., tls=True)`, an `Ftp(..., tls=True)`
> upload, a `Direct()` relay with a `username`, and an `https://` `FhirLookup()`.
>
> **A first `serve` start does not treat every refusal alike** (measured for BACKLOG #2193). It
> builds each outbound on its own, so a refused outbound is recorded failed and the rest of the
> graph starts. It builds the lookups once for the whole graph, so a refused `FhirLookup` stops
> the start. `messagefoundry check`, dry-run and reload fail as a whole in both cases.
>
> **At the shipped default the ways across are:** keep the hop on **loopback**; load a CRL with
> `[tls].crl_file` where it reaches the hop; or attest this one connection with
> **`tls_revocation_attested = true`** plus a mandatory **`tls_revocation_attested_reason`** — an
> `outbound()` or `FhirLookup()` keyword, or a **top-level** `connections.toml` key beside `cleartext_accepted` (not under
> `[settings]`). The attestation says a revocation-checking PKI or terminator backs *this* hop, and
> each construction it lets through on an enforcing instance logs a WARNING carrying the reason
> ([ADR 0173](adr/0173-tls-peer-revocation-checking-and-ocsp-stapling-across-terminating-and-originating-surfaces.md)).
> The same pair on an `inbound()` mTLS listener clears the listener's revocation gate, where
> `tls_crl_file` is the in-engine fix to prefer. The process-wide
> `MEFOR_TLS_REVOCATION_ATTESTED=1` no longer crosses an enforcing outbound hop (BACKLOG #299): one
> variable cannot say which hop's PKI was reviewed. Routing egress through a revocation-checking
> proxy does **not** change the decision — the
> authority has an input for it that no call site sets. Anything else is a *posture change* rather than
> a fix: `[security].enforcement = warn` downgrades it to a WARN. Nothing silences it instance-wide
> any more — the synthetic declaration that did was retired in [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md).
>
> **Some of the engine's other verifying TLS hops are not gated at all** — the inbound FTPS poll,
> the `Database(...)` destination / `DatabasePoll(...)` source, the SQL Server store
> hop, LDAPS — so confirming the refusal on MLLP tells you nothing about those: revocation there is your
> PKI's job, and `MEFOR_TLS_REVOCATION_ATTESTED` is not consulted for them. Full treatment:
> [DEPLOYMENT.md §Revocation-guard behavior](DEPLOYMENT.md#revocation-guard-behavior).
>
> **And turning TLS *off* is not the way out — that is the opposite refusal, not an escape.** Leaving
> an off-box outbound cleartext is decided by a **separate** authority
> ([`config/tls_policy.py`](../messagefoundry/config/tls_policy.py)'s `insecure_hop_disposition`,
> ADR 0153), which on the shipped default **REFUSES** a non-loopback hop with no TLS and no
> declaration — measured: `MLLP(host="epic-host", port=6661)` with no `tls` resolves to `REFUSE`; the
> same hop with `cleartext_accepted=True` resolves to `WARN`; the same hop on `127.0.0.1` to `ALLOW`.
> **So the plain, TLS-less worked examples throughout this section are refused on a stock instance
> too**, and for a different reason than the TLS ones — including the two-line `outbound("OB_EPIC_ADT",
> MLLP(host="epic-host", port=6661))` in *Authoring a connection* above. Every example here is written
> to show its **connector's** shape; making one *run* off-box means picking a lane deliberately:
> **verifying TLS** (+ the revocation attestation above), the audited per-connection
> [**`cleartext_accepted` + `cleartext_reason`**](#declaring-a-cleartext-hop-cleartext_accepted)
> declaration, or keeping the hop on **loopback**. A lab rig on loopback needs none of this, which is
> what makes the examples copy-runnable there.

### MLLP — `MLLP(...)`

| Setting | Dir | Default | Meaning |
|---------|-----|---------|---------|
| `host` | out | — (required) | the downstream peer to dial. **Inbound takes no host** — passing one is a wiring error; the listen interface is the service-level `[inbound].bind_host` (see below). |
| `port` | both | — (required) | bind/connect port |
| `encoding` | both | `utf-8` | charset used for MLLP framing |
| `max_connections` | in | `256` | cap on concurrent client connections (connection-flood guard). Counts **sockets, not hosts** — see `max_connections_per_host` below for the peer-scoped term. `None`/`0` = unlimited. |
| `max_connections_per_host` | in | `32` | cap on concurrent connections from **one peer address** (BACKLOG #1725). The connection is accepted, then refused and closed with an `at_capacity` connection event whose reason reads `max_connections_per_host`; nothing was received, so nothing is dropped, and the peer reconnects as soon as one of its own connections ends. An eighth of `max_connections`, so it takes at least eight distinct source addresses to fill a default listener — it raises the floor on a single-address peer and does **not** bound a distributed one. **Set it to `None`/`0` behind a source-NAT load balancer or proxy that does not preserve the client address**: every partner then arrives as one peer and this, not `max_connections`, becomes your effective listener capacity. |
| `receive_timeout` | in | `60.0` | close a client **idle** this many seconds (slowloris guard). Applied **per read**, so it resets on every byte received: it bounds silence, not a frame — see `max_frame_seconds`. `None`/`0` = no timeout. |
| `max_frame_bytes` | both | `16 MiB` | reject a single MLLP frame larger than this before buffering it whole (OOM guard); applies to inbound frames and outbound ACKs. `None`/`0` = unlimited. |
| `max_frame_seconds` | in | `60.0` | close a client whose frame takes longer than this to complete (BACKLOG #1725). This is the bound on a peer that trickles one byte at a time: it is never idle, so `receive_timeout` never fires on it, and without this it would hold a slot and up to `max_frame_bytes` of reassembly buffer indefinitely. Runs **beside** `receive_timeout`, not instead of it — a peer that opens a socket and says nothing starts no clock, so only the idle bound covers that. The clock restarts for **each** frame, so a pipelined sender is unaffected. **A sender that keeps a quiet socket open with keep-alive bytes can be closed by it**, even where `receive_timeout` is longer or off. When the clock starts and stops is stated once, in the `receive_timeout` bullet under [Resource management & limits](#resource-management--limits-asvs-1312--1313--1326). **Raise this whenever you raise `max_frame_bytes`** — 16 MiB inside 60 s needs about 2.2 Mbps sustained on that one socket, so a large-document feed over a slower link will otherwise trip it on every message. The connection closes with a `closed` event whose reason reads `frame_deadline`. `None`/`0` = no deadline. |
| `max_inflight_frames` | in | `32` | cap on complete frames this listener hands to its inbound handler **at once** (BACKLOG #1725). The handler is the pre-ACK path (decode, parse, validate, ingress commit), where one large message costs several times its own size, so without this the handling peak was `max_connections` times that cost. A frame over the cap **waits** for a slot, first come first served, and is never refused, dropped or NAK'd; it still holds the bytes it arrived in, so this bounds the handling cost, not the raw buffer. The bound is per listener. A frame, once decoded, is **always handled**, exactly as with the cap off: one still waiting when the listener stops is handled once a slot frees, inside the shutdown grace, and cancelled past it like a slow handler. With `[store].group_commit_window_ms` above zero, one listener at this default can never fill a 64-row group-commit batch, so raise it with that window if one listener carries most of the traffic. `None`/`0` = unlimited. |
| `max_messages_per_second` | in | **off** | sustained message-rate ceiling per **connection** (ASVS 2.4.1 / 15.2.2). Over budget the listener **pauses reading**, so TCP back-pressures the sender — **no message is ever dropped, refused or NAK'd**, and none is reordered. Unset = no bound, which is a deliberate exception to this table's usual secure-default rule: a guessed rate on a clinical interface throttles real traffic, so the number has to come from your own feed profile. |
| `message_burst` | in | = the rate | tokens the bucket holds, i.e. how large a burst passes unpaced before the sustained rate applies. Only meaningful with `max_messages_per_second` set. Floor of 1 so a connection can always make progress. |
| `connect_timeout` | out | `10.0` | TCP connect timeout (s) |
| `timeout_seconds` | out | `30.0` | wait this long for the ACK |
| `no_ack` | out | `false` | **(BACKLOG #117, ADR 0124) fire-and-forward (MLLP outbound only):** when `true`, deliver on the successful TCP **write** and read **no** ACK — delivery is confirmed on write, **not** on a positive MSA-1 ACK, so there is **no NAK- or timeout-driven retry** (*at-most-once-confirmation*). A connect/drain failure is still charged and retried (at-least-once for the write; a retry may duplicate — receivers stay idempotent). Composes with `persistent=true` (no handshake **and** no ACK wait — the max-throughput non-acking posture). **Incompatible with `capture_response`/`reingress_to`** (nothing to capture) and MLLP-only — both rejected at `check`. `false` (default) = **byte-identical** (read + validate one ACK). |
| `persistent` | out | `false` | **(ADR 0067)** default `false` **this release** (opt-in): connect-per-message — dial a fresh connection per delivery, send, read the ACK, close. Set `persistent=true` to reuse **one** lazily-established TCP connection across deliveries (the MLLP-standard posture) — the **reuse path**, which removes the per-message TCP/TLS handshake and its `TIME_WAIT` port pressure (recommended on sustained high-rate lanes). Under `persistent=true`, a stale cached connection is detected and redialed once **before any payload byte is written** (uncharged); any failure after the payload was written discards it (charged, normal retry). The default flips to `true` in a subsequent release (ADR 0067 §8 trigger); some partners require connection-per-message (e.g. devices that process only the first frame on a connection) and stay on `false`. |
| `idle_timeout_seconds` | out | `60.0` | (applies when `persistent=true`) don't reuse a persistent connection idle longer than this — the next send closes it and dials fresh (uncharged). `None`/`0` = never expire on idle. |
| `max_connection_age_seconds` | out | — (off) | (applies when `persistent=true`) recycle the persistent connection once it is this old (load-balancer / firewall hygiene). `None`/`0` = off. |
| `tls` | both | `false` | **`[BUILT]` (WP-13b, ADR 0002):** wrap the connection in TLS (1.2+). |
| `tls_cert_file` | both | — | **in:** the server-identity cert (required when `tls`). **out:** a client cert for mTLS (optional). PEM path. |
| `tls_key_file` | both | — | private key for `tls_cert_file`. |
| `tls_ca_file` | both | — | trust anchor — **in:** verify client certs (opt-in mTLS → require a client cert); **out:** verify the server cert. |
| `tls_ca_pin` | both | - | the SHA-256 of `tls_ca_file`, hex, `:` separators allowed. Pins the CA's integrity (BACKLOG #1142): a pin that does not match always refuses. Under `[security].enforcement = enforce` the engine also refuses a CA another account can replace, or one whose permissions or path it cannot read; a matching pin lets the second kind load, with a warning and an `auth.trust_anchor` row. Each check writes its rows under `inbound:<connection name>`. An outbound connection's CA takes the same checks at start and at every reload, under `outbound:<connection name>`, and there a matching pin is no escape: see [The engine checks the file at every start and reload](#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin) (vault BACKLOG #2371). It pins `tls_ca_file` only. A `tls_crl_file` is read by path with no pin, and a certificate in it that `tls_ca_file` does not already hold refuses the build (BACKLOG #1890). Set without `tls` and `tls_ca_file`, it is refused, since nothing would check it. Set but empty or whitespace, it is refused too; leave it out for no pin. |
| `tls_verify` | out | `true` | verify the server's certificate. `false` is MITM-able and is **refused at construction**. `MEFOR_ALLOW_INSECURE_TLS=1` downgrades that refusal to a loud warning **only where the clamp allows it** (#200, [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) decision 2): the escape is inert on an instance that is **both** PHI-classified **and** at `[security].enforcement = enforce`. That is the shipped default, so **on a stock instance the refusal stands with the variable set** — treat the env var as a lab tool, not a deployment option. Nothing else opens this hop: `cleartext_accepted` deliberately does **not** reach a verify-off hop (it has TLS — see [Declaring a cleartext hop](#declaring-a-cleartext-hop-cleartext_accepted)), and the MLLP verify-off refusal does not read [`tls_hop_attested`](#attesting-a-hop-secure-tls_hop_attested) either. If the partner's certificate has merely lapsed, `tls_allow_expired` below is the narrower lever — read that row before reaching for it. |
| `tls_check_hostname` | out | `true` | require the server cert to match `host` (SNI + hostname check). `false` keeps the chain check and accepts any certificate from the trust anchor, whatever host it names. It is a [reported loosening](SECURITY-LOOSENING.md): a WARNING at each build, a `tls-check-hostname` line in `messagefoundry check`, and a `security_loosenings()` entry (ASVS 12.3.2). |
| `tls_allow_expired` | out | `false` | **(#129, ADR 0094)** honour a partner **server cert whose validity period has lapsed** (`notAfter` past) while STILL validating the chain and key usage, and the hostname too unless `tls_check_hostname = false` — the **granular** alternative to `tls_verify=false` for the narrow expired-cert case. It is genuinely narrower (a wrong-host or untrusted-chain peer is still rejected), but do not book it as "not MITM-able": **expiry is the control that retires a certificate**, so a hop that ignores it will keep authenticating a **compromised key indefinitely** — and on the two connectors with no revocation gate (**DICOM-SCU, FTPS**) nothing else would catch that certificate either. **No posture gate covers this setting at all.** It needs no `MEFOR_ALLOW_INSECURE_TLS`; `[security].enforcement = enforce` does not clamp it; verification stays on, so no #200 cleartext/verify-off refusal keys on it. It **is reported**, by the WARNING logged at each connector build, a `tls-allow-expired` line in `messagefoundry check` and a `security_loosenings()` entry, and so `GET /security/posture`; the serve-time loosening warning fires before the graph loads and cannot name it. CORRECTED 2026-10-01: this row said it was absent from `security_loosenings()` and from `check`, which stopped being true under BACKLOG #333. Nothing expires a "two-week bridge" set when a partner's cert lapses, so record the connection name and a removal date in your own risk register. Relaxes both validity bounds (a not-yet-valid cert is also accepted). `false` (default) = **byte-identical** (an expired cert is rejected as before). It is a factory parameter on **six** outbound connectors — **MLLP, FTPS (`Ftp(tls=True)`), DICOM C-STORE SCU, REST, SOAP, FHIR** — and on the `Ftp(tls=True)` inbound poller, which dials out through the same FTPS context (CORRECTED 2026-10-01: this said "six outbound connectors only"), and is **not** honoured by the engine's other verifying TLS hops, including **`DICOMweb()`** (which reuses the REST client but does not read it), the `Database(...)` destination / `DatabasePoll(...)` source, and the `Email()`/`Direct()` SMTP TLS legs. |
| `encoding_characters` | out | (off) | **(Corepoint `-override` parity)** re-encode each outgoing message with a different set of HL7 delimiters (the 5 MSH chars in MSH order: MSH-1 + the 4 MSH-2 chars, e.g. `"#@*!%"`) before framing. Validated at build (exactly 5, all distinct). Unset = payload **byte-identical**. A non-HL7 payload, or a value the new delimiters cannot carry as data, fails the delivery permanently (code `reencode`, [ADR 0206](adr/0206-an-hl7-write-or-re-encode-never-lets-data-become-structure.md)) and is dead-lettered at once. On a batched outbound the whole batch goes with it; ADR 0206 records that gap. |
| `hl7_raw_separators` | out | `false` | **(BACKLOG #107) escape-hatch for a partner that cannot decode HL7 escapes:** emit the four reserved **structural** separators as RAW bytes (`\F\ \S\ \R\ \T\` become the message's own field/component/repetition/subcomponent char) instead of their escape sequences. Reserved chars are read from the payload's own MSH; re-serialized via the parsed model, never string-slicing. `false` (default) = payload **byte-identical**. Enabling it can produce **non-conformant** output (a formerly-escaped `^` now reads as a component separator); that is the point; use only for such a broken partner. Composes after `encoding_characters` (delimiter rewrite first, then raw-separator emit). A non-HL7 payload fails the delivery permanently (code `reencode`, ADR 0206) and is dead-lettered at once; on a batched outbound, see ADR 0206. **HL7v2/MLLP outbound only.** |
| `verify_ack_control_id` | out | `false` | **(BACKLOG #82)** tighten the *accept* decision: accept a **positive** ACK (MSA-1 AA/CA) only if its MSA-2 (message control id) echoes the sent message's MSH-10 — a reply carrying a different id is a correlation failure (retryable `DeliveryError` → retried per the at-least-once path). Both ids are read **separator-aware** from the message (never hardcoded `\|^~\&`). If the sent MSH-10 is absent/unreadable there is nothing to correlate, so the check is skipped and the message delivers as before. Does not alter a **negative** ACK's handling. `false` (default) = **byte-identical** (no correlation). |
| `send_min_interval_seconds` | out | — (off) | **(BACKLOG #82)** minimum **seconds between sends** on this outbound lane: the engine holds each `send` until at least this many seconds have elapsed since the lane's previous send **began**, so a partner that cannot absorb bursts sees a bounded send rate. **Per-envelope** — a batched `BHS…BTS` send (ADR 0082) counts as **one** interval (it throttles the send *rate*, not a per-message rate; a strict per-message cap is a future refinement). A pure **wait** at the delivery seam: it never reorders (strict per-lane FIFO holds — the row is already claimed) and is cancellable by the connection's stop. Independent outbounds pace **independently** (a per-lane clock, not a shared bucket). `None`/`0` (default) = **no pacing**, delivery **byte-identical**. A negative value is rejected at wiring, and so is an `env()` reference (**BACKLOG #1653**) — it is a plain pacing interval, not a per-environment or secret value, so write it as a literal number. |

Plus on `inbound(...)`: `ack_mode` (`original`/`enhanced`/`none`), `strict`, `hl7_version`. On
`outbound(...)`: `retry` (`RetryPolicy`), `ordering`, `internal_error`, `buildup`, `stall`
(`StallThreshold` — Corepoint "Max Message Stall", #50; off unless set, see below), and `simulate`
(`bool`, default `false`). `simulate=True` puts the outbound in **shadow / parallel-run mode** (#15): it
runs the full transform + count-and-log and finalizes the message `PROCESSED`, but **suppresses the real
egress** (no bytes/SQL leave the box) and retains the would-send payload for parity comparison — so a
shadow instance can process real traffic without double-delivering. Set it per-outbound here, or force it
on for every outbound with `[shadow].simulate_all_egress` (see [CONFIGURATION.md](CONFIGURATION.md)). A
simulated lane shows as `simulated` on `GET /connections` and `[SIMULATED]` in the console.

> **TLS** composes with the fail-closed `[egress].allowed_mllp` allowlist (both enforced). A non-loopback
> MLLP listener **must** set `tls=true` — it is **refused at wiring time** otherwise
> (`check_mllp_tls_exposure` raises before the engine starts, so it surfaces at `messagefoundry check` /
> dry-run as well as at `serve`). `serve --allow-insecure-bind` downgrades that refusal to a warning, but
> the flag is **clamped**: on a PHI-classified instance under the default `[security].enforcement =
> enforce` the bind is refused *even with it*, exactly as for the HTTP / raw-TCP / X12 / DICOM listener
> gates. Loopback test rigs
> may stay plaintext. On the **outbound** side, `tls=true` is subject to the revocation gate described at
> the top of this section.

**Operability (optional, validated at wiring time — caught in dry-run / `messagefoundry check`):**
`metadata` — a free-form table of operator labels (owner / runbook / environment) on **either**
direction, surfaced by the API and never used for routing. On a **listen source** only (MLLP, TCP, X12,
HTTP, DICOM): `bind_address` overrides the service `[inbound].bind_host` for that one listener, and
`source_ip_allowlist` restricts it to the listed peer IPs / CIDR networks — fail-closed when set; omit
or leave empty for no restriction. Both are a wiring error on a poll or internal source (File, DB,
RemoteFile, Timer, Loopback, PassThrough — none of them binds an interface).

> **Inbound bind interface (service-level, with a per-connection override).** Inbound MLLP/TCP
> listeners take **only a port** — passing a `host` is a wiring error. Every inbound binds to the
> service-level `[inbound].bind_host` (default `127.0.0.1`). Binding `0.0.0.0` exposes unauthenticated
> MLLP to the network, so the interface is a deliberate **per-environment operator decision** (DEV
> typically loopback, PROD a specific NIC or `0.0.0.0` behind a firewall) set in `messagefoundry.toml`.
> A single connection may override it with a per-connection **`bind_address`** (same operator decision,
> scoped to one listener; the same off-loopback risk applies), and **`source_ip_allowlist`** restricts
> which peers that listener accepts. See [docs/CONFIGURATION.md](CONFIGURATION.md).

> **Port-conflict detection.** Two inbound listeners that bind the **same port on overlapping
> interfaces** are caught **statically** — at `messagefoundry check` / dry-run and at engine
> start/reload — naming **both** connections, instead of aborting at the bare OS bind. The check is
> **interface-aware**: two listeners on the same port but **different** explicit `bind_address`es (a
> multi-NIC host) don't conflict, while a `0.0.0.0` (all-interfaces) bind conflicts with any specific
> interface on that port. `env()`-resolved ports and the engine's own **API listener port** (`[api].port`)
> are included in the start/reload pass. At runtime, a port already held by **another process** (a
> second instance, an OS service) is reported as a clear, named conflict and the affected inbound is
> **isolated** (the engine still comes up; see [ADR 0031](adr/0031-startup-connection-fault-isolation.md)).

#### Inspecting & testing a connection (API)

Two read/diagnostic endpoints back the console's connection view (auth + per-channel RBAC apply — see
[SECURITY.md](SECURITY.md)):

- **`GET /connections/{name}/metadata`** (`monitoring:read`) — the connector type, the operator
  `metadata` labels, running state, and a **secret-scrubbed** settings view (`env()` refs show as
  `{"env": key}` and are never resolved; credential fields render as `"***"`). Inbound is per-channel;
  a shared outbound is barred to channel-scoped users.
- **`POST /connections/{name}/test`** (`connections:test`) — a **reachability probe** that builds a
  *fresh* connector (never the live one), honors the `[egress]` allowlist fail-closed, and **sends no
  real message** — a socket connect (MLLP/TCP/X12), `SELECT 1` (Database), an HTTP `HEAD` (REST/SOAP),
  a `GET {base}/metadata` (FHIR) or `OPTIONS` (DICOMweb), a **C-ECHO** (DICOM SCU), connect/EHLO/NOOP
  with no `MAIL FROM`/`DATA` (Email, Direct), a directory-writability check (File), or an SFTP/FTP
  connect (RemoteFile). It is **audited**. The result is `{supported, success, detail}`: a listen source
  (MLLP/TCP/X12/HTTP/DICOM SCP), a Timer, or an internal `Loopback()`/`PassThrough()` inbound reports
  `supported=false` (nothing external to probe), and a `401/403` from an HTTP endpoint is a *failure*
  (bad credentials), not a pass. A probe never sends data, but a File/RemoteFile probe may create the
  target directory, exactly as a real delivery would.

> **At-least-once / duplicates:** an outbound delivery that is sent but whose ACK is lost
> (peer closes or times out after receiving) is retried, so the receiver may see a duplicate.
> This is the documented at-least-once trade-off — **outbound receivers must be idempotent.**
>
> Enabling the **persistent** outbound connection reuse path (`persistent=true`, ADR 0067 — an
> opt-in this release) makes that window *more frequent*, not new: a write onto a stale cached
> connection can "succeed" into the TCP buffer and only fail at drain/ACK-read — after the peer may
> already have processed the message — so the retry may duplicate. The engine bounds it (a reuse-time
> liveness check redials **before any payload byte is written** — that internal reconnect provably
> cannot duplicate and is never charged — plus `idle_timeout_seconds`) and **never resends
> internally**; a post-write failure is a charged `DeliveryError` whose detail names the failing phase
> (drain / ACK read). The governing invariant is unchanged and stays with the receiver. Partners that
> misbehave on connection reuse (accept the connection but process only the first frame, or send
> unsolicited/duplicate reply frames — extra frames are detected in-transaction and again at reuse
> time and cost only a reconnect, but one arriving *mid-transaction* can still be read as the current
> send's ACK; strict MSA-2↔MSH-10 correlation is demand-gated, BACKLOG #82) should stay on the default
> `persistent=false` (connect-per-message). The default `persistent=false` posture is unaffected — it
> dials fresh per delivery, so there is no cached-connection reuse window at all.

> **Message size caps:** beyond the MLLP frame cap, every inbound message is also rejected
> before parsing if it exceeds **16 MiB** or **10,000 segments** (`ERROR` disposition + AR NAK),
> bounding both the tolerant peek and the strict (hl7apy) validation paths.

### Raw TCP — `Tcp(...)`

A raw-TCP transport (source **and** destination) with **configurable delimiter framing**, built to
relay **X12 (and other non-HL7) feeds over custom-framed TCP** — the payload is carried **opaquely**
(no structured parse). It is the generalization of MLLP's framing: MLLP is the `vt_fs`/`mllp` preset
of the same codec. Pair an inbound `Tcp(...)` with `content_type="x12"` so the body routes as a
`RawMessage` ([ADR 0004](adr/0004-payload-agnostic-ingress.md)); the connector itself never inspects
the bytes.

| Setting | Dir | Default | Meaning |
|---------|-----|---------|---------|
| `host` | out | — (required) | the downstream peer to dial. **Inbound takes no host** (wiring error) — listeners bind the service-level `[inbound].bind_host`. |
| `port` | both | — (required) | bind/connect port |
| `framing` | both | `"stx_etx"` | framing **preset**: `"stx_etx"` (`0x02`/`0x03`, no trailer) or `"vt_fs"`/`"mllp"` (`0x0B`/`0x1C`/`0x0D`). Pass `framing=None` to use explicit bytes instead. |
| `start` / `end` / `trailer` | both | — | explicit delimiter **byte ints** (use with `framing=None`; `trailer` optional). Specifying these *and* a preset is a config error. |
| `encoding` | both | `utf-8` | charset used to encode/decode the framed payload |
| `max_connections` | in | `256` | cap on concurrent client connections (flood guard). `None`/`0` = unlimited. |
| `receive_timeout` | in | `60.0` | close a client idle this many seconds (slowloris). `None`/`0` = no timeout. |
| `max_frame_bytes` | both | `16 MiB` | reject a single frame larger than this before buffering it whole (OOM guard); applies to inbound frames and any framed reply. `None`/`0` = unlimited. |
| `max_connections_per_host` | in | `32` | cap on concurrent connections from **one peer address** (vault BACKLOG #2606), as on MLLP. Refused pre-ingress with an `at_capacity` event whose reason reads `max_connections_per_host`. **Set it to `None`/`0` behind a source-NAT proxy**, where every partner shares one address. |
| `max_frame_seconds` | in | `60.0` | close a client whose frame takes longer than this to complete (vault BACKLOG #2606): the bound on a peer that trickles bytes and so is never idle. It runs on the same clock as MLLP's (vault BACKLOG #2847); the `receive_timeout` bullet under [Resource management & limits](#resource-management--limits-asvs-1312--1313--1326) states when it starts and stops. Closes with a `closed` event whose reason reads `frame_deadline`. **Raise it with `max_frame_bytes`.** `None`/`0` = no deadline. |
| `max_messages_per_second` | in | **off** | sustained message-rate ceiling per **connection** (ASVS 2.4.1 / 15.2.2, BACKLOG #1114 — the MLLP pacer, ported). Over budget the listener **pauses reading**, so TCP back-pressures the sender — **no message is ever dropped, refused or reordered**. Unset = no bound, which is a deliberate exception to this table's usual secure-default rule: a guessed rate on a clinical interface throttles real traffic, so the number has to come from your own feed profile. |
| `message_burst` | in | = the rate | tokens the bucket holds, i.e. how large a burst passes unpaced before the sustained rate applies. Only meaningful with `max_messages_per_second` set. Floor of 1 so a connection can always make progress. |
| `connect_timeout` | out | `10.0` | TCP connect timeout (s) |
| `timeout_seconds` | out | `30.0` | send / await-reply timeout (s) |
| `persistent` | out | `false` | **(ADR 0067 §9 / BACKLOG #97)** reuse **one** lazily-established TCP connection across deliveries (opt-in; default `false` = connect-per-send, byte-identical). A stale cached connection is redialed once **before any byte is written** (uncharged); any post-write failure discards it (charged, normal retry). Same model as the MLLP `persistent` knob, minus TLS (raw TCP has none). |
| `idle_timeout_seconds` | out | `60.0` | (applies when `persistent=true`) don't reuse a connection idle longer than this — the next send closes it and dials fresh (uncharged). `None`/`0` = never expire on idle. |
| `max_connection_age_seconds` | out | — (off) | (applies when `persistent=true`) recycle the persistent connection once it is this old (LB/firewall hygiene). `None`/`0` = off. |
| `expect_reply` | out | `false` | read one framed reply and treat receiving it as confirmation (the reply is **not** parsed). `false` = fire-and-forget after the write. |

```python
from messagefoundry import Tcp, inbound, outbound

# Receive an X12 feed framed with STX/ETX; route it opaquely as a RawMessage.
inbound("TCP-IN_PARTNER_X12", Tcp(port=9100, framing="stx_etx"), router="x12_router",
        content_type="x12")
# Relay it back out over VT/FS framing to a downstream peer.
outbound("TCP-OUT_DOWNSTREAM_X12", Tcp(host="downstream", port=9200, framing="vt_fs"))

# Same feed, with a message-rate bound taken from ITS OWN measured profile: 40/s sustained,
# 200 absorbed as a burst. Over that the listener stops reading until the debt clears; the
# partner is back-pressured by TCP and every message it sent still arrives, in order.
inbound("TCP-IN_PARTNER_X12", Tcp(port=9100, framing="stx_etx",
                                  max_messages_per_second=40, message_burst=200),
        router="x12_router", content_type="x12")
```

- **No HL7 ACK, and no reply at all.** A `Tcp(...)` source does **not** generate an HL7
  acknowledgement, and the engine writes nothing back on the inbound socket — routing runs after the
  ingress commit, so a Handler's return value never reaches that connection. Reply to a partner by
  returning `Send("<outbound>", payload)`; returning the payload bare is an authoring error and
  raises (ERROR / dead-letter, replayable) rather than delivering.
- **Opaque relay.** Bytes in = bytes out (delimiters stripped/added) — no transformation,
  validation, or content sniffing in the connector.
- **At-least-once / duplicates.** An outbound send (and its framed reply, when expected) may be
  retried, so the receiver may see a duplicate — **the receiver must be idempotent.**
- **Egress allowlist.** A `Tcp(...)` destination is gated by `[egress].allowed_tcp` (host or
  host:port); an inbound `Tcp(...)` is a local listener and is not connect-gated. See
  [docs/CONFIGURATION.md](CONFIGURATION.md).
- **Structured X12 parsing** (ISA/GS/ST) is now available as a **pure library** —
  `messagefoundry.parsing.x12` ([ADR 0012](adr/0012-x12-edi-codec.md)) — that a Router/Handler calls
  on demand against the `RawMessage`. For X12 feeds that arrive with **no transport sentinel** (the
  interchange itself is the frame), use the dedicated **`X12(...)`** connector below instead of
  `Tcp(...)`.
- **Deferred follow-ups:** X12 acknowledgements (997/TA1) and strict implementation-guide validation
  are intentionally **not** built. **Length-prefix framing** (a leading byte count instead of an end
  delimiter) is also a follow-up; only delimiter framing is supported by `Tcp(...)` today.

### X12 EDI — `X12(...)`

A raw-TCP transport (source **and** destination) for **ASC X12 EDI** that frames by the **interchange
itself** (`ISA…IEA`) — there is **no transport sentinel**, and the segment terminator is **discovered
from each ISA header** (it may even be `CR`+`LF`), so `X12(...)` takes **no framing knobs**
([ADR 0012](adr/0012-x12-edi-codec.md)). Use it when partners send bare interchanges; use `Tcp(...)`
when each interchange is wrapped in a fixed sentinel (STX/ETX, VT/FS). The payload is relayed
**opaquely** — pair an inbound `X12(...)` with `content_type="x12"` so it routes as a `RawMessage`
([ADR 0004](adr/0004-payload-agnostic-ingress.md)); a Router/Handler parses it on demand via
`messagefoundry.parsing.x12` (a cheap `X12Peek` for routing, `X12Message` for transforms).

| Setting | Dir | Default | Meaning |
|---------|-----|---------|---------|
| `host` | out | — (required) | the downstream peer to dial. **Inbound takes no host** (wiring error) — listeners bind the service-level `[inbound].bind_host`. |
| `port` | both | — (required) | bind/connect port |
| `encoding` | both | `utf-8` | charset used to encode/decode the interchange bytes |
| `max_connections` | in | `256` | cap on concurrent client connections (flood guard). `None`/`0` = unlimited. |
| `receive_timeout` | in | `60.0` | close a client idle this many seconds (slowloris). `None`/`0` = no timeout. |
| `max_interchange_bytes` | both | `16 MiB` | reject a single interchange larger than this before it completes (OOM guard); applies inbound and to any returned interchange. `None`/`0` = unlimited. |
| `max_connections_per_host` | in | `32` | cap on concurrent connections from **one peer address** (vault BACKLOG #2606), as on MLLP and `Tcp(...)`. **Set it to `None`/`0` behind a source-NAT proxy.** |
| `max_frame_seconds` | in | `60.0` | close a client whose interchange takes longer than this to complete (vault BACKLOG #2606). The `receive_timeout` bullet under [Resource management & limits](#resource-management--limits-asvs-1312--1313--1326) states when the clock starts and stops. Closes with a `frame_deadline` reason. **Raise it with `max_interchange_bytes`.** `None`/`0` = no deadline. |
| `max_messages_per_second` | in | **off** | sustained **interchange**-rate ceiling per **connection** (ASVS 2.4.1 / 15.2.2, BACKLOG #1114 — the MLLP pacer, ported; one token per `ISA…IEA`). Over budget the listener **pauses reading**, so TCP back-pressures the sender — **nothing is dropped, refused or reordered**. Unset = no bound, deliberately: a guessed rate throttles real traffic, so the number has to come from your own feed profile. |
| `message_burst` | in | = the rate | tokens the bucket holds, i.e. how large a burst passes unpaced before the sustained rate applies. Only meaningful with `max_messages_per_second` set. Floor of 1 so a connection can always make progress. |
| `connect_timeout` | out | `10.0` | TCP connect timeout (s) |
| `timeout_seconds` | out | `30.0` | send / await-reply timeout (s) |
| `persistent` | out | `false` | **(ADR 0067 §9 / BACKLOG #97)** reuse **one** lazily-established connection across deliveries (opt-in; default `false` = connect-per-send, byte-identical). A stale socket is redialed once **before any byte is written** (uncharged); any post-write failure is charged + retried. A returned TA1/business interchange is a complete transaction on a healthy transport, so the connection **stays cached** across a captured reply (and a TA1\*R reject); a TA1 naming another interchange discards it. |
| `idle_timeout_seconds` | out | `60.0` | (applies when `persistent=true`) don't reuse a connection idle longer than this. `None`/`0` = never expire on idle. |
| `max_connection_age_seconds` | out | — (off) | (applies when `persistent=true`) recycle the persistent connection once it is this old (LB/firewall hygiene). `None`/`0` = off. |
| `expect_reply` | out | `false` | read one returned interchange and treat receiving it as confirmation (not parsed). `false` = fire-and-forget after the write. |
| `capture_response` | out | `false` | **synchronous request/response** (ADR 0016): capture the returned **271/TA1** as a reply (ADR 0013). Implies a reply is read; a **TA1** is classified (below). |
| `reingress_to` | out | — | route the captured reply into this `Loopback()` inbound; **implies `capture_response=True`** (ADR 0013). Requires `expect_reply=True`. |
| `ta1_required` | out | `false` | a delivery that reads **no** TA1/business reply within `timeout_seconds` is a `DeliveryError` (retry), for partners who always TA1. Set `true` on RTE feeds. |

> **Backend support.** `capture_response` and `reingress_to` work on **every** store backend — SQLite,
> Postgres, **and SQL Server**. See the
> [capability matrix](CONFIGURATION.md#per-backend-capability-matrix).

```python
from messagefoundry import X12, ContentType, Loopback, inbound, outbound

# Receive bare ISA…IEA interchanges over TCP; route opaquely as a RawMessage.
inbound("X12-IN_PARTNER_270", X12(port=2710), router="partner_x12_router",
        content_type=ContentType.X12)
# Relay verbatim to a downstream payer.
outbound("X12-OUT_PAYER", X12(host="payer.example.org", port=5010))

# Real-time eligibility (270 → 271 on one socket): capture the 271 + route it back.
outbound("X12-OUT_RTE", X12(host="payer.example.org", port=5010,
                            expect_reply=True, reingress_to="X12-IN_ELIG_RESULT", ta1_required=True))
inbound("X12-IN_ELIG_RESULT", Loopback(), router="route_elig_result",
        content_type=ContentType.X12)   # the captured 271 re-ingresses as a RawMessage

# Same intake with an interchange-rate bound from its own measured profile: 10/s sustained,
# 50 absorbed as a burst. Over that the listener stops reading; nothing is dropped or refused.
inbound("X12-IN_PARTNER_270", X12(port=2710, max_messages_per_second=10, message_burst=50),
        router="partner_x12_router", content_type=ContentType.X12)
```

See `samples/config/IB_PARTNER_X12.py` + `samples/messages/x12_270_eligibility.edi` for a runnable
example, and `messagefoundry.parsing.x12` for the codec a Router/Handler uses.

- **No X12 ACK on the *inbound*, and no reply at all.** An `X12(...)` source does **not** generate a
  TA1/997/999, and the engine writes nothing back on the inbound socket — routing runs after the
  ingress commit, so a Handler's return value never reaches that connection. Reply to a partner by
  returning `Send("X12-OUT_...", payload)` to an **outbound**; returning the payload bare is an
  authoring error and raises (ERROR / dead-letter, replayable) rather than delivering. For a
  synchronous 270/271 use the capturing outbound below.
- **Synchronous request/response on the *outbound* (ADR 0016).** With `capture_response`/`reingress_to`
  the destination blocks for the returned interchange and classifies a **TA1** interchange ack:
  **TA1\*A** → accepted; **TA1\*R** → permanent reject → **dead-letter**; **TA1\*E** →
  accepted-with-warning (delivered, **not** retried, logged). **A TA1 is acted on only when its
  TA1-01 names the ISA13 just sent.** Both are compared as nine-digit control numbers, and a shorter
  all-digit TA1-01 is zero-padded. If the sent ISA13 is not nine digits, only an exact echo matches;
  a blank one matches nothing. If the sent payload has no readable ISA there is nothing to
  correlate, and the TA1 is classified on TA1-04 alone. A reply carrying several TA1s is searched,
  up to the first 32, for the one naming the interchange sent. A reply with no TA1 naming it (stale
  on the socket, misdirected, or from a partner that echoes the wrong field) is **neither a reject
  nor an accept**: it is logged at WARNING with control numbers only, the delivery is **retried**
  (`DeliveryError`), and a `persistent` connection is discarded rather than reused. Unlike MLLP's
  opt-in `verify_ack_control_id`, this check is always on and also covers a reject. A business **271/277/278** returned
  *instead of* a TA1 is itself the confirmation and rides re-ingress. Only a **TA1** is a transport
  retry gate — **999/997** functional acks are content, routed by a Handler. A non-idempotent 270
  re-sent in the at-least-once crash window yields a fresh 271 captured at the next `response_seq`
  (latest-wins) — the partner must tolerate a re-send. The **X12-over-REST** variant is zero new code
  (`Rest(..., reingress_to=...)` captures the bare-X12 HTTP body); the **X12-over-SOAP** variant needs
  the trigger Handler to build the SOAP envelope and the `Loopback()` handler to un-wrap the response
  envelope (declare it `content_type="soap"`/raw) before peeking via `parsing/x12`.
- **Opaque relay; delimiters discovered.** The connector never rewrites the bytes — delimiters are
  read from the ISA, not configured, and the interchange is preserved verbatim in the store.
- **At-least-once / duplicates.** An outbound send may be retried — **the receiver must be
  idempotent.**
- **Egress allowlist.** An `X12(...)` destination shares `[egress].allowed_tcp` (host or host:port);
  an inbound `X12(...)` is a local listener and is not connect-gated.
- **Deferred follow-ups:** **TA1** classification on a *capturing outbound* is built (ADR 0016); an
  *inbound* TA1/997/999 **generator** and outbound **999/997** functional-ack classification are **not**
  built (a Router can branch on `X12Peek`'s `ST01`/`GS08` today). Strict **implementation-guide**
  validation *is* built as an on-demand library — `messagefoundry.parsing.x12.validate` behind the
  `[x12]` extra (pyx12's bundled HIPAA IG maps, BACKLOG #32) — and its walk emits a conforming **999**
  (005010) / **997** (004010) as a by-product a Handler may return; it is never run by the connector.

### HTTP web-service listener — `Http(...)` (inbound only, ADR 0023)

An **inbound HTTP/1.1 listener** — a connector-owned bound socket a partner `POST`s a body to (REST, a
SOAP envelope, FHIR, a webhook). **Source only**: it never delivers, and it lives in `transports/`, not
`api/` — the engine's FastAPI app stays the admin/RBAC surface and `transports/` must never import `api/`,
so intake is a registry connector owning its own `asyncio` socket. Stdlib only
(`asyncio.start_server`) — no second web framework. Pair it with `inbound(..., content_type=...)`
([ADR 0004](adr/0004-payload-agnostic-ingress.md)): the default `hl7v2` runs the HL7 peek/validate path and
routes a `Message`; `json`/`xml`/`text`/`fhir` route a `RawMessage` the Handler parses on demand.

| Setting | Default | Meaning |
|---------|---------|---------|
| `port` | — (required) | bind port. **Takes no host** — the listen interface is the service-level `[inbound].bind_host` (or a per-connection `bind_address`), exactly as MLLP/TCP/X12. |
| `encoding` | `utf-8` | charset the POSTed body is decoded with (non-binary content types) |
| `max_connections` | `256` | cap on concurrent clients (connection-flood guard). `None`/`0` = unlimited. |
| `receive_timeout` | `60.0` | bound the **whole-request** read — request line + headers + body (slowloris guard); over budget answers a synchronous `408`. `None`/`0` = no timeout. |
| `max_connections_per_host` | **off** | cap on concurrent connections from **one peer address**, answered `503` with an `at_capacity` event whose reason reads `max_connections_per_host` (vault BACKLOG #2606). **Ships off, unlike MLLP/TCP/X12**: this connector answers one request per connection, so behind a reverse proxy every partner arrives from one address and any cap would be the listener's whole capacity. Set one only where the listener sees real client addresses. |
| `max_body_bytes` | `16 MiB` | the MLLP frame cap's HTTP twin — an over-declared `Content-Length` is refused `413` **before a body byte is read** (OOM guard). `None`/`0` = unlimited. |
| `max_header_bytes` | `64 KiB` | cap the request line + headers (header-flood guard). This one cap can't be switched off: unset or `None` takes the 64 KiB default, and `0` (or `"0"`) is refused at load rather than silently becoming the default (BACKLOG #1872). |
| `max_messages_per_second` | **off** | sustained message-rate ceiling for the **whole listener** (ASVS 2.4.1 / 15.2.2, BACKLOG #1114 — the MLLP pacer, ported). Over budget the connector **waits before reading the request**, so the partner is back-pressured and then served in full — **nothing is dropped, refused or answered differently**, and the wait sits outside `receive_timeout` so a paced partner is never handed a `408` for a delay the engine imposed. **Listener-wide, not per-connection**, unlike MLLP/TCP/X12: this connector answers one request per connection, so a per-connection bucket would be charged once and thrown away, bounding nothing. A `GET`/`HEAD` probe waits behind an outstanding debt but **charges nothing**, and neither does a request refused before its body reaches the engine. Only a body the engine reads and records spends budget, including one it then refuses with a `422`, so a peer that submits nothing cannot starve one that does. Unset = no bound, deliberately: a guessed rate throttles real traffic, so the number has to come from your own feed profile. |
| `message_burst` | = the rate | tokens the bucket holds, i.e. how large a burst passes unpaced before the sustained rate applies. Only meaningful with `max_messages_per_second` set. Floor of 1 so the listener can always make progress. |
| `tls` | `false` | serve **HTTPS** (TLS 1.2+, the same per-connection inbound TLS builder MLLP uses). |
| `tls_cert_file` / `tls_key_file` | — | the server-identity cert + its private key (required when `tls`). A PEM **path** (a plain string — unlike `DICOM()`, these two are not typed for `env()`). |
| `tls_key_password` | — | passphrase for an **encrypted** `tls_key_file` — a **secret**, supply via `env()`; it must meet the [wrap floor](#encrypted-private-keys-must-meet-the-wrap-floor). |
| `tls_ca_file` | — | trust anchor — opt-in **mTLS** (require + verify a client certificate). |
| `tls_ca_pin` | - | the SHA-256 of `tls_ca_file`. Pins the CA's integrity (BACKLOG #1142): a pin that does not match always refuses. Under `[security].enforcement = enforce` the engine also refuses a CA another account can replace, or one whose permissions or path it cannot read; a matching pin lets the second kind load, with a warning and an `auth.trust_anchor` row. Each check writes its rows under `inbound:<connection name>`. It pins `tls_ca_file` only. A `tls_crl_file` is read by path with no pin, and a certificate in it that `tls_ca_file` does not already hold refuses the build (BACKLOG #1890). Set without `tls` and `tls_ca_file`, it is refused, since nothing would check it. Set but empty or whitespace, it is refused too; leave it out for no pin. |
| `intake_auth` | `"none"` | **peer credential required to submit a message** ([ADR 0154](adr/0154-synchronous-captured-downstream-reply-and-intake-authentication-for-the-inbound-http-listener-adr-0023-deferred-tail.md) D6): `none` \| `api_key` \| `bearer` \| `mtls_subject`. A sibling of `source_ip_allowlist` — it authorises *submitting*, never *reading*; it mints no identity and opens no session. A missing or wrong credential is refused `401`. A request that sends the credential header twice gets `400` instead, before any comparison; [SECURITY.md](SECURITY.md) Table B has the rule. Under `mtls_subject`, a verified certificate whose subject is not in `intake_client_subjects` is refused `403`. Each refusal comes **before any request body byte is read**, so it costs an anonymous peer nothing to be turned away. |
| `intake_api_key` | — | the credential for `api_key`/`bearer` — a **secret**, `env()` only (a literal, a `default=` or a `cast=` is refused at the factory). |
| `intake_api_key_next` | — | rotation slot, accepted **alongside** `intake_api_key` so a partner key rotates with no outage: set it, have the partner cut over, promote it, then clear it. Leaving it set keeps a retired credential live. |
| `intake_api_key_header` | `"x-api-key"` | which header carries the `api_key` credential. A header **name**, not a secret. |
| `intake_client_subjects` | — | `mtls_subject` allow-list, entries **qualified**: `"CN:partner.example"` / `"SAN:DNS:partner.example"`. Qualifying the namespace is what stops a spoofed commonName colliding with a pinned SAN; a bare `partner.example` is refused at the factory rather than silently matching nothing. |
| `intake_auth_health` | `"require"` | whether `GET`/`HEAD` health probes must authenticate too. **`"allow"` is a real exemption**: it hands anyone who can reach the socket an unauthenticated "is MessageFoundry up, and where" oracle. Set it only when a load-balancer check cannot carry the credential. It applies under `api_key` and `bearer` only: under `mtls_subject` the certificate is checked at accept, before the method is read, so a probe still needs a listed certificate. |
| `intake_auth_rate_limit` | `10` | **failed** intake-auth attempts per minute per peer, then `429` + `Retry-After`. A *successful* authentication never consumes budget, so this bounds guessing without capping throughput. `None`/`0` disables. |
| `intake_auth_rate_limit_global` | `60` | **failed** attempts per minute across all peers. Consulted only for peers with no successful authentication in the window, so one attacker cannot `429` an authenticated partner. `None`/`0` disables. |
| `reply_from` | — | **presence is the mode switch** ([ADR 0154](adr/0154-synchronous-captured-downstream-reply-and-intake-authentication-for-the-inbound-http-listener-adr-0023-deferred-tail.md) D4): names the outbound whose **captured** reply becomes this request's HTTP body, turning the listener from fire-and-forget into a **proxy**. See *Synchronous captured-downstream reply* below. One knob, not two — a separate `sync_reply: bool` would admit a half-configured "mode on, no target" state that could only fail at runtime. |
| `reply_timeout` | `30.0` | seconds the HTTP turn may block waiting for that reply. Must be **positive** — an unbounded or zero budget is not a timeout. Expiry answers `reply_on_timeout` and **leaves the message flowing**; the engine does not cancel it. |
| `reply_on_timeout` | `"504"` | what to answer when `reply_timeout` expires: `504` (the partner did not answer in time) or `202` (demote to the ordinary receipt path). |
| `reply_content_type` | `"passthrough"` | `passthrough` echoes the partner's **own** captured `content-type`; a literal MIME type (must contain `/`) pins it instead. |
| `reply_on_empty` | `"204"` | answer for a captured but *deliberately empty* partner reply — `204` or `200`. An empty reply is distinguished from a missing one, never conflated. |
| `reply_write_timeout` | `30.0` | seconds to drain the (partner-sized) response body back to the caller. Must be **positive**. |

> **TLS is confidentiality; intake auth is authentication — neither argues the other away.** A bare
> `tls` + `tls_ca_file` means *"any certificate this CA ever signed"*, with **no subject binding at
> all**, which is why `mtls_subject` additionally requires `intake_client_subjects`. Enabling
> `intake_auth` is likewise never a reason to relax `check_http_tls_exposure`. A **non-loopback** HTTP
> listener with no *effective* peer control — no sufficiently narrow `source_ip_allowlist`, no
> `intake_auth`, and no `mtls_subject` binding — is refused at start under an enforcing PHI posture
> and warned about otherwise, independently of the TLS gate and **without** consulting
> `--allow-insecure-bind`: a cleartext escape hatch does not get to waive authentication. Loopback
> binds are unaffected.

Plus on `inbound(...)`: `router`, `content_type`, `bind_address`, `source_ip_allowlist`, `metadata`,
`capture_connection_errors`, and the per-connection overrides further below. A **non-loopback** HTTP
listener without `tls=true` is **refused at start** (`check_http_tls_exposure`, the same generalized
bind-guard MLLP/TCP/DICOM use). `serve --allow-insecure-bind` downgrades that refusal to a warning —
but the flag is **clamped**: on a PHI-classified instance under the default `[security].enforcement =
enforce` the bind is refused *even with it*. Treat the flag as a lab tool, not a deployment option.

**Respond-with-receipt (ACK-on-receipt).** A `POST`/`PUT`/`PATCH` body is committed to the ingress stage
and answered **`202 Accepted`** carrying the engine `message_id` the instant it is durably committed — the
HTTP twin of MLLP's AA-on-receipt. A post-ingress routing/transform/delivery failure happens *after* the
`202` and is **not** reflected in the HTTP status; it surfaces as the message's `ERROR`/dead-letter
disposition + the AlertSink, exactly as a post-ACK MLLP failure does. A body the engine **refuses at
ingress**, after reading it, answers **`422`** with `{"error":"message was not accepted"}` and no
`message_id`. Examples are a body the engine cannot decode or one over its ingress ceiling. Others include
a body that does not match the declared `content_type`, or an HL7 parse or strict-validation failure. The
message is still recorded, with status `ERROR`, so it is counted and never silently dropped
(owner ruling 2026-09-26, [ADR 0154 amendment](adr/0154-synchronous-captured-downstream-reply-and-intake-authentication-for-the-inbound-http-listener-adr-0023-deferred-tail.md#amendment-2026-09-26-a-body-refused-at-ingress-is-answered-422-on-both-paths)).
A **pre-ingress** refusal answers
synchronously and emits an ADR 0021 `connection_event`: `403` (not in `source_ip_allowlist`), `408` (the
request didn't fully arrive within `receive_timeout`), `413` (over `max_body_bytes` **or**
`max_header_bytes`), `400` (a malformed request line or header, or framing this listener will not guess at -- including at least any `Transfer-Encoding`, a duplicated or non-digit `Content-Length`, whitespace before a header colon, a folded header line, a bare CR or LF, a control character in a header value, an HTTP version other than 1.x, a missing `Host` on any version but HTTP/1.0, more than one `Host`, and a non-zero body declared on a method other than `POST`/`PUT`/`PATCH`), `411` (a `POST`/`PUT`/`PATCH` with no `Content-Length`; the body is never read to EOF), `503` (at
`max_connections` — the connection is accepted, then refused and closed at the application layer).
`GET`/`HEAD` are static, non-PHI health probes and write **no** ingress row; any other method is `405`. A probe is held to the same head rules as any request, so an HTTP/1.1 probe must send one `Host` header. Methods are case-sensitive (RFC 9110), so a lowercase `get` or `post` is not a probe or an intake request.

**Synchronous captured-downstream reply (`reply_from`, ADR 0154 increment B).** Naming `reply_from` makes
the HTTP turn **block** until the named outbound's reply has been captured **and committed to the store**,
then returns that reply as the response body — a proxy API rather than a receipt. The **committed row is
the sole authority** for the returned bytes: every in-process signal is only a latency hint and the waiter
re-reads the store, which is what keeps this correct under engine sharding, HA failover, every claim mode,
and any race between the capturing worker and the reader. A reply is therefore returned only once it is
durable and replayable. An inbound **without** `reply_from` keeps the receipt path above: `202` for a
committed body, `422` for a body refused at ingress. A `reply_from` inbound answers that same `422` for a
refused body, before it would wait for any reply.

Refused at **check time** (`messagefoundry check`) rather than at runtime: a `reply_from` naming no
deployed outbound; an outbound that does not capture responses; `reply_content_type="passthrough"` against
an outbound not capturing the content type; and — because either would make N concurrent callers queue
behind one lane and let a single stuck message time out every caller — an effective `ordering` of **FIFO**
or a **finite `max_attempts`** on the named outbound. Setting any `reply_*` knob **without** `reply_from`
is refused at the factory, since the path is off and the knob would never be read.

**Not built.** **Routing metadata** (HTTP method / path / headers as Router inputs) is a defined follow-on
— a Handler sees the body only. **`capture_error_responses` is the headline gap:** a partner `4xx`
dead-letters and the caller receives a fixed-JSON `502`, **not** the partner's own status and body, so a
proxy API built on `reply_from` is currently correct only when the partner *succeeds*. The inbound **FHIR
facade** (BACKLOG #20) and **DICOMweb STOW-RS receiver** (#24) are consumers of this listener, each its own
build. `POST /connections/{name}/test` reports `supported=false` — a bound listener has nothing external to
probe.

```python
from messagefoundry import ContentType, Http, env, inbound, router

# Receive JSON orders over HTTPS; route them opaquely as a RawMessage.
inbound("REST-IN_ACME_ORDERS",
        Http(port=8088, tls=True,
             tls_cert_file="/etc/mefor/http.crt", tls_key_file="/etc/mefor/http.key",
             tls_key_password=env("http_tls_key_password")),   # only if the key is encrypted
        router="acme_orders_router", content_type=ContentType.JSON,
        source_ip_allowlist=["10.0.0.0/8"])

# The same listener with a message-rate bound from its own measured profile: 25/s sustained,
# 100 absorbed as a burst, shared by every partner connection. Over that a POST waits before
# its request is read, then is served in full and answered 202 -- never 429, never dropped.
inbound("REST-IN_ACME_ORDERS",
        Http(port=8088, tls=True,
             tls_cert_file="/etc/mefor/http.crt", tls_key_file="/etc/mefor/http.key",
             max_messages_per_second=25, message_burst=100),
        router="acme_orders_router", content_type=ContentType.JSON)


@router("acme_orders_router")
def route(msg):
    return ["acme_orders"] if msg.json().get("kind") == "order" else []   # else UNROUTED
```

### File — `File(...)`

| Setting | Dir | Default | Meaning |
|---------|-----|---------|---------|
| `directory` | both | — (required) | folder to poll / write into |
| `pattern` | in | `*.hl7` | filename glob to pick up |
| `poll_seconds` | in | `1.0` | poll interval. It is also the **settle window**: a file is read only once its size and modification time are unchanged since the last poll that saw it (BACKLOG #1811), so every file waits at least one poll. The settle gate is always on and has no setting, but a very small `poll_seconds` narrows its window to almost nothing. |
| `min_age_seconds` | in | `0` | skip files modified within this window. This is an extra wait on top of the settle gate, not the gate itself; set it for a partner that pauses between writes for longer than `poll_seconds`. |
| `after_read` | in | `move` | `move` (→ `.processed`), `delete`, or `leave` (process **in place** — never move/delete the source file, for a read-only share / a directory another system owns; a hashed dedup ledger ensures a left file is ingested **once**, #142) |
| `sort` | in | `name` | process order: `name` or `mtime` |
| `recursive` | in | `false` | also scan subdirectories |
| `max_file_bytes` | in | `16 MiB` | route files larger than this to the error dir instead of reading them into memory (OOM guard). `None`/`0` = unlimited. |
| `poll_max_files` | in | `500` | most files one scan will take. The rest stay in the drop directory and the next scan takes them — a **deferral, not a drop**: nothing is quarantined, errored, or left unaccounted for. See [*Per-tick poll ceilings*](#per-tick-poll-ceilings) for the number and when to raise it. `None`/`0` = unlimited. |
| `validate_directory` | both | `false` | validate the directory **at startup** (#114): a missing/unusable dir reports the connection **`failed`** (ADR 0031) instead of the default deferral to run time. **No mkdir** — a merely-missing dir fails. **In:** a `leave` source validates read-only (a read-only share passes); `move`/`delete` also require write. **Out:** the target must already exist and accept a write, and is then **never created** — not at start, not on write (a delivery into a vanished dir fails retryably instead), and not by `POST /connections/{name}/test`. Left off (the default) the outbound target is still created on first write, but the creation is now logged as a `WARNING`. |
| `processed_subdir` / `error_subdir` | in | `.processed` / `.error` | where read/failed files go |
| `filename` | out | `{MSH-10}.hl7` | output name (supports `{HL7-path}` placeholders). Resolved values are sanitized to a **single safe filename** — path separators/unsafe chars stripped, leading dots removed, trailing dots and spaces stripped, and `.`/`..`/reserved device names fall back — so a message field can never write outside the directory. The final name, `.gz` included, is capped at **200 UTF-8 bytes**; a longer one falls back to `message.hl7` (ADR 0204). **Out:** a deep `directory` lowers the cap to the room left under the platform path limit (logged once when the connection is built), and a directory with no room for the fallback, or a template whose fixed text is over the cap, is refused when the connection is built. |
| `overwrite` | out | `false` | overwrite vs. uniquify a name collision (collisions are resolved by an **atomic** exclusive create, so concurrent writes never clobber) |
| `encoding` | both | `utf-8` | file charset (write) |
| `credential_username` | both | — (unset) | **Windows-only** alternate share identity (ADR 0132, #111): `user`, `DOMAIN\user`, or a `user@domain` UPN. Unset = the engine service-account identity (byte-identical). |
| `credential_domain` | both | — (unset) | optional AD domain (omit for `DOMAIN\user` / UPN forms). |
| `credential_password` | both | — (required with a username) | share password — **`env()` only** (an inline literal is refused). Secret; redacted in every settings view, never logged. |

File writes are always **atomic** (write to a temp `.part` file, then rename), so a downstream reader
never sees a partial file.

**Alternate Windows / network-share credential (UNC/SMB — `credential_*`, #111, ADR 0132).** A File
endpoint (both the inbound poll and the outbound write) can authenticate to a local/UNC share under a
Windows identity **distinct from the engine service account** — for a site that isolates share access
per-feed rather than granting the service account blanket access. Configure it with `credential_username`
(+ optional `credential_domain`) and `credential_password`:

```python
from messagefoundry import File, inbound, env

inbound(
    "IB_ACME_ADT",
    File(
        directory=r"\\fileserver\acme\in",
        credential_username="acme_svc",       # or "CORP\\acme_svc" / "acme_svc@corp.example"
        credential_domain="CORP",             # optional; omit for the DOMAIN\user / UPN forms
        credential_password=env("acme_share_pw"),  # SECRET — env() only, never inline
    ),
    router="r_acme",
)
```

- **`env()`-only password.** `credential_password` must be an `env()` reference — an inline literal (or an
  `env()` with a `default=`) is **refused** at load, so a share secret never lands in source/config. The
  password is redacted in `/metadata` and `graph --json`, and is **never logged** (a logon failure reports
  the Win32 error *code* only).
- **Win32-only, fail-loud.** The credential is established via `LogonUser` + per-thread impersonation
  (stdlib ctypes — no pywin32, no privilege). On a **non-Windows host** a File connection with `credential_*`
  settings **refuses to build** with a clear error (never a silent no-op) — remove the settings or run the
  engine on Windows. CI cannot stand up a real alt-credential UNC share, so the live path is a
  Windows-CI/manual gate; the non-Windows refusal is unit-tested.
- **A bad credential never crashes the connection.** A logon/auth failure is a logged `ERROR` — a delivery
  retry/dead-letter on an outbound, a `failed` connection on a `validate_directory=true` inbound, or a
  logged per-poll retry otherwise — never an accept-and-drop or a connection crash.
- **Credentialed endpoint tester.** `POST /connections/{name}/test-credential` dials the share **under the
  configured alternate credential** (no real data written), returning a clear "reaches the share / does not"
  answer for setup — see [SECURITY.md](SECURITY.md) for the RBAC. It 400s if the connection has no
  `credential_*` identity.

**Process-in-place (`after_read='leave'`, #142).** For a **read-only share**, or a directory whose files
another system owns, a source may **leave** each file untouched instead of moving/deleting it. To avoid
re-ingesting the same file every poll, the engine keeps a durable **processed-file dedup ledger** (the
store's `processed_files` table, all three backends) keyed on a **hash** of the file's identity — the
file's **path relative to the watch root** + mtime + size locally, or the **full remote path** + size for
SFTP/FTP (a remote listing carries no reliable mtime, so size is the change signal) — **never a
cleartext path** (a filename/path can embed an MRN), and never logged. Folding the *path* (not just the
basename) in keeps two same-named files in different `recursive` subdirs distinct, so both are ingested.
A file is recorded **after** its message(s) emit successfully, with the **file** (not each split message)
as the dedup unit; a crash before recording re-emits the whole file (at-least-once). An **updated** file
(new mtime/size → new hash) is re-ingested. The ledger is bounded by an age + count prune. In `leave`
mode the `.processed`/`.error` subdirs are created best-effort (a read-only share doesn't fail start),
so a malformed file on a truly read-only share that can't be moved to `.error` re-logs each poll — fix it
at the source.

#### File handling & quarantine policy (ASVS 5.1.1)

This block lists the file surfaces ASVS 5.1.1 asks about, one row each. Two rules decide what
counts:

- An **upload feature** is any shipped surface where a party other than the host operator, working at
  the host, supplies content that the product persists or processes. Content means a file, a DICOM
  object or a message body. A request body that only steers an operation, such as a search needle or a form
  field, is a parameter and not content. One addition by owner ruling of 2026-09-23: the IDE
  extension's local file pickers count too, although a developer at the host uses them.
- A **download** is any response the product sends with `Content-Disposition: attachment`.

How each part of the list is kept:

- **Receiver rows** follow the `register_source(...)` calls in `messagefoundry/transports/`.
- **Upload-route rows** follow `_UPLOAD_BODY_PATHS` in `api/app.py`, plus a hand-kept list of JSON
  routes whose body is a message. No code marker tells a content body from a parameter body on a JSON
  route, so that list cannot be derived.
- **The IDE picker row** follows the `showOpenDialog` calls in `ide/src/`. The live-debug sample
  choice is a pick list, which the code cannot tell from a menu, so the test pins it by name.
- **The harness row** follows the code units in `harness/` that start a server and build an
  `MLLPDecoder`, and those that build a `QFileSystemWatcher`.
- **The harness sink row** follows the public modules in `harness/sinks/`, which is what the harness
  discovers as sinks. For each, the test checks that the row names it and that it, or a helper it
  imports, names an engine cap constant. That is a tripwire, not proof the cap is enforced; each
  sink's refusal is tested beside it.
- **Download rows** follow the code sites that write a `Content-Disposition` header or build a
  `FileResponse`, and the API routes whose handler is such a site or calls one.
- **The harness client row** follows every code unit in `harness/` outside `harness/sinks/` that
  builds a frame reader (an `MLLPDecoder`, an `X12FrameReader` or a codec's `decoder`) and starts no
  server. The test checks that the row names each one's file and that every frame reader in
  `harness/` is built with a cap, except the one the exclusions below name. The HTTP driver and the
  API client read with no frame reader, so they are named by hand, and nothing checks that no other
  such client exists; the exclusions name the ones known to be uncapped.
- **The rig log and coordination rows** are kept by hand: no code marker tells a file the engine or
  another host wrote from the operator's own. The test checks that each named unit reads through the
  bounded reader, or reads only a tail, and that its file reads nothing whole.
- **Kept by hand:** the reply-capture row, the harness reconcile-loader row, the `/ui` delegates, the
  two limits after the upload table, and the exclusions. For these the test pins each figure quoted beside a code constant, and checks
  that the reply-capture setting and the transports that offer it still match. It does not check that
  nothing is missing.

`tests/test_asvs_file_surface_inventory.py` derives the first seven parts from the code, all but
the two clients the seventh names by hand. It fails the
build when a derived row is missing, when a row names a surface the code no longer has, or when a
figure stops matching the constant named beside it.

**Upload features.**

| Surface | Permitted type | Extension | Maximum size | Unpacked size |
|---|---|---|---|---|
| `file`: local drop directory, `File(...)` | the inbound's declared `content_type` (default `hl7v2`), content-sniffed against that declaration; see the policy below | chosen by `pattern` (default `*.hl7`); the type check reads content, not the extension | `max_file_bytes`, default `DEFAULT_MAX_FILE_BYTES` = 16 MiB (`transports/file.py`) | no unpacking unless `decompress="gzip"` is set; then `max_decompressed_bytes`, default `DEFAULT_MAX_DECOMPRESSED_BYTES` = 64 MiB |
| `remotefile`: SFTP or FTP drop directory, `Sftp(...)` / `Ftp(...)` ([Remote file](#remote-file--sftp--ftp)) | as for `file` | chosen by `pattern` (default `*.hl7`) | `max_file_bytes`, default `DEFAULT_MAX_FILE_BYTES` = 16 MiB, charged against the listed size and again against the bytes read | no unpacking on intake; the connector has no `decompress` setting |
| `dimse`: DICOM C-STORE SCP, an inbound `DICOM(...)`; its size, peer and TLS settings are under [DICOM](#dicom--dicom-inbound-c-store-scp--outbound-c-store-scuc-echo-and-dicomweb-stow-rs-adr-0025) | DICOM objects in the SCP's accepted presentation contexts | not applicable; objects arrive over DIMSE | `max_object_bytes`, default `DEFAULT_MAX_OBJECT_BYTES` = 128 MiB (`transports/dicom.py`), charged before decode | a Deflated Explicit VR LE object is inflated in bounded memory before decode, capped at the lesser of `max_object_bytes` and `DEFAULT_MAX_INFLATED_BYTES` = 16 MiB, the ceiling the codec applies when a Router parses the object (BACKLOG #2104). Setting `max_object_bytes` to `0` or `None` does not remove either cap; the DICOM section says what it does instead |
| `http`: web-service listener, `Http(...)` ([HTTP](#http-web-service-listener--http-inbound-only-adr-0023)) | the inbound's declared `content_type` | not applicable; a request body | `max_body_bytes`, default `DEFAULT_MAX_BODY_BYTES` = 16 MiB (`transports/http_listener.py`); headers `DEFAULT_MAX_HEADER_BYTES` = 64 KiB | no unpacking on intake. The listener decodes no `Content-Encoding` and no transfer coding. It refuses a body whose `Transfer-Encoding` is exactly `chunked`, and reads any other body as sent, up to the cap |
| `mllp`: MLLP listener ([MLLP](#mllp--mllp)) | the inbound's declared `content_type` (default `hl7v2`) | not applicable; a framed stream | `max_frame_bytes`, default `DEFAULT_MAX_FRAME_BYTES` = 16 MiB (`mllpcodec.py`) | no unpacking on intake |
| `tcp`: raw TCP listener ([Raw TCP](#raw-tcp--tcp)) | the inbound's declared `content_type` | not applicable; a framed stream | `max_frame_bytes`, default `DEFAULT_MAX_FRAME_BYTES` = 16 MiB | no unpacking on intake |
| `x12`: X12 EDI listener ([X12 EDI](#x12-edi--x12)) | X12 interchanges | not applicable; a framed stream | `max_interchange_bytes`, default `DEFAULT_MAX_INTERCHANGE_BYTES` = 16 MiB (`parsing/x12/delimiters.py`) | no unpacking on intake |
| `database`: database poller, `DatabasePoll(...)` ([Database source](#database-source--databasepoll)) | rows from `poll_statement`, each handed on as one body in the declared `content_type` | not applicable; table rows | no byte cap of its own; the engine's per-message ceiling below rejects an oversized row after it is read; `poll_max_rows`, default `DEFAULT_MAX_ITEMS_PER_POLL` = 500, bounds rows per poll | no unpacking on intake |
| `/uploads` (POST) and `/ui/uploaded-logs/upload`: uploaded diagnostic logs ([ADR 0134](adr/0134-offline-uploaded-logs-viewer-connection-decoupled-upload-browse-resend-deletion-phi-at-rest-posture-stdlib-multipart.md)) | off unless `[store].uploads_dir` is set. Plain text only, content-sniffed against the extension. A resend, `/uploads/{file_id}/resend`, puts one message from the file onto a chosen inbound's ingress stage. First it runs that inbound's ingress guards, `admit_resubmitted_body` (`pipeline/ingress_guards.py`): the inbound's size ceiling, never above `DEFAULT_MAX_MESSAGE_BYTES` = 16 MiB; `Peek.parse` for an HL7 inbound, or a match against the declared type for any other; the NUL rule; a check that the inbound's charset can hold the text; and, where the inbound sets `validation.strict`, the listener's strict `hl7apy` validation under the same `validation.strict_timeout_s` backstop, whose refusal counts the errors and quotes none. A refusal answers 413, 415 or 422, writes an `upload.resend_reject` audit row, and writes no message | `_ALLOWED_UPLOAD_EXTENSIONS`: `.hl7`, `.hl7v2`, `.txt`, `.xml` | `[store].max_upload_bytes`, default 25 MiB (`StoreSettings`) | not unpacked; see the uploaded-logs policy below |
| `/messages/{message_id}/edit-resend` (POST) and its `/ui` delegate: an operator's edited message body | The edited body re-enters the origin channel's pipeline as a new message, or goes straight to a chosen outbound when `to` is set. A re-route first runs the origin inbound's ingress guards, `admit_resubmitted_body` (`pipeline/ingress_guards.py`): the inbound's size ceiling, never above `DEFAULT_MAX_MESSAGE_BYTES` = 16 MiB; `Peek.parse` for an HL7 inbound, or a match against the declared type for any other; the NUL rule; a check that the inbound's charset can hold the text; and, where the inbound sets `validation.strict`, the listener's strict `hl7apy` validation under the same `validation.strict_timeout_s` backstop, whose refusal counts the errors and quotes none. A re-route whose origin inbound this engine does not hold answers 409. The direct path has no inbound, so only the NUL rule and that ceiling apply, and strict validation, an inbound's setting, never does. A refusal answers 413, 415 or 422, writes a `message_edit_resend_reject` audit row, and writes no message | not applicable; the JSON field `raw` | `_MAX_REQUEST_BODY_BYTES` = 1 MiB, the API's request-body cap; `EditResendRequest.raw` also sets `max_length` 16,000,000 characters, which that cap reaches first | no unpacking |
| `ide/src/testBench.ts` (Load Message Set), `ide/src/stepsView.ts` (Use for Live Values) and `ide/src/liveDebug.ts` (the live-debug sample, a pick list of the `.hl7` files in the message-sets folder): the IDE extension's local file pickers, a 5.1.1 upload feature by owner ruling of 2026-09-23 | any file: each picked path goes to `messagefoundry dryrun`, which runs it against an inbound's declared `content_type` | the two dialogs offer `.hl7` first and also "All files", so they enforce no extension; the live-debug pick list offers only `.hl7` names | `MAX_FIXTURE_FILE_BYTES` = 16 MiB per file (`pipeline/dryrun.py`), raised to the largest `max_message_bytes` an inbound in the graph sets; refused with a message naming the file, before it is read whole. `dryrun` then applies the per-message ceiling below itself. The Steps view also reads its picked sample inside the extension to list its segments. There `MAX_SAMPLE_FILE_BYTES` = 16 MiB (`ide/src/sampleFile.ts`) refuses an over-cap file when it is picked, with a message naming it, and still bounds the read if the file grows later. That cap is fixed: no `max_message_bytes` raises it | no unpacking |
| `harness/mllp.py` (`MllpReceiver`, the Receive tab), `harness/load/sink.py` (`CorrelationSink`) and `harness/reconcile/capture.py` (`CaptureSink`): the test harness's MLLP receivers; and `harness/file_transport.py` (`FolderWatcher`, the File tab's watch pane), which reads each new `*.hl7` file in a directory the engine writes to. The harness is a separate distribution attached to each release, and it is inside the ASVS assessed scope by owner ruling of 2026-10-02 (R1 of `docs/security/ASVS-OWNER-RULINGS-2026-10-02-1130.md` in the vault). These take frames or files from another party, the engine under test, so they count | anything framed, or any `*.hl7` file. The Receive tab shows it, the load sink times it, the capture sink appends it to a JSON-lines file, and the watch pane shows it | the watch pane takes only `*.hl7` names; for the receivers, not applicable: a framed stream | `DEFAULT_MAX_FRAME_BYTES` = 16 MiB per frame, the engine's MLLP default. `0` turns it off, as on the engine. The harness also refuses a negative value. The two sinks take `max_frame_bytes` to change it, and `python -m harness.reconcile capture --max-frame-bytes` passes it on. An over-cap frame drops its connection with no ACK, and none of it is shown or kept. A frame accepted earlier in the same read still gets its ACK before the drop, a delayed one included. The Receive tab and the capture sink count each refusal. The watch pane caps each file at `DEFAULT_MAX_MESSAGE_BYTES` = 16 MiB, the engine's per-message cap. It does not follow a symlink: it checks with `lstat`, and opens with `O_NOFOLLOW` where the OS has it, so a file swapped for a symlink after the check is refused at the open, as a symlink. Windows has no `O_NOFOLLOW`, so there the `lstat` is the only symlink check. It checks the size before it opens the file, checks it again on the open handle so a file swapped or grown in between is judged by what is read, and reads no more than one byte past the cap (`harness/bounded_file.py`). It skips an over-cap file, or anything but a regular file, for good, and logs and counts it. The harness's own MLLP clients read the engine's ACK replies under a frame cap; the client row below gives each one | no unpacking on intake |
| `harness/sinks/mllp.py` (`MLLPSink`), `harness/sinks/tcp.py` (`TcpSink`), `harness/sinks/x12.py` (`X12Sink`), `harness/sinks/rest.py`, `harness/sinks/soap.py`, `harness/sinks/fhir.py` and `harness/sinks/dicomweb.py` (the HTTP sinks, all over `HttpSink`), `harness/sinks/email.py` (`EmailSink`), `harness/sinks/dimse.py` (`DimseSink`), `harness/sinks/file.py` (`FileSink`), `harness/sinks/remotefile.py` (`RemoteFileSink`, the harness SFTP share) and `harness/sinks/database.py` (`DatabaseSink`): the harness's scenario sinks, one module per outbound kind. Each stands up the peer an engine outbound delivers to, so it takes content from another party, the engine under test, and it ships in the harness wheel, inside the ASVS assessed scope by owner ruling of 2026-10-02 | whatever the outbound sends: a framed message or X12 interchange, an HTTP request body, an SMTP message, a DICOM object over C-STORE, a file the engine writes (locally or over SFTP), or a row in the harness outbox table. Each is recorded in memory for the scenario to assert on and never logged | the file and remote-file sinks take any name but a dot-file or the engine's `.part` and `.probe` temps; the rest are not applicable: a stream, a request or a row | MLLP and TCP: `DEFAULT_MAX_MESSAGE_BYTES` = 16 MiB per frame. X12: `DEFAULT_MAX_INTERCHANGE_BYTES` = 16 MiB per interchange. Over either, the connection drops with no reply and nothing is recorded, as on the engine's own listener. HTTP: 16 MiB per body, the same per-message cap, `Content-Length` framed only; a larger body is answered 413 and recorded refused with an empty payload, and any `Transfer-Encoding` is answered 400; the standard library's parser bounds the request line and headers. Email: `MAX_LINE_BYTES` = 4,096 per command or data line, and `MAX_DATA_BYTES` = 32 MiB per message, twice the per-message cap because a body encoded for the wire is larger; over either, the sink answers 500 or 552 and closes. DIMSE: `max_object_bytes`, default 16 MiB, charged against the raw received Data Set before it is decoded; a larger object is answered `0xC000` whatever status the sink was set to give, and recorded refused with an empty payload. The re-encoded Part-10 object is charged again, as on the engine's own SCP. pynetdicom has buffered the whole Data Set before either charge, so this cap bounds decoding and not receipt, the same shape as the engine's SCP. File and remote-file: 16 MiB per file, settable as `FileSink.max_file_bytes`; the remote-file sink scans with a `FileSink` at that default. Regular files only, symlinks not followed (the same `lstat` and `O_NOFOLLOW` check as the watch pane, so on Windows the `lstat` is the only one), the size checked again on the open handle and at most one byte past the cap read (`harness/bounded_file.py`); a larger file, or one that grows past the cap while read, is recorded refused with an empty payload. The SFTP share also fails a write that would grow a file past 16 MiB. Database: `MAX_OUTBOX_PAYLOAD_CHARS` = 16,777,216 UTF-16 code units per payload, never fewer than the characters the engine counts; the read withholds a larger payload on the server, so it is never fetched, and the row is recorded refused with its length | no unpacking, except that a Deflated Explicit VR LE DICOM object is inflated in bounded memory, output discarded, before it is decoded; past the lesser of `max_object_bytes` and `DEFAULT_MAX_INFLATED_BYTES` = 16 MiB it is refused as above |
| `harness/reconcile/compare.py` (`load_messages`, behind `python -m harness.reconcile compare`): the reconcile loader, which reads files another system produced, a capture the capture sink wrote and another engine's export, although the operator names the paths | a JSONL capture, a directory of one-message files, or a batch file of concatenated HL7, split on `MSH` lines | `.jsonl` selects the capture reader, for a named file or one in a directory; any other name is read as HL7 | each file capped at `max_file_bytes`, default `DEFAULT_MAX_LOAD_FILE_BYTES` = 1 GiB, 64 times the per-message cap because a capture or an export holds many messages and is held in memory whole; `--max-file-bytes` changes it. Reads go through the same reader as the watch pane. For a directory the cap is a total across its files, and a refusal says the cap it names is what was left of that total. A larger file, or a named path that is not a regular file, is refused with a message naming it, before it is read whole, and the command exits 2, as it does for any input it cannot read. A JSONL line that is not an object with a string `raw` is refused the same way, by its line number and never its content. A path the operator names is followed if it is a symlink. In a directory, only regular files are read. A symlink is not followed, with the same check as the watch pane, so on Windows the `lstat` is the only symlink check. It is skipped, as is anything else that is not a regular file and an entry removed before it is read, and a warning counts the skips | no unpacking |
| `harness/drivers/mllp.py` (`MLLPDriver`), `harness/mllp.py` (`SendWorker`, the Compose and Send tabs), `harness/load/sender.py` (`PersistentConnection`), `harness/fuzz/transport.py` (`WireMLLPDriver`), `harness/drivers/tcp.py` (`TcpDriver`), `harness/drivers/x12.py` (`X12Driver`) and `harness/drivers/http.py` (`HttpDriver`): at least these harness clients read what the engine under test answers to each message they send, each under a stated maximum, and the exclusions below name the ones that do not yet; and `messagefoundry/apiclient/client.py`, the API client the harness and the web console share, reading each API response body. The engine is another party here, as in the rows above, although these start no server | an ACK or other reply frame, an X12 interchange, an HTTP inbound's answer, or an API response. A reply is read for its acknowledgement code or receipt and shown or counted; an API response is decoded as JSON | not applicable; a reply on the client's own connection | MLLP: `DEFAULT_MAX_FRAME_BYTES` = 16 MiB per reply frame, the engine's MLLP default. A larger frame is refused, never buffered whole and never cut short: the driver and the Compose and Send tabs record the send as failed with `reply refused`, and the load sender counts it in `frame_refusals` and its transport errors, closes the connection without calling it an engine close, and reconnects. The fuzzer caps a reply frame at `_MAX_REPLY_BYTES` = 1 MiB, because an ACK is a few hundred bytes; a larger one makes the case's outcome `malformed`, a finding. TCP: the driver reads at most `DEFAULT_MAX_MESSAGE_BYTES` = 16 MiB, plus at most one 64 KiB read past it, and a reply frame over 16 MiB is recorded as no reply. X12: the same, at `DEFAULT_MAX_INTERCHANGE_BYTES` = 16 MiB. HTTP: the driver reads at most `MAX_REPLY_BYTES` = 64 KiB of an answer and leaves the rest unread, so a longer answer is cut there rather than refused; the driver reads it only for the engine's `message_id` receipt or an error status. API client: `MAX_RESPONSE_BYTES` = 128 MiB per response body, eight times the per-message cap because a message body comes back JSON-escaped at up to six bytes per byte; a larger body raises `ApiError` and none of it is kept | no unpacking. The API client lets `httpx` decode a `Content-Encoding`, and charges the cap on the decoded bytes |
| `harness/load/shardcert_ladder.py` (`read_node_log`, behind the three timing aggregators) and `harness/load/failover.py` (`EngineNode.log_tail`): the load rig's reads of the log each engine node writes. The rig keeps a node log only when `MEFOR_BENCH_KEEP_NODE_LOGS` names a directory, and the timing aggregators read only those kept logs. The rig starts the engine and opens the file its output goes to, but the engine under test writes the content, so it counts as another party's | a node log, read for its timing lines or, on a failed start, for its last lines | not applicable; the rig names each log itself, `<node_id>.log` | `MAX_NODE_LOG_BYTES` = 1 GiB per log, 64 times the per-message cap: the timing aggregators read a whole log, and an INFO-level node log stays far below that in a rung's hold. Reads go through the same bounded reader as the watch pane, but follow a symlink: the rig names each path itself. A larger log, or one that is not a regular file, is refused before it is read, logged with its path and size and never its content, and contributes nothing, the same as a missing log; none of it is read in part. `log_tail` reads only the last `limit` bytes, 4,000 by default, and never the rest | no unpacking |
| `harness/load/coord.py` (`FileDropCoord.read`): the two-box rig's coordination messages, which the other box writes into a directory both share, a mount or a synced folder. Another host writes them, so they count | a JSON object of counts, ports and timestamps, one per file | `<run_id>.<name>.json`, a name the rig builds; nothing else in the directory is read | `MAX_COORD_MESSAGE_BYTES` = 1 MiB per message; a real one is a few KiB. Read through the same bounded reader as the watch pane, but a symlink is followed, so the cap and the regular-file check apply to its target. A larger file, or one that is not a regular file, raises `CoordMessageRefused` naming the file and the reason, which stops the run with that reason rather than being polled again until a timeout that would name the wrong cause. It is not a timeout, so no caller that treats a missing optional message as absent swallows it; not every command turns it into a clean abort yet, and where none catches it the run ends with a traceback | no unpacking |
| `capture_response` / `reingress_to`: a partner's reply captured from an outbound, and re-ingressed through a `Loopback()` inbound when `reingress_to` is set ([ADR 0013](adr/0013-query-response-orchestration.md)) | whatever the partner returns on that hop. A re-ingressed reply does not pass the `Loopback()` inbound's listener checks, so the read bound in this row is its bound | not applicable; a reply on the outbound's own connection | the outbound's own read bound: `DEFAULT_MAX_RESPONSE_BYTES` = 16 MiB (`transports/bounded_read.py`) on REST, SOAP, FHIR and DICOMweb; `max_frame_bytes` on MLLP and TCP; `max_interchange_bytes` on X12; `capture_max_rows`, default 100, plus a fixed byte cap on a database outbound, both checked only after the whole result set is fetched | no unpacking on capture |

Two limits apply after intake. The first covers the rows keyed by a connector type, the first eight.
The other rows skip the listener, so it does not reach them, except that `dryrun` applies the same
ceiling to what the IDE row feeds it. The second covers content from any row:

- **The engine's per-message ceiling.** The listener applies `DEFAULT_MAX_MESSAGE_BYTES` = 16 MiB
  (`parsing/peek.py`) to each received body, measured in characters once a text body is decoded. A
  body over it is kept as an `ERROR` message and never processed. An HL7 v2 inbound replaces it with
  its own `max_message_bytes` when that is set. The DICOM SCP never accepts an object over it: its
  object cap is clamped to the same 16 MiB (BACKLOG #1910).
- **Unpacking a payload.** When a Router or Handler parses a Deflated DICOM Part-10 payload,
  `guard_part10_deflate` caps the inflate at `DEFAULT_MAX_INFLATED_BYTES` = 16 MiB, with no setting.
  For a Handler that unpacks content itself, the engine offers `gzip_decompress`,
  `deflate_decompress`, `deflate_decompress_with_tail` and `zip_decompress` (`parsing/compression.py`, [ADR 0123](adr/0123-compression-codec-gzip-zip-deflate-file-connector-compress-decompress-option.md)).
  `deflate_decompress_with_tail` is for a stream with other data after it, and returns that data
  unread beside the body; its ceiling bounds the one stream.
  Each takes `max_output_bytes` as a required keyword with no default, so the Handler author must
  choose the ceiling. Passing `None` removes it, and has to be written out. `zip_decompress` also caps
  the member count at `max_entries`, default 1024, and refuses the whole archive when one member's
  name or content fails the checks in `parsing/sniff.py`. A Handler is ordinary Python, though, and
  can unpack with any library instead, such as `gzip` or `zipfile` directly. The engine then sets no
  bound, and the Handler author owns the unpacked-size limit.

**Downloads.** The "Downloads are made safe at serve (ASVS 1.3.4)" clause below covers the attachment
row only. The two export rows are made safe as their own row says.

| Surface | What it serves | Type and file name | Maximum size | How it is made safe |
|---|---|---|---|---|
| `/messages/{message_id}/attachments/{attachment_id}` (GET) and its `/ui` delegate ([ADR 0105](adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md)) | one detached document, byte for byte | an allow-listed type or `application/octet-stream`; the extension comes from the same table, default `.bin` | the stored document, already bounded at intake by the rows above | the ASVS 1.3.4 clause below |
| `/messages/export` (GET and POST) | stored message bodies, decrypted, one JSON object per line | `application/x-ndjson`, `messages-export.ndjson` | at most `limit` bodies per call, default 1000, ceiling 100,000 (the route's `limit` bound and `MessageExportRequest.limit`); an explicit id list is capped at `MAX_EXPORT_IDS` = 100,000 | `_export_ndjson_line` writes each body as a JSON string, so no body can break the one-object-per-line framing. The route needs step-up with `messages:export` and `messages:view_raw`, rechecks channel scope on each body, and writes one `messages_export` audit row before it streams ([SECURITY.md](SECURITY.md#route--permission-map-engine-api)) |
| `/audit/export` (GET) | audit rows as CSV: metadata only, never a message body | `text/csv`, `audit-export.csv` | at most `limit` rows, default 10,000, ceiling 1,000,000 (the route's `limit` bound) | every cell passes through `_csv_safe`, which neutralizes spreadsheet formula injection ([PHI.md](PHI.md#logging-inventory-1611--1623)). The route needs `audit:export` and writes one `audit.export` row before it streams |

**Excluded, with the reason.**

- `loopback`, `passthrough` and `timer` are registered sources that read nothing from outside
  themselves. `Loopback()` re-ingresses a captured reply, which has its own row above.
  `PassThrough()` re-ingresses what a Handler produced, and `Timer(...)` fires on the clock.
- A Handler's live lookup result is data it reads to shape its output, not content the product keeps
  as a message ([ADR 0010](adr/0010-handler-callable-db-lookup.md),
  [ADR 0043](adr/0043-fhir-read-lookup.md)). `fhir_lookup` reads are capped at
  `DEFAULT_MAX_RESPONSE_BYTES` = 16 MiB. `db_lookup` reads are capped at `max_rows` rows per call,
  default `DEFAULT_DB_LOOKUP_MAX_ROWS` = 500, charged at the fetch. A larger result fails the lookup
  rather than being truncated. There is no byte cap, so a row's own width is still the statement's
  bound.
- The harness's other file reads take the host operator's own files, so the inclusion rule above
  does not count them. Among them, at least: load profiles and corpora, fuzz replay files and a load
  baseline. The logs of the engines the load rig starts are not among them: the engine writes them,
  so they have their own row above. The fuzzer's `frames` (`harness/fuzz/mutate.py`) decodes a fuzz
  case's wire bytes, generated by the fuzzer or read from a replay file the operator names, never the
  engine's reply, so it takes no frame cap.
- **Not settled: the load rig's own reads of the engine API.** The harness client row above lists
  the clients whose reply reads have a stated maximum; it is not every harness read of an engine
  reply. At least these read the engine's API answer with no byte cap of their own:
  `harness/load/rigadmin.py` (the rig's sign-in and session calls),
  `harness/load/failover.py` and `harness/load/shardcert.py` (their `httpx` health and status
  reads), and the DIMSE driver's C-STORE responses, which pynetdicom reads under its own defaults.
  The engine under test is another party here as in the rows above, so these are uncapped
  surfaces that belong in the table once each is bounded.
- `/ui/static` serves first-party assets that ship in the package. `AllowlistedStaticFiles` serves
  only `ALLOWED_STATIC_EXTENSIONS` (`.css`, `.js`), and it sends no `Content-Disposition`.
- The API routes not listed above that take a body are treated as parameter routes, capped by
  `_MAX_REQUEST_BODY_BYTES` = 1 MiB. That classification is kept by hand. The route closest to the
  line is the browser CSP report sink, `/ui/csp-report`: it takes an unauthenticated report, parses
  it, logs a bounded summary and keeps nothing.
- Local admin CLI commands run as the host operator at the host, which the rule above excludes. The
  ones that read or write a file include: `restore` and `restore-verify` of a `.mfbak` archive,
  which cap the store member at `_MAX_RESTORE_MEMBER_BYTES` = 16 GiB; `restore --config-to`, which
  also caps the config bundle at `_MAX_CONFIG_MEMBERS` = 10,000 members and
  `_MAX_CONFIG_BYTES` = 1 GiB; `import corepoint`; `cert import`; `dryrun` and `check` run by hand,
  which read fixture files under the IDE row's cap (`check` reads each fixture's `.expect` sidecar
  under the same cap); and `support-bundle`, which
  writes its archive to the local disk and serves nothing.
- `/ai/chat` (POST) carries a prompt, not a file: a parameter that `AiChatRequest.prompt` caps at
  200,000 characters, which the engine relays to the configured AI provider ([AI.md](AI.md)).

**The embedded-document detach is a STAGE, not a receiver, and its ceilings are stated here
because the requirement asks for unpacked size wherever content is accepted.** When an inbound sets
`stream_threshold_bytes` (default `None`, so the whole path is OFF unless a feed asks for it), a body
at or above that size has its opaque documents detached from the transformable skeleton
([ADR 0105](adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md))
and stored for the attachment-download route above. Nothing new arrives on the wire -- the bytes came
in through one of the receivers already listed -- which is why it has no row of its own. Two
ceilings bound it, and they bound different things:

- the inbound's own **`max_message_bytes`** bounds a SINGLE body, and applies whether or not a detach
  happens;
- **`[inbound].stream_inflight_budget_bytes`** bounds the AGGREGATE bytes of over-threshold bodies
  concurrently mid-detach across all inbounds. Its default is `0`, which means **unlimited in the
  aggregate**. Read that precisely: no single body escapes `max_message_bytes`, but the number of
  such bodies in flight at once is uncapped until an operator sets this. A detach that would cross a
  positive budget is refused with backpressure, `ERROR`-ed rather than accepted-and-dropped.

Permitted **types** on this path are whatever the inbound declared. Outside the handful of families
with a leading magic signature, a detached document's type is accepted as sent
(`messagefoundry/parsing/sniff.py`), so this stage is not a content gate and must not be read as one.

The **directory
source's** handling of an untrusted drop directory is fixed policy (the HTTP uploaded-logs surface has
its own policy block below):

- **Permitted type — the inbound's declared `content_type` (default `hl7v2`).** Files are selected by
  the `pattern` glob (default `*.hl7`), and every candidate is **content-sniffed against that declared
  type** before its bytes reach the pipeline: an `hl7v2` drop (the default, and how an inbound that
  declares nothing is treated) must begin with an HL7 header segment (`MSH`/`FHS`/`BHS`, after an
  optional UTF-8 BOM / MLLP start byte / leading whitespace), and each other structured type must lead
  with its own format signature. A file whose content **contradicts** its declaration — a PDF on a
  `json` inbound, a headerless body on an `hl7v2` one — is rejected on **content, not extension**
  (ASVS 5.2.2). It is a declared-type **conformance** check, not an HL7-only gate: an inbound declaring
  a non-HL7 `content_type` bypasses HL7 handling entirely and its exact bytes reach the
  content_type-aware pipeline (ADR 0004). The two declarations that carry no reliable leading signature
  — `binary` (opaque bytes) and `text` (arbitrary) — are accepted **unchecked** by explicit policy; the
  pipeline codec/parser stays the real validator that records `ERROR`.
- **Maximum size.** `max_file_bytes` (default **16 MiB**, matching the MLLP frame cap). The cap is
  charged on the handle the read opens, not on an earlier `stat()`: an oversize file is rejected by
  its handle's size **before** it is read into memory, and the read itself stops at the cap plus one
  byte, so a file that grows after it was listed is refused too (OOM / DoS guard, BACKLOG #2507).
  `None`/`0` disables it.
- **Links are refused at listing, read and move time.** The listing looks at each name without
  following a link there. A drop is read only if the opened handle is a regular file at the listed
  name inside the watch directory, reached through no symbolic link or junction: POSIX opens each path
  component with `O_NOFOLLOW`, and Windows opens each one as itself and holds the directories it
  passes, then compares the handle's final path. The listing, the read and the move open a link
  itself rather than what it names, so on Windows a link to a UNC path or a named pipe does not reach
  that server through them (BACKLOG #2535); the one exception is listed below. The
  same check runs again just before the file is archived, quarantined or deleted, and must find the
  very file that was read: a file renamed over the name after the read is left for the next scan to
  read rather than archived or deleted unread. POSIX then acts on the name relative to its checked
  directory; Windows renames or deletes through the checked handle, so neither resolves the name again.
  `.processed` and `.error` are opened the same way for every move, so if either is replaced by a link
  after start the move is refused and nothing is written through the link; one that is already a link
  or junction when the source starts fails the start, naming `processed_subdir`/`error_subdir`. To
  archive elsewhere, set those to an absolute path outside the watch directory. A refused entry is
  logged (a WARNING the first time) and left in place, never read or moved. This includes a link that points
  inside the watch directory: drop real files, not links. **What this does not cover, at least:** a
  hard link, which is the same file as every other name for it, so an outside file hard-linked into the
  drop directory is read like a drop (keep the drop directory on a volume holding nothing a partner may
  not read; Linux's default `fs.protected_hardlinks` also stops a user linking a file they cannot
  write); on POSIX, a file renamed over the name in the instant between the last check and the unlink
  that removes the original (for `delete`, or after an archive had to copy), which is deleted unread;
  on Windows, a deduplicated, cloud or tiered file (a reparse point that names no other path), which
  is opened a second time by name so its filter can serve the data, and that second open follows a
  link swapped in at that instant before the identity check refuses it; a filesystem whose inode
  numbers are not stable (some FUSE or sshfs mounts, CIFS with `noserverino`), where the identity check
  fails, so each file is left in place and read again; and an archive directory configured *outside*
  the watch directory, which is the operator's and is used as configured, judged by its configured
  path and not by where links lead.
- **Decompression is off by default; opt-in single-stream gzip is bomb-guarded** (ADR 0123). With no
  `decompress=` set the connector performs no decompression itself, so it materialises nothing beyond
  `max_file_bytes` where that cap is set. An earlier revision went further and said there is "no
  unpacked-size surface"; that was wrong — a file's *payload* can carry its own compressed stream. The
  shipped case is a **Deflated Explicit VR LE** DICOM object, which the drop's content sniff accepts on
  the `DICM` magic alone and which therefore reaches the pipeline with its inflated size unexamined.
  That inflate is bounded where the object is unpacked rather than at ingest: at **16 MiB**, with no
  per-connection knob, when a Router or Handler parses it (`guard_part10_deflate` in
  `parsing/dicom/_inflate.py`, called from `DicomPeek.parse` and `DicomDataset.parse`), and at
  `max_object_bytes` when an outbound C-STORE SCU forwards it. The guard finds the deflated Data Set
  with pydicom's own header readers, the ones `dcmread` runs just before it inflates. So it bounds the
  same bytes `dcmread` inflates, even behind a malformed file meta. That covers at least a missing or
  wrong group length, a second transfer-syntax element, and a forced read with no preamble. A site
  dropping DICOM into a watch
  directory should size those two ceilings deliberately rather than read this bullet as saying no
  unpacking happens. When
  `decompress="gzip"` is enabled it gunzips each drop **before** the content sniff, the AV scan, and the
  batch split (so all three see the real bytes), and `max_decompressed_bytes` (default 64 MiB) caps the
  *decompressed* size — a decompression-bomb guard the compressed-only `max_file_bytes` cap cannot
  provide (ASVS 5.2.3). A corrupt or over-ceiling archive is **quarantined to `.error`, never
  accept-and-dropped**, and the decompressed body is never logged. Multi-entry zip stays Handler-composed.
- **Malicious / malformed-file behavior — quarantine, never a silent drop.** An oversize file, or one
  whose content contradicts its declared type, is **moved to the `.error` subdirectory** (preserved for
  the operator) and logged. A *textual-but-non-conformant* HL7 file still flows through and is recorded
  as an `ERROR`-status message by the parser (raw preserved in the store). A **transient** read failure
  (file locked / mid-write) or an **infrastructure** failure (store unavailable) **leaves the file in
  place to retry** next scan — never an accept-and-drop. A local File source reads a file only once its
  size and modification time are **unchanged since the last poll that saw it** (the settle gate,
  BACKLOG #1811), so a partner that pauses between writes for less than `poll_seconds` is waited out. It
  is always on. The cost is one poll of latency per file, and one more poll before a retry of a file
  left in place after a read, scan-hook or hand-off failure. It cannot see at least these: a partner
  that pauses for longer than `poll_seconds`, a same-length rewrite inside the share's modification-time
  resolution, and a copier that sets the final size first and holds the modification time fixed while
  it fills the file in. For those, use the partner's write-then-rename, or for the first a
  `min_age_seconds` longer than its pause. The SFTP/FTP source has the same gate on the listed size
  alone (BACKLOG #2071); `RemoteFileSource._settled` says where it differs. As a backstop, the source also compares a file's
  size and modification time on each side of the
  read (BACKLOG #116). A file that changes **during** the read is not emitted that scan. One that
  changes **after** it is not moved or deleted, so the next scan reads it whole, and a WARNING says the
  message already handed off may be cut short. That message is **not a duplicate**: the pipeline treats
  it like any other message, and a file that keeps growing can yield one on more than one scan before
  the whole one follows. The WARNING is the only thing that ties them together. SFTP/FTP sources
  compare sizes the same way when the server reports one. A remote `leave` source skips the
  after-the-read check (the during-the-read one still runs), so it logs no WARNING, and nothing ties a
  cut-short message to the whole one. It still re-reads a grown file, because its dedup key folds in
  the listed size. A local `leave` source does warn.
- **Traversal-safe output naming.** The destination resolves `{HL7-path}` placeholders to a **single safe
  filename** (path separators / unsafe chars stripped, leading dots removed, `.`/`..`/reserved device
  names fall back), so an attacker-controlled field can't write outside the target dir or shadow
  `.processed`/`.error`.

**Trusted-directory assumption.** The poll directory is a **trust boundary** — write access to it is
equivalent to write access to the engine (a dropped file is executed as data through the full pipeline).
There is **no built-in antivirus / content-malware scan** (ASVS 5.4.3): for a less-trusted or remote/SMB
drop source, front it with an AV/ICAP scan or a staging gateway *before* files land in the poll
directory, and lock the directory's ACLs down to the engine's service account + the upstream producer
(see [SERVICE.md](SERVICE.md)).

For an **in-process** scan, the engine exposes a **pre-ingest scan-hook seam**: an operator/plugin calls
`messagefoundry.transports.file.set_scan_hook(hook)` to install a scanner that runs over the raw bytes of
**every** inbound file — both the local `File(...)` source and the remote `Sftp(...)`/`Ftp(...)` source —
*before* they enter the pipeline. The seam is **off by default** (no-op) and format-agnostic (it sees raw
bytes, so it works for HL7, X12, or any payload); it is the integration point for an in-process
AV/ICAP/YARA scanner, complementing — not replacing — the gateway-fronting above.

**Enforced precondition, fail-closed (ASVS 5.4.3, BACKLOG #204).** MessageFoundry does **not** ship an ICAP
client (that stays an operator/plugin integration), but the *enforcement point* is built and mandatory:
when a hook is installed it is a **precondition on ingest**, not an advisory pass, and unscanned content
can never reach the pipeline on either failure axis. (1) A **content rejection** — the hook raises
`ScanRejected` — quarantines the file to `.error` and never emits it. (2) A **scanner malfunction** — the
hook raises **any other** exception (the AV/ICAP service is unreachable, a plugin bug) — is fail-closed
too: the file is **not emitted** and is left in place to be re-scanned on the next poll once the scanner
recovers (at-least-once), never passed through unscanned. This is the **operator's responsibility to
uphold the contract**: MessageFoundry guarantees the hook runs and that neither a rejection nor a scanner
outage can leak content past it; the operator supplies a scanner that actually inspects the bytes.

#### Uploaded-logs file policy (ASVS 5.1.1)

The **HTTP uploaded-logs** surface ([ADR 0134](adr/0134-offline-uploaded-logs-viewer-connection-decoupled-upload-browse-resend-deletion-phi-at-rest-posture-stdlib-multipart.md))
is a **separate, opt-in** file feature — an operator uploads a **plain-text diagnostic log** over
POST `/uploads` (or the web-console delegate POST `/ui/uploaded-logs/upload`, which backs the very same
core handler) to browse/re-send it offline. It is **off unless `[store].uploads_dir` is set**, and its
upload chokepoint enforces a fixed policy independent of the directory-source policy above:

- **Permitted types — text only.** An extension allowlist (`.hl7`, `.hl7v2`, `.txt`, `.xml`) is enforced
  on the sanitized display filename **and** the content is sniffed against it: `.hl7`/`.hl7v2` must begin
  with an HL7 header segment (`MSH`/`FHS`/`BHS`), `.xml` with a leading `<`, `.txt` must be NUL-free
  decodable text (ASVS 5.2.2). A disallowed extension or a content/extension mismatch (e.g. PNG bytes in
  a `.hl7`) is refused at the chokepoint — before any PHI is written — with **HTTP 400** and a
  metadata-only `upload.reject` audit. In addition, POST `/uploads` rejects any **non-text or
  metadata-bearing container** body (a NUL-byte / control-character-dense payload, or JPEG/PNG/PDF/ZIP —
  incl. DOCX — magic bytes) with **HTTP 415** (ASVS 14.2.8); because only plaintext is ever accepted, no
  embedded-metadata container (EXIF/XMP/`docProps`) can reach storage, so there is nothing to strip.
- **Maximum size.** `[store].max_upload_bytes` (default **25 MiB**) caps a single uploaded file; the
  global 1 MiB HTTP body cap is raised to this value **only** on the two upload routes.
- **No decompression / unpacking.** Uploads are **never unpacked** — unpacked size equals file size, so
  there is no zip-bomb / unpacked-size surface (ASVS 5.2.3 is N/A for this surface by construction). The
  `uploads.py` `split_batch` helper is an **HL7 batch splitter** (it slices an HL7 `FHS`/`BHS` batch into
  its constituent messages), **not** an archive reader.
- **Per-user quotas + retention.** Each uploader is bounded by `[store].max_upload_files_per_user`
  (default **100**) and `[store].max_upload_total_bytes_per_user` (default **250 MiB**); an upload that
  would exceed either is refused **HTTP 409** with a metadata-only `upload.reject_quota` audit, before any
  write. Stale PHI-at-rest is age-pruned: blob+meta pairs older than `[store].uploads_retention_days`
  (default **30**) are deleted — opportunistically at save time and by a periodic sweep — every prune
  audited (`upload.prune`, file id + uploader only, never content). These quota/retention defaults are
  **on** with a `ge=1` floor, so the control cannot ship disabled once `uploads_dir` is set (ASVS 5.2.4).
- **Malicious / mismatched-file behaviour.** A rejected upload is **never stored**: the disallowed
  extension / content-mismatch path returns **HTTP 400** (`upload.reject`), and the non-text / container
  path returns **HTTP 415** — both metadata-only-audited, so a PHI body is never persisted or logged.
  (There is **no** antivirus/content-malware scan on the upload path — the `ScanRejected` pre-ingest
  scan-hook seam applies only to the `File(...)`/remote directory sources above, not to HTTP uploads.)
- **Consent affordance (ASVS 14.2.8).** The `/ui/uploaded-logs/upload-form` page states, above its submit
  button, that the original filename and the uploader's username are stored and shown to the uploader
  and to authorized operators holding `files:access_any`, and recorded in the audit log — **submitting
  the form is the consent**; the POST `/uploads` OpenAPI docstring states the same for programmatic
  callers.
- **Owner-only access (ASVS 8.2.2).** An uploaded file is reachable only by the **account** that
  uploaded it — keyed on the immutable `Identity.user_id`, not the reusable username: the listing is
  filtered to the caller, and browse / resend / delete answer **404** for anyone else, audited as
  `upload.denied` (which principal was refused, which file, which operation — never a filename or
  content). `files:access_any` (Administrator) is the explicit cross-operator override. The rule and
  its rationale live in
  [SECURITY.md](SECURITY.md#uploaded-files-phi-at-rest); the age-based retention prune above is
  deliberately owner-blind.

**Downloads are made safe at serve (ASVS 1.3.4).** The attachment download route (GET
`/messages/{message_id}/attachments/{attachment_id}`, and its `/ui` delegate) serves the stored bytes
**verbatim** (the preserve-the-original invariant forbids rewriting a clinical payload) but neutralizes
them at the response. An SVG is the exception: it is served as a copy rebuilt from a tag and attribute
allow-list, or refused with HTTP 422 when it cannot be vetted, and the stored value stays verbatim. The
rules are recorded once, in
[ADR 0105's 2026-09-28 amendment](adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md). The sender-influenced OBX-5.2 MIME goes through `_safe_attachment_content_type`,
which is an **allow-list**: it declares the stored label only when the label exactly names one of a short,
reviewable set of inert types (`application/pdf`, `application/dicom`, `application/json`, `text/plain`,
`text/csv`, and the raster image types), matched case-folded and length-bounded. Everything else is served
as `application/octet-stream` -- every **browser-active** type (`text/html`, `image/svg+xml`,
`application/hta`), every type nobody listed, and every non-clean or over-long value. The direction
matters: the earlier control listed the browser-active subtypes to refuse, which asked a reviewer to prove
no further executable type existed, and `application/hta` showed that negative could not be proved. The
same table supplies the download-name extension, defaulting to `.bin`, so the served filename is a
property of the product rather than of the host's MIME registry.

The allow-list decides what is **declared**, never whether the file is served: an unrecognized type
downloads exactly as a refused one does. The response carries `Content-Disposition: attachment` (a
download, never an inline render), `X-Content-Type-Options: nosniff` (no MIME re-sniff), and
`Content-Security-Policy: default-src 'none'; sandbox; frame-ancestors 'none'` (an opaque origin with scripts/forms disabled, and no framing),
re-asserted on the `/ui` delegate from **outside** the console's own CSP writers, so a browser-active
representation can never execute in the application origin, and none can be framed.
`frame-ancestors` is named in that policy rather than left to the API's security header
floor because it takes **no fallback from `default-src`** -- without it, the strictest
policy the engine writes was the one response family carrying no framing decision at all
(ASVS 3.4.6).

`application/pdf` is allow-listed by a decision recorded beside the table in `api/app.py`, not by
oversight: a PDF can carry script that runs in a viewer once a saved file is opened, but that script runs
against the document rather than against the serving origin, and the declared type stops governing the
moment the file is on disk. The instrument for the local-open threat would be content scanning, which this
route does not do.

### Remote file — `Sftp(...)` / `Ftp(...)`

**One** connector type (`REMOTEFILE`) with two factories, each **source *and* destination** — the `File(...)`
poll/write shape against a remote server, selected by an internal `protocol` setting:

- **`Sftp(...)`** — SSH file transfer over **paramiko**, behind the **`[sftp]` extra**
  (`pip install 'messagefoundry[sftp]'`, lazily imported so an install that never uses SFTP skips it).
  **Host-key verification is ON by default** (the system host keys plus an optional extra `known_hosts`,
  paramiko `RejectPolicy`); an unknown key is **refused** unless `MEFOR_ALLOW_INSECURE_TLS` is set (and
  loudly logged when it is). **Since #329 this cell routes the escape through the clamped
  `weakened_tls_escape_permitted_here()`** — like the `tls_verify` / `encrypt` cells elsewhere in this
  document, so on a production-PHI enforcing instance the escape is inert and an unknown host key stays
  refused (`RejectPolicy`) even with the variable set; it takes effect only on a non-enforcing / non-PHI
  instance.
- **`Ftp(...)`** — stdlib `ftplib`, **no extra**: `tls=False` is plain FTP, `tls=True` is **FTPS**
  (explicit TLS + `PROT P`, encrypting the control *and* data channels). FTPS **verifies the server
  certificate and hostname by default** (a verifying `SSLContext`, not ftplib's no-verify fallback).
  Plain FTP is cleartext, so supplying a `username`/`password` over it is **refused** (the credential
  itself would cross in the clear) — use FTPS or `Sftp(...)`; an *anonymous* plain-FTP hop is governed by
  the [`cleartext_accepted`](#declaring-a-cleartext-hop-cleartext_accepted) declaration below.

| Setting | Dir | Default | Meaning |
|---------|-----|---------|---------|
| `host` | both | — (required) | the remote server — the `[egress].allowed_remote` key. Use `env()` for a DEV/PROD-specific host. |
| `port` | both | `22` (`Sftp`) / `21` (`Ftp`) | server port |
| `remote_dir` | both | — (required) | remote directory to poll / upload into |
| `username` | both | — (unset) | login user (unset = anonymous, FTP only) |
| `password` | both | — (unset) | login password — a **secret**, via `env()`. Refused over plain `ftp`. |
| `private_key` | both | — | **`Sftp` only** — the **text** of an **RSA** private key, not a path; a **secret**, via `env()`. See *RSA key text only* below the table. |
| `key_password` | both | — | **`Sftp` only** — **refused** (BACKLOG #1352): an encrypted SFTP key cannot meet the [wrap floor](#encrypted-private-keys-must-meet-the-wrap-floor), so supply `private_key` unencrypted through `env()`. Setting this fails at `check` |
| `known_hosts` | both | — | **`Sftp` only** — an *additional* `known_hosts` file (the system host keys are always loaded) |
| `tls` | both | `false` | **`Ftp` only** — `true` selects **FTPS** (explicit TLS); `false` is plain FTP. An FTPS **upload** to an off-box host is **refused on a stock instance** unless `[tls].crl_file` reaches the hop or the connection declares `tls_revocation_attested` with a reason (BACKLOG #2193). The inbound FTPS poll has no such gate |
| `tls_allow_expired` | both | `false` | **`Ftp` only** — honour an FTPS server cert whose validity period has lapsed while still verifying the chain, and the hostname too unless a hand-built spec sets `tls_check_hostname = false` (#129, ADR 0094). Same contract as the [MLLP `tls_allow_expired` row](#mllp--mllp): **no posture gate and no escape variable covers it**. It is reported, in both directions, by the per-build WARNING, `messagefoundry check` and `security_loosenings()`; CORRECTED 2026-10-01, this row said no loosening register covered it, and the inbound poller was in fact listed nowhere until then. The FTPS *upload* has a revocation gate since BACKLOG #2193. The inbound FTPS poll has **none**. It loads `[tls].crl_file` when one is set (vault BACKLOG #2370), but without one an expired *and* revoked partner certificate crosses there with nothing refusing it. Put the connection name and a removal date in your own risk register |
| `tls_ca_file` | both | — | **`Ftp` only, FTPS** (#1180) — pins this hop to one private CA. See [Pinning a private CA per connection](#pinning-a-private-ca-per-connection-tls_ca_file) |
| `tls_ca_pin` | both | — | **`Ftp` only, FTPS** (vault BACKLOG #2371) — the SHA-256 of `tls_ca_file`; a mismatch is refused. See [The engine checks the file at every start and reload](#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin) |
| `pattern` | in | `*.hl7` | filename glob to pick up |
| `poll_seconds` | in | `5.0` | poll interval. It is also the **settle window**: a file is read only once it lists at the same size as at the last poll that saw it (BACKLOG #2071), so every file waits at least one poll. The gate is always on and has no setting. It reads the listed size alone, so it cannot see a same-size rewrite, nor anything on a server that lists every file at size 0. |
| `min_age_seconds` | in | `0.0` | **accepted but not honoured on a remote source today** — the connector never reads it (a remote directory listing carries no reliable mtime). Only `File(...)` implements it; the settle gate on `poll_seconds` above, and the partner's own write-then-rename, are what guard against partial reads here. |
| `after_read` | in | `move` | `move` (→ `processed_subdir`), `delete`, or `leave` (process **in place**, #142 — a durable dedup ledger keyed on a hash of the **full remote path** + size ensures a left file is ingested once) |
| `max_file_bytes` | in | `16 MiB` | **charged twice, and the second charge is the one that binds.** Before the retrieve, against the size the **server reported** in its own directory listing — an over-size entry is moved to `error_subdir` without being read. Then **during** the retrieve, against the **bytes actually read**: the download streams in 1 MiB chunks and is cut off at the first byte past the budget, so a share that lists a small file and then delivers an arbitrarily large body is refused mid-transfer rather than buffered whole (BACKLOG #1191). Either refusal quarantines the file to `error_subdir` and logs it — never a silent drop, and never left in place to be re-pulled every poll. `None`/`0` = unlimited, in both charges. |
| `poll_max_files` | in | `500` | most files one poll will take. The rest stay on the share and the next poll takes them — a **deferral, not a drop**. Identical in shape and reasoning to the `File(...)` row; see [*Per-tick poll ceilings*](#per-tick-poll-ceilings). `None`/`0` = unlimited. |
| `validate_directory` | both | `false` | validate `remote_dir` **at startup** (#114): unreachable/unusable reports the connection **`failed`** (ADR 0031) instead of deferring to run time. The probe is a **listing** — it never creates. **Out:** the upload dir is then never `ensure_dir`ed either, on send or by `POST /connections/{name}/test`. Instead every send first **lists** `remote_dir`, so the account needs list permission there even with `overwrite = true`, at one extra round trip per delivery. An upload into a vanished dir then fails **retryably** rather than dead-lettering on the partner's permanent no-such-dir; a credential refusal on that listing stops the lane. Left off (the default) the upload dir is still created on first send, but the creation is now logged as a `WARNING`. |
| `processed_subdir` / `error_subdir` | in | `.processed` / `.error` | where read / failed files go |
| `filename` | out | `{MSH-10}.hl7` | upload name (supports `{HL7-path}` placeholders, sanitized to a **single safe filename** exactly as `File(...)`) |
| `overwrite` | out | `false` | overwrite vs. uniquify a name collision (never a silent clobber). Left `false`, each upload first **lists** `remote_dir` to find a free name, so the account needs list permission there, and `POST /connections/{name}/test` checks it. A listing that fails writes nothing and is retried; `RemoteFileDestination._unique` states the rule (BACKLOG #1936). Any entry of the same name counts as a collision, a symlink or a directory as well as a file (BACKLOG #2082). On a write-only drop directory, only `true` delivers. It replaces any file of the same name, so pair it with a `filename` that is unique per message. |
| `encoding` | out | `utf-8` | charset the payload is encoded with before upload (the **source** hands the retrieved bytes to the pipeline and never uses it). A payload that cannot be encoded in it is a permanent `encoding` refusal. On a live send it dead-letters on the first attempt, before anything is sent, and is never retried. The error names the charset, never the content. |

- **Unencrypted, RSA-2048 or larger (BACKLOG #1352).** An encrypted `private_key`, or any
  `key_password`, is refused at construction: paramiko opens an encrypted key only through MD5
  (legacy PEM) or bcrypt_pbkdf (OpenSSH format), and neither is an approved key derivation. Keep
  the key unencrypted in the secret store that `env()` reads (`ssh-keygen -p -N '' -f <key>`
  removes a passphrase). An RSA key under 2048 bits is refused at construction too, so `check`
  reports it; the connector checks the size again when it loads the key.
- **RSA key text only.** The connector loads `private_key` with paramiko's `RSAKey` and nothing else.
  Two encodings of an RSA key load: PKCS#1, whose PEM header names `RSA PRIVATE KEY`, and the
  OpenSSH format, whose header names `OPENSSH PRIVATE KEY`. At least these are refused:
  - an Ed25519 or ECDSA key, in either encoding;
  - an RSA key in PKCS#8 form, whose header names only `PRIVATE KEY`;
  - a file path, which is read as key text.

  Building the connection does not parse the key. The error comes on the first connect,
  before any network traffic, as a permanent `SFTP connection rejected: ...` error. Its wording can
  mislead: an Ed25519 key in OpenSSH form reports `unpack requires a buffer of 4 bytes`. Measured
  against paramiko 5.0.0, the locked version.
- **A slow SFTP server is retried; a refusing one is not (BACKLOG #1999).** A server that stalls in
  the SSH banner, the key exchange or authentication is a **transient** error, and so is one that
  drops the connection before the key exchange completes, so the delivery retries. A host-key
  rejection stays permanent, and an authentication refusal stays a credential fault that stops the
  lane (ADR 0095). How the connector tells the two apart, and which paramiko bounds apply, is stated
  once, in `remotefile._sftp_slow_peer`'s docstring.
- **A busy FTP server is retried; a credential or configuration fault stops the lane (BACKLOG
  #2083).** While an FTP session opens, a refusal is classed by its step and its text. A server at
  its connection limit is retried. A TLS refusal and a refused greeting are configuration faults. An
  unclear login refusal is a credential fault. Either one stops the lane and keeps the queue under
  the default `credential_fault_policy` (ADR 0095), since every queued message would meet the same
  refusal, and the alert names which fault it was. The 5xx rules are stated once, in
  `remotefile._ftp_connect_refusal`, and the 4xx rule in `remotefile._FtpClient._connect`. Why an
  unclear login refusal is read as a credential fault is in `remotefile._names_connection_limit`.
  A busy reply that also carries a credential word stops the lane too.
- **The server must offer `aes256-gcm@openssh.com`, and `hmac-sha2-256-etm@openssh.com` or
  `hmac-sha2-512-etm@openssh.com`.** The connector proposes that one cipher and those two MACs, and
  nothing else. A server missing either fails the handshake with a permanent `SFTP connection
  rejected: Incompatible ssh server (no acceptable ciphers)` or `(no acceptable macs)`. No setting
  widens either list. `_APPROVED_SFTP_CIPHERS` in `transports/remotefile.py` says why each name is
  in or out, and why the MAC still matters beside GCM. (BACKLOG #2041, #2044)
- **Atomic publish.** An upload writes an unguessable temp `.part` name then **renames**, so a poller on
  the far side never sees a partial file; a failed rename removes the temp before the delivery is
  classified (transient → retry, permanent → dead-letter).
- **With `overwrite = false`, the rename refuses a name taken since the listing (BACKLOG #2553).**
  The upload lists `remote_dir` to pick a free name before it writes, and a partner can write that
  name while the temp uploads. So the publish checks again, and if the name is taken it moves on to
  the next free one, on the same connection. After `PUBLISH_NAME_ATTEMPTS` names it fails as a
  transient error and retries with a fresh listing. The log names the upload only through
  `safe_name`.
  - **SFTP:** atomic where the server honours the SFTP `RENAME`, which refuses an existing name.
    OpenSSH's server does, on a filesystem with hard links. `_SftpClient.publish` in
    `transports/remotefile.py` states where it does not hold, and two costs: on OpenSSH the final
    name appears by a hard link, so a partner watching for a move event does not see it, and a
    server that refuses `RENAME` outright fails every delivery. Either site sets
    `overwrite = true` with a per-message `filename`.
  - **FTP and FTPS: not atomic.** A partner file written in the few round trips between the
    publish's own listing and `RNTO` is still replaced on a server whose `RNTO` replaces.
    `_FtpClient.publish` states why. The check costs one more directory listing per delivery.

  With `overwrite = true`, nothing changes: the rename replaces any entry of the same name.
- **Mostly the same file policy as `File(...)`.** A remote source is one of the *directory sources* the
  [file handling & quarantine policy](#file-handling--quarantine-policy-asvs-511) above governs — the
  content-type-aware magic-byte sniff (a drop whose leading bytes contradict its declared `content_type` is
  quarantined before its bytes reach the pipeline), `max_file_bytes`, `.error` quarantine (never a silent
  drop), and the fail-closed pre-ingest `set_scan_hook` AV/ICAP seam all apply. The HL7 **batch split**
  carries over too: a multi-message `MSH`/`FHS`/`BHS` file is N hand-offs and N dispositions, in file
  order, as with `File(...)` ([ADR 0206](adr/0206-an-hl7-write-or-re-encode-never-lets-data-become-structure.md)
  rule 5). **Two File-source behaviours do *not* carry over:** opt-in gzip `decompress` (ADR 0123, local
  `File(...)` only), and `min_age_seconds` (above).
- **One message per body on a listener.** An MLLP, TCP or HTTP inbound, and any other source that does
  not split, refuses an HL7 v2 body holding more than one `MSH` segment: it records `ERROR`, and a
  listener with an ACK channel answers `AR` with MSA-3 `more than one MSH in body` (ADR 0206 rule 5). A
  sender with a batch sends one message per frame or request, or drops the file where a `File(...)` or
  remote-file source splits it. That includes the shipped helper: `samples/send_mllp.py` sends a whole
  file as one frame, so `samples/send_mllp.py samples/messages/adt_batch.hl7` (five messages, no
  envelope) gets an `AR`.
- **Leader-gated.** The remote directory is a *shared* external resource, so in a cluster only the leader
  lists, downloads, or moves its files — otherwise two nodes would double-ingest the drop.
- **No timeout knob.** Neither factory exposes one. The bounds these connections do have are hard-coded
  in `transports/remotefile.py`. The "Timeouts are per-connector, not universal" paragraph under
  [Resource management & limits](#resource-management--limits-asvs-1312--1313--1326) says what each one
  covers, and [Table B](#table-b--per-service-resource-strategy-asvs-1313) has the SFTP and FTP/FTPS rows.
- **Egress allowlist.** `[egress].allowed_remote` gates the host in **both** directions — a poll dials out
  too, so the allowlist guards against polling an arbitrary server. Fail-closed once configured.
- **At-least-once.** An upload may re-send, and a poll may re-emit a file that was handled but not yet
  marked, so **downstream consumers must tolerate duplicates.**
- **A client per operation.** No pooled or held session: each poll and each delivery opens, uses, and
  closes its own client in a `finally`, mirroring the MLLP destination's fresh-connection-per-delivery.

```python
from messagefoundry import Ftp, Sftp, env, inbound, outbound

# Poll a partner's SFTP drop directory, leaving their files in place (read-only share).
inbound(
    "SFTP-IN_ACME_ADT",
    Sftp(host=env("acme_sftp_host"), remote_dir="/outbound/adt", pattern="*.hl7",
         username=env("acme_sftp_user"), private_key=env("acme_sftp_key"),
         after_read="leave", poll_seconds=30.0, validate_directory=True),
    router="acme_adt_router",
)
# Publish results back over FTPS (explicit TLS; verifying by default).
outbound(
    "FTP-OUT_ACME_ORU",
    Ftp(host=env("acme_ftp_host"), tls=True, remote_dir="/inbound/oru",
        username=env("acme_ftp_user"), password=env("acme_ftp_password")),
)
# In messagefoundry.toml (the SERVICE settings file — NOT the --config dir, which only ever reads
# *.py, connections.toml and codesets/):
#   [egress]
#   allowed_remote = ["acme-sftp.example.org", "acme-ftp.example.org"]
```

### REST — `Rest(...)`

An **outbound** HTTP(S) client ([ADR 0003](adr/0003-non-hl7-transports-database-rest-soap.md)). The
Handler produces the request body (JSON, XML, an HL7-in-FHIR document — whatever the endpoint expects);
the connector delivers it. `Rest(...)` is **outbound only** — the inbound side is its own connector,
[`Http(...)`](#http-web-service-listener--http-inbound-only-adr-0023) (ADR 0023), not a direction on this
one.

| Setting | Default | Meaning |
|---------|---------|---------|
| `url` | — (required) | endpoint; `http`/`https` only. Use `env()` for a DEV/PROD-specific host. |
| `method` | `POST` | HTTP method |
| `content_type` | `application/json` | sets the `Content-Type` header |
| `headers` | `{}` | extra **static** headers (no secrets — an `env()` ref *inside* the table is refused at load; `env()` for the whole table is fine) |
| `bearer_token` | — | `Authorization: Bearer …` (a **secret** — supply via `env()`) |
| `basic_user` / `basic_password` | — | HTTP Basic auth (secrets — via `env()`) |
| `timeout_seconds` | `30` | per-request timeout |
| `verify_tls` | `true` | TLS cert verification. `false` is MITM-able and is **refused at construction** for a non-loopback host. `MEFOR_ALLOW_INSECURE_TLS` relaxes it to a loud warning **only while `[security].enforcement` is not `enforce`** — the escape is **clamped** (#200, ADR 0092 decision 2) and is therefore **inert on the shipped default**, where the refusal stands with the variable set. `cleartext_accepted` does **not** reach this hop (it has TLS — it is encrypted-but-unauthenticated, not cleartext), and a hop secured by other means is [attested](#attesting-a-hop-secure-tls_hop_attested) instead. A **loopback** URL is allowed unchanged, which is what makes this usable in a lab |
| `tls_allow_expired` | `false` | **(#129, ADR 0094)** tolerate an **expired** server cert while chain + hostname stay verified — the narrow alternative to `verify_tls=false`. Same contract as the [MLLP row](#mllp--mllp): **no posture gate and no escape variable**. It **is reported**: a WARNING at each build, a `tls-allow-expired` line in `messagefoundry check` and a `security_loosenings()` entry, and so `GET /security/posture` (CORRECTED 2026-10-01: this row said `security_loosenings()` never reports it, stale since BACKLOG #333) |
| `tls_ca_file` | — | **(#1180)** pins this hop to one private CA. See [Pinning a private CA per connection](#pinning-a-private-ca-per-connection-tls_ca_file) |
| `tls_ca_pin` | — | (vault BACKLOG #2371) the SHA-256 of `tls_ca_file`; a mismatch is refused. See [The engine checks the file at every start and reload](#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin) |
| `encoding` | `utf-8` | request-body charset |

**Delivery semantics.** A **2xx** is delivered. **5xx / 408 / 429 / connection / DNS / TLS / timeout**
raise `DeliveryError`, so the lane **retries** with backoff. **Other 4xx** (and a refused **3xx
redirect**) raise a permanent `NegativeAckError`, so the message **dead-letters immediately** rather
than blocking the FIFO lane on a request the endpoint will never accept.

**A 2xx reply over the byte bound (vault BACKLOG #2180).** The engine keeps at most 16 MiB of a reply
body. A retry after a 2xx would send again a request the partner has already answered, so on these
four destinations an over-size body does not cause a re-send. What happens instead depends on
whether the engine needs the body (owner ruling 2026-10-05). This table is the one place that lists
the four HTTP destinations, and their own sections point here.

| Destination | Write | `capture_response` | An over-size body after a 2xx |
|---|---|---|---|
| REST | any | off | **delivered**: nothing looks inside the body, so it is dropped and a WARNING names the connection |
| REST | any | on | **permanent refusal**, code `reply-too-large`: the reply would be stored and may be passed on, so the message dead-letters once |
| SOAP | any | off or on | **permanent refusal**: a `Fault` can sit inside a 2xx body, so the engine cannot tell the outcome |
| DICOMweb | any | off or on | **permanent refusal**: a `FailedSOPSequence` can sit inside a 2xx body |
| FHIR | an update the engine sends as a transaction | off or on | **permanent refusal**: the engine reads that reply for the entry's own status, so it cannot tell the outcome |
| FHIR | any other write | off | **delivered**, with the same WARNING |
| FHIR | any other write | on | **permanent refusal**: the reply would be stored and may be passed on, as for REST |

**Which rows the ruling itself covers.** The owner ruling of 2026-10-05 names the principle: judge
an over-size body after a 2xx by who reads it. It does not name the FHIR rows that refuse. Refusing
them is a reading of that ruling made when this was built (BACKLOG #2180), and the owner may reverse
that reading. It covers every FHIR write with `capture_response` on, and an update the engine sends
as a transaction with it off. The ruling's own wording puts FHIR on the delivered side, which is
what the one remaining FHIR row does: any other write, with `capture_response` off.

"An update the engine sends as a transaction" is `conditional="if-match"`, or `interaction="update"`
with no `conditional`, each with the default `update_url_form`. Every other FHIR write is in the
last two rows. That is at least a create, `conditional="conditional-update"` or `"if-none-exist"`
under `interaction="create"` or `"update"`, an update in the path form, and a `transaction` or
`batch` `Bundle` a Handler built. The engine does not read the reply to a Handler's own `Bundle` for
its entry statuses.

A message that dead-letters this way got a 2xx, but the engine could not read the reply. The partner
may have applied it. On SOAP, on DICOMweb, and on a FHIR update sent as a transaction, the unread
body may instead have held a rejection. Its stored error carries the code `reply-too-large`. Check the partner's own record before you replay it. A
reply that is cut short or misframed after a 2xx is a separate case, and the lane still retries it.

**Security.** Redirects are **refused** (a 3xx can't divert PHI to another host — ASVS 15.3.2), the URL
scheme is constrained to `http`/`https`, and the outbound host is gated by the fail-closed
`[egress].allowed_http` allowlist (WP-11c). Standard library only (`urllib`) — no new dependency.

**No credentials inside an endpoint URL (BACKLOG #1793).** A URL of the form `https://user:password@host/`
is refused when the connector is built. The error names the setting and never the password. This covers
at least `url` on REST, SOAP, FHIR, DICOMweb and `FhirLookup`, plus `oauth2_token_url`, `smart_token_url`
and `[ai].endpoint`. The shape never worked: `urllib` does not send URL userinfo as auth, and its error
text carried the password into `last_error`. Put credentials in `basic_user`/`basic_password` or
`bearer_token` (or the `oauth2_*`/`smart_*` settings), each via `env()`. `proxy_url` is not covered
by this rule. It has its own, below.

**A proxy URL with credentials is refused unless it is written `https://` (vault BACKLOG #2572).**
`urllib` sends a `user:password@` from a proxy URL to the proxy as a `Proxy-Authorization: Basic`
header. Such a proxy is refused before each request, whether it comes from `proxy_url`, from
`HTTP_PROXY` or `HTTPS_PROXY`, or from the system proxy settings. That covers at least REST, SOAP,
FHIR, DICOMweb, `FhirLookup`, the token endpoints, the alert webhook, the OIDC legs and the AI
broker. A connection with such a `proxy_url` still builds, and each send then fails with this
error. The error names no part of the proxy URL, and `[security].enforcement` does not relax it. A
request that goes direct is not refused: one to a loopback host, or to a host that `NO_PROXY` or the
system bypass list names. A connection's own `proxy_no_proxy` is not that list. A host it names
skips the connection's `proxy_url` and still follows a proxy from the environment.
**Writing the proxy `https://` is not refused, and it does not protect the credentials either:**
`urllib` sends `CONNECT`, with the credential header, before any TLS. Take the credentials out of
the proxy URL.

**Idempotency — operator responsibility.** Delivery is **at-least-once**, so a retry **re-sends** the
request. The receiving endpoint **must be idempotent** (an idempotency key, a natural upsert, or a
message-id de-dup) or a retried `POST` will double-apply.

```python
from messagefoundry import outbound, Rest, env

outbound(
    "REST-OUT_ACME_ADT",
    Rest(url=env("acme_api_url"), bearer_token=env("acme_api_token")),
)
```

### Database — `Database(...)`

An **outbound** SQL connector ([ADR 0003](adr/0003-non-hl7-transports-database-rest-soap.md)) over
`aioodbc`, via the `[sqlserver]` extra (`pip install 'messagefoundry[sqlserver]'`), **lazily imported**
(SQLite-only installs unaffected). It has **two dialects** (#66):

- **`dialect="sqlserver"`** (default) — the **SQL Server preset** over the Microsoft ODBC Driver 18.
  **Status: production / supported** — the live aioodbc round-trip is exercised by the CI SQL Server
  service-container job.
- **`dialect="generic"`** — a **generic ODBC path** for another ODBC-reachable database (PostgreSQL,
  MySQL, …). No new Python dependency: you install the target's **ODBC driver at the OS level**
  and name it in `odbc_driver`; see [*Generic ODBC*](#generic-odbc-postgresql--mysql) below.

(The SQL Server *store* backend is a **separate** layer, also production; the connector doesn't depend on
it.) The **inbound** direction is the DB poll source below (`DatabasePoll(...)`).

The Handler produces a **JSON-object** body; the connector binds its keys to the `:name` parameters in
`statement` (translated to positional ODBC `?` — always parameterized, never string-built) and runs it.

| Setting | Default | Meaning |
|---------|---------|---------|
| `server` | — (required) | DB host (the `[egress].allowed_db` allowlist key). Use `env()` for a DEV/PROD-specific host. |
| `database` | — | database name — **required** for `dialect="sqlserver"`; optional for `"generic"` |
| `statement` | — (required) | parameterized SQL / proc call with `:name` placeholders, e.g. `INSERT INTO obs (mrn, val) VALUES (:mrn, :val)` |
| `dialect` | `sqlserver` | `sqlserver` preset · `generic` ODBC (see [*Generic ODBC*](#generic-odbc-postgresql--mysql)) |
| `auth` | `sql` | `sql` · `integrated` (Windows) · `entra` (ActiveDirectoryDefault) — **SQL Server preset only**. On `dialect="generic"` this setting is **not read at all**: that arm emits `username`/`password` under `odbc_user_key`/`odbc_password_key`, so writing `auth="integrated"` there still produces a static login. `messagefoundry check`'s advisory `static-credentials` line names every DATABASE hop on an unchanging credential (ASVS 13.2.1), including that case — see [*Static database credentials*](#static-database-credentials) |
| `username` / `password` | — | SQL-auth credentials (`password` is a **secret** — via `env()`) |
| `port` | `1433` | server port |
| `encrypt` | `true` | TLS to the DB (**SQL Server preset only** — see the generic-ODBC note below). `false` is a weakened hop and is **refused at construction**; `MEFOR_ALLOW_INSECURE_TLS` relaxes it **only while `[security].enforcement` is not `enforce`** — the escape is **clamped** (#200, ADR 0092 decision 2) and is **inert on the shipped default** |
| `trust_server_certificate` | `false` | accept an untrusted cert. Same weakened-hop cell as `encrypt=false` — **refused**, with the same **clamped** escape that does nothing on a stock instance. Import the DB CA instead (below) |
| `connect_timeout` | `15` | login timeout (s): how long connecting to the server may take. A whole number, at least 1, or the connection is **refused at construction**. Applied on the **SQL Server preset only**, where it reaches ODBC Driver 18 as pyodbc's `timeout=` (the driver ignores a DSN keyword for it). `generic` gets no login timeout from the engine and uses its driver's default |
| `app_name` | `messagefoundry` | ODBC `APP` name |
| `pool_max` | `5` | max pooled connections |

**Delivery semantics.** A committed statement is delivered. A **transient** DB failure (connection drop,
deadlock, timeout — SQLSTATE class `08`/`40` or `HYTxx`) → `DeliveryError`, so the lane **retries**. A
**permanent** failure (constraint / data / syntax) **and a payload that doesn't match the statement** →
`NegativeAckError` → **dead-letter** (a retry can't fix it).

**Security.** Values are bound as **parameters** (never string-interpolated into SQL); the connection
string brace-quotes every value (no connection-string injection); TLS is **on by default** and a
weakened posture (`encrypt=false` / `trust_server_certificate=true`, `dialect="sqlserver"` only) is
**refused at construction** — `MEFOR_ALLOW_INSECURE_TLS` is **clamped** and cannot relax it while
`[security].enforcement = enforce`, which is the shipped default, so on a stock instance there is **no
env-var route to a weakened DB hop**: fix the trust instead (below). The outbound server is gated by the
fail-closed `[egress].allowed_db` allowlist (WP-11c). A `:name` placeholder must not appear inside a
quoted string literal in `statement` — bind dynamic strings as parameters. To validate a private /
internal DB CA with `trust_server_certificate` left **false**, import that CA into the Windows
**machine** trust store (`LocalMachine\Root`) via
[`scripts/service/import-db-ca.ps1`](../scripts/service/import-db-ca.ps1) — **never**
`TrustServerCertificate=true`; ODBC 18 has no connection-string CA-file keyword. See the CA-import +
make-before-break rotation runbooks in
[`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md#5-db-tls-trust-import-the-db-ca--rotate-certificates).

**Idempotency — operator responsibility.** Delivery is **at-least-once**, so a retry **re-executes** the
statement. Use an idempotent write (`MERGE`/upsert on a natural key, or a de-dup) so a retry doesn't
double-apply.

```python
from messagefoundry import outbound, Database, env

outbound(
    "DB-OUT_ACME_OBS",
    Database(
        server=env("acme_sql_host"),
        database="Results",
        username=env("acme_sql_user"),
        password=env("acme_sql_password"),
        statement="INSERT INTO obs (mrn, value) VALUES (:mrn, :value)",
    ),
)
```

#### Generic ODBC (PostgreSQL / MySQL)

`dialect="generic"` (#66) targets **any ODBC-reachable database** without a new Python dependency: the
connector still rides the already-present `aioodbc` driver — you install the *target's* **ODBC driver at
the OS level** (e.g. psqlODBC, MySQL Connector/ODBC) and name it in
`odbc_driver`. The parameterized-`:name` binding, error classification, pooling and `[egress].allowed_db`
gate are identical to the SQL Server preset.

| Setting | Default | Meaning |
|---------|---------|---------|
| `odbc_driver` | — (required for `generic`) | the **exact OS-registered ODBC driver name**, e.g. `PostgreSQL Unicode`, `MySQL ODBC 8.0 Unicode Driver` |
| `odbc_params` | — | a mapping of **driver-specific ODBC keywords** → values, e.g. `{"PORT": 5432, "SSLmode": "verify-full"}`. Values are **literals** (not `env()`-resolved — put per-env/secret values in the top-level fields) and are brace-quoted. Keys must come from the [accepted keyword list](#accepted-odbc_params-keywords) below; any other keyword is **refused when the connection is built**, and so is a value holding a delimiter (see [*Values*](#values-on-the-generic-dialect)). An `env()` reference here is **refused at load** — as a code-first `env(...)` value, as a `connections.toml` inline table (`PWD = { env = "acme_pw" }`), and as one naming the whole table (`odbc_params = { env = "..." }`). |
| `odbc_user_key` | `UID` | ODBC keyword the top-level `username` is emitted under (some drivers want `USER`). One of `UID`, `USER`, `Username` or `User ID`, in any case; anything else is **refused** |
| `odbc_password_key` | `PWD` | ODBC keyword the top-level `password` is emitted under (some drivers want `PASSWORD`). `PWD` or `PASSWORD`, in any case; anything else is **refused** |

The DSN is built as `DRIVER={odbc_driver};SERVER=<server>;[DATABASE={database};][<user>={username};<pwd>={password};]<odbc_params…>`. `server` is emitted as the near-universal `SERVER` keyword.

##### Accepted `odbc_params` keywords

`[egress].allowed_db` checks the host in `server`. **No `odbc_params` keyword can give the
driver another host** (vault BACKLOG #2577): `odbc_params` takes a fixed list of keywords, and
each one sets a port, a TLS mode, a local file or a session option:

<!-- odbc-params-allowlist:start -->
| Group | Keywords |
|---|---|
| Port | `PORT` |
| TLS mode and files | `SSLmode`, `SSLCA`, `SSLCAPATH`, `SSLCERT`, `SSLKEY`, `sslpassword`, `SSLCIPHER`, `Encrypt` |
| Session | `CHARSET`, `ReadOnly`, `READTIMEOUT`, `WRITETIMEOUT`, `Fetch`, `UseDeclareFetch`, `BoolsAsChar`, `KeepaliveTime`, `KeepaliveInterval` |
<!-- odbc-params-allowlist:end -->

Keywords match in any case. Spell one with single blanks between words and none at the end: the
keyword is sent as you wrote it, and not every driver trims it. A keyword given twice, in any
case, is refused. The list says what the engine accepts. It does not say which keywords your
driver reads, so check the driver's own manual.

A file keyword (`SSLCA`, `SSLCAPATH`, `SSLCERT`, `SSLKEY`) must be a plain local path: a drive
letter, or one leading separator. A path that starts with two separators, or with a device
prefix, is refused, because it can name another host. This reads the spelling only. It does
not follow a mapped drive or a link, so keep those files on a local disk.

This is a rule about keywords. It assumes `odbc_driver` names a network database driver that
reads `SERVER` as its target.

Any other keyword is refused when the connection is built, and the error names the keyword and
the connection. That fails `messagefoundry check`, a reload and a `connection` edit. At `serve`
start the connection is not built, so it never connects. The refused set includes at least
these kinds:

- another name for the host, address, service, data source or socket;
- a keyword that passes the driver a whole option string, such as psqlODBC's `pqopt`;
- a keyword with a typed setting of its own: the driver, server, database and credentials go in
  `odbc_driver`, `server`, `database`, `username` and `password`;
- a keyword whose only use is to stop certificate verification, such as `TrustServerCertificate`.

Two limits follow from this:

- **A driver that takes its target under another keyword cannot be configured here.** The engine
  sends the target as `SERVER` and nothing else. Oracle's ODBC driver documents `DBQ` for its
  target, and `DBQ` is refused. Whether that driver also reads `SERVER` has not been tested.
- **psqlODBC takes libpq options through `pqopt`, which is refused.** That covers at least a CA
  file path, a client certificate and key, and a connect timeout. With `SSLmode=verify-full`,
  libpq still reads its CA from its default location or from the `PGSSLROOTCERT` environment
  variable of the service.

##### Values on the generic dialect

Every value is sent inside braces and must be printable ASCII. A value that breaks its rule is
refused when the connection is built, and the error names the setting and never the value:

| Setting | Rule |
|---|---|
| `odbc_driver`, `database`, `username`, every `odbc_params` value | printable ASCII, and none of `;`, `{`, `}` |
| `server` | printable ASCII, and none of `;`, `{`, `}`, `=` |
| `password` | printable ASCII. A `}` is sent with the ODBC `}}` escape, which the driver must read |

ASCII only, because a driver manager may convert the string for the driver, and some
conversions turn a non-ASCII character into a delimiter.

To have a keyword added, open an issue that names the driver and what the keyword does.

> **TLS is the operator's responsibility on the generic path.** MessageFoundry reads SQL Server's
> `Encrypt`/`TrustServerCertificate` to *refuse* a weakened DB hop, but it cannot introspect an arbitrary
> driver's TLS posture — so the weakened-TLS refusal does **not** apply here. Configure **verifying** TLS
> via the driver's own keyword in `odbc_params` (psqlODBC `SSLmode=verify-full`, MySQL
> `SSLMODE=VERIFY_IDENTITY`). Never point PHI at an unverified generic hop. So the
> delegation is never *silent*, a generic connection logs a **WARNING** at construction, naming itself,
> when `odbc_params` carries **no** ssl/tls/encrypt keyword **or** carries one set to a no-TLS value
> (`SSLmode=disable`/`allow`/`prefer`, MySQL `DISABLED`/`PREFERRED`, `Encrypt=no`/`0`/`false`/`off`) —
> dropped to DEBUG only once a keyword is set to something outside that deny-list. A passphrase keyword
> such as `sslpassword` is not a TLS keyword here: it sets no TLS mode, and its value is never read or
> reported (BACKLOG #1352). It is also reported
> by `security_loosenings()` / `GET /security/posture` and by `messagefoundry check`'s `generic-db-tls`
> line, for `DatabasePoll` inbounds as well as `Database` outbounds (#333). This exemption is
> recorded in the [ADR 0092 amendment (2026-07-12)](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md).

> **A generic hop that says TLS is not required is REFUSED, not merely warned about** (BACKLOG #1178).
> The warning above used to be the whole control, so a generic connection with no TLS keyword would
> cross in plaintext with nothing stopping it. That arm now goes through the same cleartext-hop
> authority every other cleartext transport uses, with the same owner-ratified precedence: an on-box
> hop is allowed, a per-connection `tls_hop_attested` with its `tls_hop_attested_reason` allows it (audited, and reported),
> `cleartext_accepted` warns
> and audits, a non-enforcing instance warns, and an **enforcing** instance **refuses** it. The refusal
> lands at construction, so it fails `messagefoundry check` / dry-run / reload / the `serve` pre-flight
> before anything starts.
>
> What is gated is the case the classifier can judge: **no** ssl/tls/encrypt keyword, or one pinned to
> a no-TLS value. A keyword set to anything outside that deny-list is still delegated, because the
> engine cannot tell whether an arbitrary driver's value verifies the certificate — that residual is
> unchanged. `cleartext_accepted` is an outbound-only declaration, so a `DatabasePoll` inbound's only
> per-connection relaxation is `tls_hop_attested` with a `tls_hop_attested_reason`, for a hop secured by
> other means. Otherwise set a verifying keyword, or run at `[security].enforcement = warn`.

> **Scope / limitations.** Native async DB drivers (`asyncpg`-as-connector, `oracledb`, `mysqlclient`) are
> **out of scope** (dep-heavy) — the generic path is ODBC-only. The `test_connection` reachability probe
> runs `SELECT 1` (works on PostgreSQL / MySQL / SQL Server). Read-only `db_lookup` (ADR 0010) stays SQL-Server-only.

#### Give `db_lookup` a read-only login

**Point every `DatabaseLookup(...)` at an account that cannot write — a `db_datareader`-class login on
the partner database.** That account is the only thing that makes a lookup read-only. The engine's two
in-process layers are defence in depth and neither is authority:

| Layer | What it does | What it cannot do |
|---|---|---|
| Statement gate (`_require_read_only`) | refuses a statement that does not open with `SELECT`/`WITH`, or that carries a write/`EXEC`/DDL keyword outside a literal or comment, or that chains a second statement | it reads text. A write executed on a linked server through a pass-through literal is opaque to it |
| `ApplicationIntent=ReadOnly` on the DSN | advertises read-only intent | honored only by a SQL Server Always-On **read replica**; a no-op against any other server |

Lookup pools are opened **autocommit**, so a write that got past the statement gate would commit rather
than roll back. T-SQL has no `SET TRANSACTION READ ONLY`, so the engine cannot open a read-only
transaction instead: on SQL Server the read-only mechanisms — a read-only database or filegroup, a
snapshot, or `ApplicationIntent` against an availability-group replica — are all operator provisioning.

Grant the lookup account `SELECT` on the objects the feed reads and nothing else. It needs no
membership in `db_datawriter`, `db_ddladmin` or `db_owner`, and no `EXECUTE` unless a feed genuinely
reads through a stored procedure — which this gate refuses anyway.

> This is a **separate principal** from the engine's own store login. `[store]` settings govern the
> database MessageFoundry writes its own messages to; a `DatabaseLookup` dials a partner database under
> a credential the operator configures per connection.

#### A lookup that selects too many rows fails the message

Each `DatabaseLookup(...)` takes `max_rows`, default `500`. A `db_lookup` call whose statement selects
more rows than that raises `DbLookupError`, and the Handler's message goes to `ERROR` like any other
lookup failure. The engine never hands the Handler a truncated result, because a Handler shaping a
message from the first 500 rows of a larger set would be wrong with nothing to say so.

The ceiling is charged at the fetch (BACKLOG #1730). The executor asks the driver for at most
`max_rows + 1` rows, so a broad predicate is refused with at most one row past the ceiling held in the
transform worker, not the whole result set. The driver may still spend time discarding the unread rows
when the cursor closes. The error names the connection and the ceiling, never the statement or a row.

A lookup that shapes one message rarely needs more than a handful of rows. If a feed needs a large
table, a synced `Reference(...)` is the better fit. `max_rows=0` removes the ceiling. A negative
or fractional value stops `serve` building the lookup. `messagefoundry check` refuses it in its build
leg, which runs when the config has a `messagefoundry.toml`. The ceiling counts rows, not bytes.

#### Static credentials on every backend hop

ASVS 13.2.1 asks that every backend hop authenticate with an individual service account, a short-term
token or a certificate, not with an unchanging credential. The engine keeps one list of the hops it
dials that do not (BACKLOG #1182). A hop is on the list when it presents a static credential (a
password, API key, static bearer token or Vault token) or no credential at all. A hop that presents
only a compliant credential is never on it.

Three surfaces read that one list, so they cannot disagree:

- `messagefoundry check` prints it on the advisory `static-credentials` line. With a
  `messagefoundry.toml` it also reads the service-settings hops, and it says when it could not.
- `GET /security/posture` returns it as `static_credential_hops`, one entry per hop.
- `serve` refuses on it, but only when you turn the refusal on.

The list covers the hops named in the table below. It is not a promise about hops added later.

**The refusal ships off.** Set `[security].require_nonstatic_credentials = true` to turn it on. `serve`
then refuses to start while any listed hop has no opt-out. To keep a hop, name it with a reason:

```toml
[security]
require_nonstatic_credentials = true
static_credential_accepted = { "OB_ACME_REST" = "partner offers HTTP Basic only", "settings:alerts.webhook" = "no credential field exists" }
```

Each opt-out is logged at start with the hop's name and your reason, never a secret, and
`security_loosenings()` names the set. The refuse/warn split is `[security].enforcement`, as it is for
`[store].require_managed_identity`. The settings hops are checked before anything starts. The graph
hops are checked at the first graph load and at every `/config/reload`, where a refusal leaves the
running graph in place.

**An edit to either setting needs a restart.** `serve` reads `[security]` once, at start. A
`/config/reload` reloads the connection graph, not the service settings, so it judges the new graph
against the `require_nonstatic_credentials` and `static_credential_accepted` values the engine
started with. To add, change or remove an opt-out, edit the setting and restart the engine.

**Some hops have no compliant option today.** For those, the only way through with the refusal on is an
opt-out. That is expected, and the table says which they are.

| Hop | Named as | Compliant kind in the product |
|-----|----------|-------------------------------|
| `Rest(...)`, `FHIR(...)` | `<name>` | yes: SMART Backend Services or OAuth2 client credentials |
| `FhirLookup(...)` | `fhir_lookup:<name>` | yes: SMART Backend Services |
| `Soap(...)` | `<name>` | yes: client certificate, or OAuth2 |
| `DICOMweb(...)` | `<name>` | **no** (static bearer or Basic only) |
| forward-proxy credential on any HTTP connection (`proxy_user`/`proxy_password`, or a user and password in the proxy URL, its own or an inherited `[egress].proxy_url`) | `proxy:<name>`, or `proxy:fhir_lookup:<name>` for a lookup | **no** (Basic or Digest only) |
| `MLLP(...)`, `DICOM(...)` outbound | `<name>` | yes: `tls=True` with `tls_cert_file` |
| `Tcp(...)`, `X12(...)` outbound | `<name>` | **no** (no credential of any kind) |
| `Email(...)`, `Direct(...)` SMTP AUTH | `<name>` | **no** |
| `Sftp(...)` | `<name>` or `inbound:<name>` | yes: SSH private key |
| `Ftp(...)` | `<name>` or `inbound:<name>` | **no** |
| `File(...)` alternate-share credential | `<name>` or `inbound:<name>` | **no** (drop it to run as the service identity) |
| the four database factories | see the table below | yes: `auth="integrated"` or `"entra"` |
| `[store]` on SQL Server or Postgres | `settings:store` | SQL Server yes; Postgres **no** |
| Vault token (store key, Transit, secrets) | `settings:vault.store_key`, `settings:vault.store_transit`, `settings:vault.secrets` | **no** |
| `[alerts]` webhook | `settings:alerts.webhook` | **no** (the sink has no credential field) |
| `[alerts]` SMTP | `settings:alerts.smtp` | **no** |
| `[ai]` broker key | `settings:ai.broker` | **no** |
| `[auth]` OIDC client secret | `settings:auth.oidc` | yes: `oidc_token_endpoint_auth_method = "private_key_jwt"` (BACKLOG #296) |
| `[auth]` AD/LDAP bind | `settings:auth.ad_bind` | **no** |
| `[logging]` syslog forwarder | `settings:logging.forward` | yes: `forward_protocol = "tls"` with `forward_tls_client_cert` |

Listeners are **not** on the list. On an inbound MLLP, TCP, X12, DICOM or HTTP listener the partner
presents a credential to the engine, not the other way round. A connection declared with
`deployed=False` is not on it either, because the engine never opens it. The same rule covers the
rows above: a forward-proxy credential is not listed when `proxy_no_proxy` (the connection's own, or
the inherited `[egress].proxy_no_proxy`) sends the connection's URL and its token endpoint direct.
A loopback host is always sent direct, with no entry needed, so a connection whose every target is
loopback lists no proxy credential either. The `[egress]` section of
[CONFIGURATION.md](CONFIGURATION.md) states that loopback rule. And the `[auth]` rows and their
Vault secrets are listed only while `[auth]` and that feature are on. OAuth2 counts as compliant by
the 2026-08-22 owner ruling, although its own token request still sends a static client secret; that
token request is not listed as a separate hop.

#### Static database credentials

ASVS 13.2.1 asks that a backend hop authenticate with an individual service account, a short-term token
or a certificate rather than an unchanging credential. On SQL Server that means `auth="integrated"` (a
gMSA or Windows machine principal) or `auth="entra"`; `auth="sql"`, the shipped default, is a static
username and password.

`messagefoundry check` names every declared database hop that presents an unchanging credential, with
its peer, on its advisory **`static-credentials`** line. That line covers every backend hop, not only
databases; see [Static credentials on every backend hop](#static-credentials-on-every-backend-hop)
above. The line itself refuses nothing. The refusal is the opt-in
`[security].require_nonstatic_credentials`, which is off by default.

It covers **four** factories, because four of them dial a database with a credential:

| Factory | Table | Reported as |
|---------|-------|-------------|
| `Database(...)` | outbound | `<name>` |
| `DatabasePoll(...)` | inbound | `inbound:<name>` |
| `DatabaseLookup(...)` | `db_lookup` read pool (ADR 0010) | `db_lookup:<name>` |
| `DatabaseRef(...)` | reference source (ADR 0006) | `reference:<name>` |

> **`[store].require_managed_identity` does NOT cover any of them.** That flag is a `StoreSettings`
> method, so it reads the `[store]` service settings and nothing else — no connector, lookup or
> reference hop is within its reach. Its name reads as though it governs the engine's whole database
> posture; it governs the store hop. See
> [`docs/CONFIGURATION.md`](CONFIGURATION.md) for the flag and
> [`docs/SECURITY.md`](SECURITY.md) for the delegation boundary.

One case is deliberately **not** reported: a `dialect="generic"` hop that sets no top-level
`username`/`password`. `odbc_params` accepts no login-name or password keyword (see
[*Accepted `odbc_params` keywords*](#accepted-odbc_params-keywords)), so such a hop carries
neither in its connection string. It may still sign in with a client certificate (`SSLCERT` and
`SSLKEY`, on a driver that reads them) or as the service's own account, and this report
classifies neither.

```python
from messagefoundry import outbound, Database, env

# PostgreSQL via psqlODBC (installed at the OS level), verifying TLS via the driver's own keyword.
outbound(
    "DB-OUT_ACME_PG",
    Database(
        dialect="generic",
        odbc_driver="PostgreSQL Unicode",
        server=env("acme_pg_host"),
        database="results",
        username=env("acme_pg_user"),
        password=env("acme_pg_password"),
        odbc_params={"PORT": 5432, "SSLmode": "verify-full"},
        statement="INSERT INTO obs (mrn, value) VALUES (:mrn, :value)",
    ),
)
```

### Database source — `DatabasePoll(...)`

The **inbound** DB poll ([ADR 0003](adr/0003-non-hl7-transports-database-rest-soap.md) §3 + the
payload-agnostic ingress of [ADR 0004](adr/0004-payload-agnostic-ingress.md)). Same connection settings
and `[sqlserver]`-extra / production status as the destination above; it is the File source's
*process-then-mark-done* shape with a query instead of a directory. Every `poll_seconds` it runs
`poll_statement` (a `SELECT`), hands each row to the bound Router as a body, then — **only after the
handler returns** — runs `mark_statement` (bound from the row's columns) so the row isn't re-read.

| Setting | Default | Meaning |
|---------|---------|---------|
| `server` | — (required) | SQL Server host. Use `env()` for a DEV/PROD-specific host. |
| `database` | — (required) | database name |
| `poll_statement` | — (required) | the `SELECT` of the next batch, e.g. `SELECT id, payload FROM mf_inbox WHERE status='NEW' ORDER BY id` |
| `mark_statement` | — | run **per row after** the handler succeeds, with `:name` params bound from the row, e.g. `UPDATE mf_inbox SET status='DONE' WHERE id=:id`. Omit only for a genuinely read-only/idempotent feed. |
| `body_column` | — | unset → the **whole row** as a JSON object `{column: value}` (pair with `content_type=json`); set → that **one column's value verbatim** (e.g. a column holding an HL7 message → `content_type=hl7v2`) |
| `poll_seconds` | `5.0` | interval between polls |
| `poll_max_rows` | `500` | most rows one poll will **hand off** from `poll_statement`'s result set. The rest are left in the table — not read, not marked, not errored — and the next poll selects them again. Still charged at the **fetch**, so a long-unattended table is not materialised whole into memory; a row the source cannot turn into a body does not spend a slot, and the poll asks the driver for the shortfall instead (at most 64 such rows per poll, then it defers the rest). Progress needs `mark_statement` to take a handled row out of the `poll_statement` predicate, which is the shape this connector already requires. See [*Per-tick poll ceilings*](#per-tick-poll-ceilings). `None`/`0` = unlimited. |
| `encoding` | `utf-8` | charset for the body bytes handed to the pipeline |
| `dialect` / `odbc_driver` / `odbc_params` / `odbc_user_key` / `odbc_password_key` | `sqlserver` / … | same as `Database(...)` — `dialect="generic"` polls an OS-installed ODBC driver (PostgreSQL / MySQL); see [*Generic ODBC*](#generic-odbc-postgresql--mysql) |
| `auth` / `username` / `password` / `port` / `encrypt` / `trust_server_certificate` / `connect_timeout` / `app_name` / `pool_max` | — | identical to the `Database(...)` destination above |

**Mark mechanism — your choice via `mark_statement`.** A **status column** (lead pattern:
`SELECT … WHERE status='NEW'` + `UPDATE … SET status='DONE'`), a **delete-from-queue** (`DELETE … WHERE
id=:id`), or a **high-water-mark** cursor (an `UPDATE` advancing a stored cursor) all work — the connector
just runs whatever statement you declare, bound from the row.

**Reliability — at-least-once, tolerate duplicates.** A crash (or a `mark_statement` failure) after the
handler ingested a row but before the mark commits re-emits that row next poll, so the **downstream
pipeline must tolerate duplicates**. A handler failure (e.g. the store is briefly down) leaves the row
**unmarked** so it retries — never marked-and-dropped. A poll error is **logged, not fatal** — a bad
`poll_statement` or a dropped connection never kills the poller; it retries next interval.

**Security.** TLS is **on by default**; weakening it (`encrypt=false` / `trust_server_certificate=true`)
is **refused at construction** through the same cell as the `Database(...)` destination, and the
`MEFOR_ALLOW_INSECURE_TLS` escape is **clamped inert** while `[security].enforcement = enforce` (the
shipped default). The connection
string brace-quotes every value; secrets go through `env()`. The polled `server` is gated by the same
fail-closed `[egress].allowed_db` allowlist as the destination — although the source pulls data *in*, it
still dials out to a host, so the allowlist guards against polling an arbitrary server.

```python
from messagefoundry import inbound, DatabasePoll, env
from messagefoundry.config.models import ContentType

inbound(
    "DB-IN_ACME_ORDERS",
    DatabasePoll(
        server=env("acme_sql_host"),
        database="Orders",
        username=env("acme_sql_user"),
        password=env("acme_sql_password"),
        poll_statement="SELECT id, payload FROM mf_inbox WHERE status='NEW' ORDER BY id",
        mark_statement="UPDATE mf_inbox SET status='DONE' WHERE id=:id",
        body_column="payload",  # the column holds an HL7 message
    ),
    router="route_orders",
    content_type=ContentType.HL7V2,  # or omit body_column + use ContentType.JSON for a whole-row body
)
```

### SOAP — `Soap(...)`

An **outbound** SOAP web-service client ([ADR 0003](adr/0003-non-hl7-transports-database-rest-soap.md)) —
a thin layer over the REST connector's HTTP client (same no-redirect, `http`/`https`-only opener and the
`[egress].allowed_http` host gate). The Handler produces the **full SOAP envelope** (XML); this adds the
SOAP `Content-Type` (+ a `SOAPAction` header for 1.1) and POSTs it. There is **no SOAP source connector**:
a partner's SOAP envelope is *received* by [`Http(...)`](#http-web-service-listener--http-inbound-only-adr-0023)
and un-wrapped in a Handler (`parsing/xml` has the hardened XPath model), but the *synchronous* SOAP-envelope
reply — a Web Service Listener that blocks on a captured downstream reply — is a defined ADR 0023 / ADR 0013
follow-on and is **not** built.

| Setting | Default | Meaning |
|---------|---------|---------|
| `url` | — (required) | endpoint; `http`/`https` only. Use `env()` for a DEV/PROD-specific host. |
| `soap_action` | — | the `SOAPAction` (1.1 header; 1.2 `action` content-type param) |
| `soap_version` | `1.1` | `1.1` (`text/xml`) or `1.2` (`application/soap+xml`) |
| `headers` | `{}` | extra **static** headers (no secrets — an `env()` ref *inside* the table is refused at load; `env()` for the whole table is fine) |
| `bearer_token` | — | `Authorization: Bearer …` (a **secret** — via `env()`) |
| `basic_user` / `basic_password` | — | HTTP Basic auth (secrets — via `env()`) |
| `timeout_seconds` | `30` | per-request timeout |
| `verify_tls` | `true` | TLS cert verification — the same posture-keyed cell as [REST](#rest--rest): `false` is **refused at construction** off loopback, and the `MEFOR_ALLOW_INSECURE_TLS` escape is **clamped inert** while `[security].enforcement = enforce` (the shipped default) |
| `tls_allow_expired` | `false` | **(#129, ADR 0094)** tolerate an **expired** server cert with chain + hostname still verified. **No posture gate and no escape variable**. It **is reported**: a WARNING at each build, a `tls-allow-expired` line in `messagefoundry check` and a `security_loosenings()` entry, and so `GET /security/posture` (CORRECTED 2026-10-01: this row said `security_loosenings()` never reports it, stale since BACKLOG #333) — see the [MLLP row](#mllp--mllp) |
| `tls_ca_file` | — | **(#1180)** pins this hop to one private CA. See [Pinning a private CA per connection](#pinning-a-private-ca-per-connection-tls_ca_file) |
| `tls_ca_pin` | — | (vault BACKLOG #2371) the SHA-256 of `tls_ca_file`; a mismatch is refused. See [The engine checks the file at every start and reload](#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin) |
| `encoding` | `utf-8` | envelope charset |

**Fault & delivery semantics.** The response is inspected for a SOAP `Fault` (which can arrive as an HTTP
500 **or** an HTTP 200 body). A **Sender/Client** fault → `NegativeAckError` → **dead-letter** (the
request is rejected; a retry won't help). A **Receiver/Server** fault → `DeliveryError` → **retry**. An
unrecognized fault is treated as permanent (so a rejected request can't loop the lane). With no fault, the
HTTP status decides (2xx delivered, 5xx retry, other 4xx / refused 3xx dead-letter); a connection/timeout
error retries. Fault bodies are **not** echoed into errors/logs (they may carry PHI) — only the fault role
+ HTTP status. A 2xx whose body is over the byte bound cannot be inspected, so it is a permanent refusal
and is not sent again: see *A 2xx reply over the byte bound* under REST.

**Security & idempotency.** Same hardening as REST (redirects refused, scheme constrained, host gated by
`[egress].allowed_http`, secrets via `env()`). Delivery is **at-least-once**, so a retry **re-sends** —
the service operation **must be idempotent**.

```python
from messagefoundry import outbound, Soap, env

outbound(
    "SOAP-OUT_ACME_ORDERS",
    Soap(url=env("acme_soap_url"), soap_action="urn:SubmitOrder"),
)
```

#### WS-\* mode — mutual TLS + WS-Security / WS-Addressing ([ADR 0015](adr/0015-ws-soap-outbound-mtls-wssecurity.md))

For a certificate-authenticated service with a hardened WS-\* contract, opt in to **WS-\* mode**. The key
difference: in WS-\* mode the **Handler returns only the operation `<Body>` fragment** (e.g. the element
wrapping an HL7 payload) — **not** the full envelope. The transport builds the `<soap:Envelope>` and
**stamps the non-deterministic headers in `send()`** (`<wsa:MessageID>`, `<wsu:Timestamp>`, optional
`<wsse:UsernameToken>` Nonce/Created), so a **pure transform never mints a per-call nonce/timestamp**
(re-run purity). **WS-\* requires `soap_version="1.2"`.**

| Setting | Default | Meaning |
|---------|---------|---------|
| `client_cert_file` / `client_key_file` | — | **mutual TLS** client cert + key (PEM path or `env()` text). Must be set together; server verification stays on, so **incompatible with `verify_tls=false`**. |
| `client_key_password` | — | key passphrase (a **secret** — via `env()`); it must meet the [wrap floor](#encrypted-private-keys-must-meet-the-wrap-floor) |
| `ws_security` | `false` | stamp `<wsse:Security>` (a `Timestamp` + optional `UsernameToken`) |
| `ws_username` / `ws_password` | `basic_*` | `UsernameToken` credentials (secrets — via `env()`) |
| `ws_password_type` | `text` | `text` (PasswordText) only. `digest` (PasswordDigest) was **retired** in BACKLOG #1171 (ASVS 11.4.1): the construction is SHA-1 by profile definition, and a UsernameToken over a cleartext hop is refused anyway, so the channel already carried the credential. Setting it raises |
| `ws_addressing` | `false` | stamp `<wsa:Action>` (from `soap_action`), `<wsa:To>` (from `url`), `<wsa:MessageID>` (per-call) |
| `ws_timestamp_ttl_seconds` | `300` | the `Created`→`Expires` window |

**Operational notes (read before going live):**
- **Populate `[egress].allowed_http`.** A WS-\* mTLS destination carries PHI, so its host must be listed
  — and on a **PHI** instance (every built-in env name by default,
  [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)) leaving it
  empty does **not** mean "unrestricted". `[security].block_unlisted_outbound` is on unless written
  false, so an empty `allowed_http`
  refuses *every* HTTP destination. With no `[egress]` allowlist at all, and that switch not written
  `true`, `serve` also refuses to start.
  Empty-means-unrestricted survives only where an operator
  writes `[security].block_unlisted_outbound = false` — the explicit, audited opt-out. No instance can
  declare its way out of the deny default ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)), and the default does not read `[security].enforcement` either.
  See [CONFIGURATION.md `[egress]`](CONFIGURATION.md#egress) for the full behaviour table.
- **`ws_timestamp_ttl_seconds` must be ≥ the worst-case retry backoff.** The timestamp is re-stamped on
  each `send()`, but a held FIFO lane plus a short TTL can fail the peer's `Expires` check.
- **Idempotency footgun.** An at-least-once **re-send mints a fresh `<wsa:MessageID>`** (correct WS-\*
  retry semantics) for the *same* clinical message — the partner's submit operation **must dedup** a
  re-send as a retry, not a duplicate submission. (A stable engine-side idempotency key is deferred to the
  XML-DSig follow-up.)
- **Scope:** WS-Security here is `Timestamp` + `UsernameToken` only; **XML-DSig body signing is not yet
  supported** (ADR 0015 §4).
- A WS-Security auth/expiry fault (`FailedAuthentication` / `InvalidSecurityToken` / `MessageExpired`)
  **dead-letters** (a credential/expiry reject won't fix on a retry).

```python
from messagefoundry import outbound, Soap, env

outbound(
    "SOAP-OUT_REGISTRY_SUBMIT",
    Soap(
        url=env("registry_url"),
        soap_version="1.2",
        soap_action="urn:submitSingleMessage",
        client_cert_file=env("registry_client_cert"),
        client_key_file=env("registry_client_key"),
        client_key_password=env("registry_key_pw"),
        ws_addressing=True,
        ws_security=True,
        ws_username=env("registry_user"),
        ws_password=env("registry_pw"),
        capture_response=True,  # capture the submit confirmation/error (ADR 0013)
    ),
)
# The Handler returns ONLY the <Body> fragment, e.g. "<submitSingleMessage>…HL7…</submitSingleMessage>".
```

#### Credentials in the operation **body** — `body_secrets` (ADR 0015 amendment, #236)

Some registries (a CDC-IIS-style `submitSingleMessage`) take username/password/facility as **elements of
the operation `<Body>`**, not a WS-Security header. **Check the WSDL first:** if it accepts a
`UsernameToken` header, use `ws_security` (above) — `body_secrets` is unnecessary. Only if the credentials
must ride the **body** do you need this.

`body_secrets={placeholder_token: env(secret)}` lets the transport substitute the secret into the body **at
send time** so it never enters the message. The Handler emits the opaque `placeholder_token` (a high-entropy
string, e.g. `secrets.token_hex(12)`) where the credential goes; the transport swaps in the `env()`-resolved
value in `send()`, after the payload leaves the store and before it hits the wire. The credential is
therefore **never** in the stored outbound/done/dead-letter rows, a replayed body, `dryrun` output, or an
operator payload view — the token is.

```python
from messagefoundry import outbound, Soap, env

outbound(
    "SOAP-OUT_REGISTRY_SUBMIT",
    Soap(
        url=env("registry_url"),
        soap_action="urn:cdc:iisb:2011:submitSingleMessage",
        capture_response=True,
        body_secrets={  # placeholder token -> env() secret; each value MUST be env() (no inline, no default)
            "MF_IIS_USER_9f2c41ab3d7e": env("registry_user"),
            "MF_IIS_PW_5b1d90ee0a11": env("registry_password"),
        },
    ),
)
# The Handler puts ONLY the tokens in the body it returns — never the credential:
#   body = ('<sub:submitSingleMessage xmlns:sub="urn:cdc:iisb:2011">'
#           '<sub:username>MF_IIS_USER_9f2c41ab3d7e</sub:username>'
#           '<sub:password>MF_IIS_PW_5b1d90ee0a11</sub:password>'
#           f'<sub:hl7Message>{escape(msg.encode())}</sub:hl7Message></sub:submitSingleMessage>')
```

Rules and behaviour, briefly (full contract: the ADR 0015 amendment):
- **Code-first only.** Each value must be an `env()` ref — an inline literal, an `env()` `default=`, or a
  `cast=` is refused, and there is **no `connections.toml` / VS Code editor form** (it is refused loudly so a
  plaintext secret can't be persisted or a body-secret connection corrupted on save).
- **Exactly once, fail-closed.** Each token must appear **exactly once** in the body — 0 (a Handler branch
  forgot it) or ≥2 (attacker-influenceable HL7 that happens to carry it) → a permanent dead-letter, and
  **nothing is sent**. Use high-entropy tokens; distinct, none a substring of another.
- **Escaping** is handled (element and attribute contexts). A body with literal `{ }` is unaffected
  (substitution is a literal replace, not `str.format`).
- **Captured replies** are best-effort scrubbed of the secret; `reingress_to` is refused with `body_secrets`.
- **Operator caution.** If you edit-and-resend a message whose body shows a `MF_…` token, leave the token in
  place — do not paste the real credential over it (that would write it into the store).

### Email / SMTP — `Email(...)` / `SMTP(...)` (outbound send, ADR 0029)

An **outbound destination only** — sends the Handler's output as a plain-text SMTP message (IMAP/POP read is
a deferred Phase 2). The Handler produces the email **body** (content-agnostic — an HL7 string, a JSON/XML
report, plain text); this connector delivers it to `host:port` from `sender` to `recipients` with a static
`subject`. `Email(...)` and `SMTP(...)` are the same factory (`ConnectorType.EMAIL`).

| Param | Type | Default | Notes |
|---|---|---|---|
| `host` | str / `env()` | — (required) | SMTP server host. |
| `sender` | str / `env()` | — (required) | `From:` address, and the envelope sender (`MAIL FROM`) that bounces go to. It must be one plain `local@domain` under the same rule as each recipient, so a display name, a group or an encoded word is refused at load. The full address rule, the domain's shape included, is in [CONFIGURATION.md `[egress]`](CONFIGURATION.md#egress). Its domain is not checked against `[egress].allowed_recipient_domains`. |
| `recipients` | list[str] / str / `env()` | — (required) | `To:` address(es). An `env()` may be the whole value; one inside the list is refused at load. An entry with a line break is refused at load too. |
| `port` | int / `env()` | `587` | `587` = STARTTLS submission; `465` = implicit TLS (`SMTP_SSL`). |
| `subject` | str / `env()` | `""` | Static subject (a per-message subject is a Phase-2 follow-up). |
| `username` | str / `env()` / None | `None` | SMTP `AUTH` user — put the secret in `env()`. |
| `password` | str / `env()` / None | `None` | SMTP `AUTH` password — `env()` only. AUTH is sent **over TLS only**; a cleartext-credential config is refused. |
| `use_tls` | bool | `True` | STARTTLS by default. `False` puts the message **body** (PHI) on the wire in the clear, so it is doubly gated. **The opt-in** is one of exactly two things you can actually set: `MEFOR_ALLOW_INSECURE_TLS` (process-global — it weakens *every* connector in the process, and it is read through the **clamped** check, so it cannot relax an enforcing production-PHI hop), or this connection's `cleartext_accepted = true` with its mandatory `cleartext_reason` (per-hop, audited — see [Declaring a cleartext hop](#declaring-a-cleartext-hop-cleartext_accepted), and prefer it). **And** the hop then goes through the shared authority (#200, ADR 0092 as amended by ADR 0153): loopback ALLOWs, a `cleartext_accepted` hop **WARNs + audits** (never a silent allow), a non-enforcing instance WARNs, everything else REFUSES — **no data label relaxes it**. A connection whose hop is secured by other means can [attest it](#attesting-a-hop-secure-tls_hop_attested) instead, which ALLOWs it. SMTP AUTH over cleartext stays refused OUTRIGHT, by any route. Matches the raw-TCP / X12 / plaintext-DICOM / anonymous-FTP cleartext egress paths. |
| `timeout_seconds` | float | `30.0` | |
| `encoding` | str | `"utf-8"` | The body's charset. A body that cannot be encoded in it is a permanent `encoding` refusal. It dead-letters on the first attempt and is never retried. The error names the charset, never the content. |

The egress host is **gated by `[egress].allowed_smtp`** — add the host or the destination is refused at
config load/reload. On a **PHI** instance (every built-in env name by default,
[ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)) an **empty**
`allowed_smtp` does **not** mean "unrestricted": `[security].block_unlisted_outbound` is on unless
written false, so an empty
`allowed_smtp` refuses *every* SMTP destination. Empty-means-unrestricted survives only where an
operator writes `[security].block_unlisted_outbound = false` — the explicit, audited opt-out. No
instance can declare its way out of the deny default ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)), and the default does not read
`[security].enforcement` either — see [CONFIGURATION.md `[egress]`](CONFIGURATION.md#egress). (The key is
`[security].block_unlisted_outbound`; `[egress].deny_by_default` moved there under ADR 0118 and is
**rejected at config load**.)

**CAUTION: whether `allowed_smtp` counts toward the open-egress startup gate depends on that
switch.** A mail-only instance that writes it `false` exits 2. "Which lists the startup gate
counts" in [CONFIGURATION.md `[egress]`](CONFIGURATION.md#egress) is the rule, and it covers
`allowed_direct` too.

**The recipients are gated too, and that gate is deny-by-default.** `allowed_smtp` gates only the
relay hop, so every address in `recipients` must also sit in a domain listed in
`[egress].allowed_recipient_domains`. An empty list refuses every `Email()` destination. The
matching rules are in [CONFIGURATION.md `[egress]`](CONFIGURATION.md#egress).

Delivery is **at-least-once**: a retry re-sends the email, and since a mailbox has no idempotency key a rare
duplicate is possible and **accepted by design** (a duplicate beats a drop). `test_connection` does
connect/EHLO/NOOP only (reachability — it never sends `MAIL FROM`/`DATA`).

```python
# samples/config/connections.py (excerpt)
from messagefoundry import outbound, Email, env

outbound(
    "OB_ALERTS_EMAIL",
    Email(
        host=env("SMTP_HOST"),
        port=587,
        sender="mefor@example.org",
        recipients=["oncall@example.org"],
        subject="MessageFoundry alert",
        username=env("SMTP_USER"),
        password=env("SMTP_PASS"),  # AUTH over STARTTLS
    ),
)
# In messagefoundry.toml (the SERVICE settings file, or --service-config — an [egress] table dropped
# in the --config dir is never read):
#   [egress]
#   allowed_smtp = ["smtp.example.org"]
#   allowed_recipient_domains = ["example.org"]   # deny-by-default: required for any Email()
# allowed_smtp alone satisfies the open-egress startup gate only while
# [security].block_unlisted_outbound is left unset; see CONFIGURATION.md §[egress].
```

### Direct Project — `Direct(...)` (S/MIME over SMTP, outbound send, ADR 0085)

An **outbound destination only** — the Direct Project's trusted-correspondent lane. The Handler produces the
clinical **body** (content-agnostic — an HL7 string, a CDA/XML document, plain text); this connector **SIGNs**
it with the sender's key + cert (authenticity + integrity), **ENCRYPTs** the signed blob to the partner's
`recipient_cert` (confidentiality — sign-then-encrypt, so the signature is itself confidential), and submits
the S/MIME message to `host:port` over STARTTLS SMTP. PHI is therefore protected **end-to-end**, independent
of the transport TLS. Crypto is core `cryptography` (`serialization.pkcs7`) and SMTP is stdlib `smtplib` —
**no new dependency, no extra**.

The envelope encrypts the content under **AES-256-CBC**. That is fixed in code, not a setting
(BACKLOG #1168). The content key is wrapped to the recipient's RSA key with RSAES-PKCS1-v1_5, which the
library offers no way to change. A partner whose S/MIME stack cannot decrypt AES-256-CBC cannot read
these messages, and the SMTP relay accepts them before anyone tries.

| Setting | Default | Meaning |
|---------|---------|---------|
| `host` | — (required) | the SMTP / HISP relay host (the `[egress].allowed_direct` key; use `env()`) |
| `sender` | — (required) | the Direct `From:` address, and the envelope sender (`MAIL FROM`) that bounces go to. It must be one plain `local@domain` that reads back unchanged, so a display name, a group or an encoded word is refused at load. The full address rule, the domain's shape included, is in [CONFIGURATION.md `[egress]`](CONFIGURATION.md#egress). Its domain is not gated. |
| `recipients` | — (required) | the Direct `To:` address(es) — a list or a single string. Each address is held to the sender's rule after any display name or group is dropped, and `To:` and `RCPT TO` carry exactly that checked address. An entry with a line break is refused at load. |
| `signing_cert` | — (required) | path to the sender's PEM/DER signing **certificate** |
| `signing_key` | — (required) | path to the sender's PEM/DER signing **private key** |
| `signing_key_password` | — | passphrase for an encrypted `signing_key` — a **secret**, via `env()`; it must meet the [wrap floor](#encrypted-private-keys-must-meet-the-wrap-floor) |
| `recipient_cert` | — (required) | path to the partner's PEM/DER **encryption** certificate (the encryption target). Must carry an **RSA** key: the S/MIME envelope supports RSA key transport only, so any other key type (EC included) is refused at construction |
| `trust_anchor` | — (required) | path to the PEM/DER CA the `recipient_cert` must chain to |
| `port` | `587` | `587` = STARTTLS submission; `465` = implicit TLS (`SMTP_SSL`) |
| `subject` | `""` | static `Subject` |
| `username` / `password` | — | optional SMTP `AUTH` credentials (secrets — via `env()`). Setting a `username` makes the relay a credential hop: to an off-box host it is then **refused on a stock instance** unless `[tls].crl_file` reaches the hop or the connection declares `tls_revocation_attested` with a reason (BACKLOG #2193). With no `username` the relay carries no revocation gate |
| `use_tls` | `true` | STARTTLS by default. `false` is refused unless `MEFOR_ALLOW_INSECURE_TLS` is set, and SMTP `AUTH` over cleartext is **refused outright**. **WARNING: this is not the same posture as `Email(...)` — the shipped enforcing default does not close it.** `Direct()` consults the **raw** escape variable directly: it does **not** route through the shared cleartext-hop authority, so `[security].enforcement = enforce` does **not** clamp it and `cleartext_accepted` / `cleartext_reason` on the outbound are **not consulted** (declaring them changes nothing here). With the variable set, a cleartext-SMTP Direct hop crosses on a production-PHI enforcing instance. The S/MIME body stays signed + encrypted either way — but the SMTP envelope (sender, recipients, subject) does not. |
| `timeout_seconds` | `30.0` | passed to the `smtplib` constructor (covers connect and each command) |
| `encoding` | `utf-8` | charset the body is encoded with before signing |

**Fail-loud at construction.** Every piece of crypto material is loaded and cross-checked when the connector
is built — so `messagefoundry check` / dry-run / start catches it, never the first message: a malformed
key/cert, a `signing_key` whose public half **does not match** `signing_cert`, a `recipient_cert` whose key
is **not RSA**, and a `recipient_cert` **not issued by** any supplied `trust_anchor` (PHI is never encrypted
to a certificate from an untrusted issuer). The connector then signs and encrypts one fixed synthetic body.
So a fault that would fail every S/MIME build also fails here. That covers at least a crypto library or
OpenSSL build that refuses the algorithms, and a line break inside `subject`. It does not cover the SMTP hop:
the relay can still refuse a `sender` or recipient at send time.
The trust check is deliberately **one level** (the recipient cert chains directly to a supplied anchor, or is
a self-signed correspondent cert pinned as its own anchor) — full multi-level path building is deferred. No
hostname/SAN match is done: a Direct address is an email, not a TLS SNI. Errors name the *setting* only,
never the material or a cert subject (which can identify a patient's provider).

**Delivery semantics.** Egress is gated by **`[egress].allowed_direct`** — kept separate from
`allowed_smtp` so a Direct HISP relay can be permitted without opening the general mail relay. An SMTP
failure raises `DeliveryError`, so the lane **retries** per its `RetryPolicy`. A message that cannot be
**built** raises a **permanent** `NegativeAckError` and dead-letters on the first attempt, because a retry
would fail the same way. That is a body the `encoding` cannot represent, or a crypto failure that began
after construction. Its error names the failure class, or the codec and character position, and never the
body. Delivery is **at-least-once** and a Direct mailbox has no idempotency key, so a rare duplicate
is possible and **accepted by design** (a duplicate beats a drop), exactly as with `Email(...)`.
`test_connection` does connect / STARTTLS / EHLO / optional login / NOOP — never `MAIL FROM` or `DATA`.

**Scope (ADR 0085 PR1) — outbound only.** An **inbound** Direct mail source (IMAP/POP + S/MIME
decrypt/verify), **MDN** disposition notifications, **DNS CERT / LDAP** certificate discovery, per-recipient
certificate maps, IHE **XDR/XDM**, and the Direct IG's CMS signed attributes (`signingTime`,
`ESSCertIDv2`) are all deferred later phases and **not** built.

```python
from messagefoundry import Direct, env, outbound

outbound(
    "DIRECT-OUT_REFERRAL",
    Direct(
        host=env("hisp_host"),
        sender="clinic@direct.example.org",
        recipients=["intake@direct.partner.example"],
        signing_cert=env("direct_signing_cert"),
        signing_key=env("direct_signing_key"),
        signing_key_password=env("direct_signing_key_pw"),  # a SECRET — always via env()
        recipient_cert=env("direct_partner_cert"),
        trust_anchor=env("direct_trust_anchor"),
        subject="Referral",
    ),
)
# In messagefoundry.toml (the SERVICE settings file, or --service-config — not the --config dir):
#   [egress]
#   allowed_direct = ["hisp.example.org"]
# allowed_direct alone satisfies the open-egress startup gate only while
# [security].block_unlisted_outbound is left unset; see CONFIGURATION.md §[egress].
```

### FHIR — `FHIR(...)`

An **outbound** FHIR REST client ([ADR 0022](adr/0022-fhir-resource-codec-rest-client.md)) that delivers a
FHIR resource (or transaction/batch `Bundle`) to a FHIR server. It **reuses the REST connector's HTTP
client exactly as SOAP does** (same no-redirect, `http`/`https`-only opener and the `[egress].allowed_http`
host gate) — it is **not** a wrapper around `Rest(...)`. The Handler produces a **FHIR-JSON** body; this
sets the `application/fhir+json` media type (Content-Type + Accept) and POSTs/PUTs it per the configured
interaction. The pure `messagefoundry.parsing.fhir` codec — `FhirPeek` to route (cheap, no `[fhir]` extra),
`FhirResource` to validate/transform (the `[fhir]` extra) — is called **on demand in Routers/Handlers**,
never pushed through the pipeline. There is **no FHIR source connector**: the inbound FHIR **server facade**
(a `/fhir` endpoint with resource-type routing and a CapabilityStatement) is still deferred — BACKLOG #20,
now a *consumer* of the shipped [`Http(...)`](#http-web-service-listener--http-inbound-only-adr-0023)
listener rather than blocked on it. Meanwhile `content_type="fhir"` routes a FHIR body received over **any**
source (`Http()`, File, a `Loopback` re-ingress) as a `RawMessage`.

| Setting | Default | Meaning |
|---------|---------|---------|
| `url` | — (required) | the FHIR service **base** URL (e.g. `https://host/fhir`); `http`/`https` only. Use `env()`. |
| `fhir_version` | `R4B` | `R4B` (default) / `R5` / `STU3` — explicit (no plain-R4 on pydantic-v2 wheels) |
| `format` | `json` | `json` only; FHIR-XML is deferred to a hardened-`lxml` path |
| `interaction` | `create` | `create` (`POST {base}/{ResourceType}`) / `update` (`POST {base}` with a one-entry `transaction` `Bundle` whose entry is `PUT {ResourceType}/{id}`; see [the id stays out of the URL](#an-update-keeps-the-resource-id-out-of-the-url)) / `transaction` / `batch` (`POST {base}` with a `Bundle`) |
| `conditional` | — | opt-in: `if-none-exist` (conditional create) / `conditional-update` (search-based PUT) / `if-match` (version-aware update, sent like `update` with the ETag in the entry, or in an `If-Match` header with `update_url_form="path"`) |
| `conditional_query` | — | FHIR search params for `if-none-exist` / `conditional-update` (e.g. `identifier=sys\|val`) |
| `update_url_form` | `transaction` | how an `update` or `if-match` is sent. `transaction` keeps the id out of the URL. `path` is the plain `PUT {base}/{ResourceType}/{id}` with the ETag in an `If-Match` header, for a server with no `transaction` interaction. `path` is a **listed loosening**; see [vendor compatibility](#vendor-compatibility-and-the-path-form-opt-in) |
| `headers` | `{}` | extra **static** headers (no secrets — an `env()` ref *inside* the table is refused at load; `env()` for the whole table is fine) |
| `bearer_token` | — | `Authorization: Bearer …` (SMART/OAuth — a **secret**, via `env()`) |
| `basic_user` / `basic_password` | — | HTTP Basic auth (secrets — via `env()`) |
| `timeout_seconds` | `30` | per-request timeout |
| `verify_tls` | `true` | TLS cert verification — the same posture-keyed cell as [REST](#rest--rest): `false` is **refused at construction** off loopback, and the `MEFOR_ALLOW_INSECURE_TLS` escape is **clamped inert** while `[security].enforcement = enforce` (the shipped default) |
| `tls_allow_expired` | `false` | **(#129, ADR 0094)** tolerate an **expired** server cert with chain + hostname still verified. **No posture gate and no escape variable**. It **is reported**: a WARNING at each build, a `tls-allow-expired` line in `messagefoundry check` and a `security_loosenings()` entry, and so `GET /security/posture` (CORRECTED 2026-10-01: this row said `security_loosenings()` never reports it, stale since BACKLOG #333) — see the [MLLP row](#mllp--mllp) |
| `tls_ca_file` | — | **(#1180)** pins this hop to one private CA; `FhirLookup()` takes it too. See [Pinning a private CA per connection](#pinning-a-private-ca-per-connection-tls_ca_file) |
| `tls_ca_pin` | — | (vault BACKLOG #2371) the SHA-256 of `tls_ca_file`; a mismatch is refused. See [The engine checks the file at every start and reload](#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin) |
| `encoding` | `utf-8` | body charset |
| `capture_response` | `false` | capture the server reply (assigned resource / `OperationOutcome`) as a response artifact (ADR 0013) |
| `reingress_to` | — | route the captured reply into this `Loopback` inbound (implies capture) |

**Interactions.** The `interaction` plus the `ResourceType`/`id` (read from the outgoing body with the cheap
`FhirPeek`, no typed parse) derive the method + path off the base `url`. A `transaction`/`batch` POSTs the
`Bundle` to the base — the FHIR **server** applies it (transaction = all-or-nothing, batch = independent per
entry); the engine never orchestrates cross-entry atomicity.

**Conditional knobs (idempotency / concurrency).** FHIR's native answer to the at-least-once duplicate
problem — opt-in, off by default: `if-none-exist` (create only if no match; the search rides the
`If-None-Exist` **header**), `conditional-update` (the server resolves which resource to update; the search
is in the **URL** query), and `if-match` (optimistic lock on a known id via an ETag derived from the
resource's `meta.versionId`, sent as the entry's `request.ifMatch`).

#### An update keeps the resource id out of the URL

The engine never puts a message-derived resource id in the request URL of a write. A RESTful update is
`PUT {base}/{ResourceType}/{id}` by specification, and an id in the path would reach the receiving server's
access logs on a first deployment. So `update` and `if-match` send the resource as the one entry of a
`transaction` `Bundle`, POSTed to `{base}`. The entry's `request` carries `PUT {ResourceType}/{id}` and, for
`if-match`, the `ifMatch` ETag. The server processes that entry as the same update
([FHIR http, transaction](https://hl7.org/fhir/R4B/http.html#transaction)). This is vault BACKLOG #1965,
under ASVS 14.2.1 and owner ruling R3.

What a site needs to know:

- The server must support the `transaction` interaction, and for `if-match` it must honor an entry's
  `request.ifMatch`. A server that accepts transactions but ignores `ifMatch` would apply the update
  unconditionally, and nothing would fail. Check both before pointing an `update` or `if-match`
  connection at a server. A server with no `transaction` interaction needs the
  [path-form opt-in](#vendor-compatibility-and-the-path-form-opt-in) below.
- The entry carries a `fullUrl` of `{base}/{ResourceType}/{id}`, because FHIR requires one on a `PUT`
  entry. Like the rest of the entry, it is in the body.
- The resource goes out byte for byte. It is spliced into the `Bundle` unchanged, so a decimal such as
  `1.50` keeps its precision.
- The reply is a `transaction-response` `Bundle`, and with `capture_response` that `Bundle` is what is
  captured. The capture outcome comes from the entry's `response.outcome`.
- If a server answers 2xx while the entry's own `response.status` failed, the message is classified on
  that entry status, like any other HTTP status. An entry status that does not read as an HTTP code is
  logged as a warning, and the 2xx reply counts as delivered.
- A reply body over the byte bound is not kept, so the engine cannot see the entry's status. The
  update is then a permanent refusal, code `reply-too-large`, in either capture mode, and it is not
  sent again. It is not recorded as delivered. See *A 2xx reply over the byte bound* under REST.
- `capture_response_headers` still captures `ETag`, `Location` and `Last-Modified`. They come from the
  entry, which describes the updated resource, and an entry field hides a reply header of the same
  name. They keep the entry's formats: `Last-Modified` is a FHIR instant, not an HTTP-date, and
  `Location` is usually relative. A value with a control character, or longer than a header value may
  be, is dropped.
- An `If-Match`, `If-None-Match`, `If-Modified-Since` or `If-None-Exist` header moves into the entry's
  matching field, whether it is static in `headers` or stamped by a Handler through `dynamic_headers`.
  The connector's own `if-match` ETag wins over both, as it did on the `PUT`.
- The resource type stays in the URL for `create`, `if-none-exist` and `conditional-update`, and so does
  the operator-configured search of `conditional-update`. None of them is the message-derived id.

The read site is outside this. A `fhir_lookup` read-by-id is `GET {base}/{ResourceType}/{id}`, which is what
a RESTful read is by specification. Owner ruling R3 names the update and if-match writes only, and the
vault row records that it does not decide the read site.

##### Vendor compatibility and the path-form opt-in

At least two large EHR vendors document no `transaction` interaction, so the default form would fail
against them on a first deployment. These readings were taken on 2026-10-01 and are not a vendor
guarantee; check the server you will point at.

- **Epic.** The CapabilityStatement of Epic's public R4 sandbox (its `metadata` endpoint, reached from
  <https://fhir.epic.com>) declares no system-level interaction: no `transaction` and no `batch`. Epic documents a plain `PUT api/FHIR/R4/{Type}/{ID}` on a
  narrow set of APIs, with the version check in an `If-Match` header. One example is Observation.Update
  (<https://fhir.epic.com/Specifications/Api?id=974>).
- **Oracle Health (Millennium).** The bundle endpoint
  (<https://docs.oracle.com/en/industries/health/millennium-platform-apis/mfrap/op--post.html>) allows only
  `type: batch`, entry method `POST`, and the Provenance resource. Its CapabilityStatement declares `batch`
  only. A plain `PUT [base]/[type]/[id]` is documented for at least AllergyIntolerance, Condition,
  DocumentReference, FamilyMemberHistory, Immunization, Observation and QuestionnaireResponse, with
  `If-Match` required on most.

For a server like these, a connection can opt back into the plain form:

```python
outbound("OB_EPIC_OBS", FHIR(url=env("epic_fhir_base"), conditional="if-match", update_url_form="path"))
```

**A plain `interaction="update"` sends no `If-Match` header.** Only `conditional="if-match"` adds one. So
a server that requires `If-Match` on update would refuse a plain update, and the message would
dead-letter. There are three ways to send the header:

- Set `conditional="if-match"`, as the example does. Each resource then needs a `meta.versionId`.
- Put a static `If-Match` in `headers`. It is the same on every message, so it only helps where the
  server accepts one fixed value.
- Set `dynamic_headers=True` and have a Handler stamp `If-Match` per message.

`messagefoundry check` prints an advisory `fhir-update-if-match` line. It names each path-form update
with no `conditional="if-match"` and no static `If-Match`. It **never blocks**: it cannot tell which
server a connection points at, and it cannot see a header a Handler stamps. The sourcing for which
Oracle Health resources require the header stops at "most" in the bullet above. Check the vendor's page
for the resource you write. This is vault BACKLOG #2570.

With `update_url_form="path"`, an `update` or `if-match` is sent as `PUT {base}/{ResourceType}/{id}`:

- The id must match the FHIR id grammar, `[A-Za-z0-9\-\.]{1,64}`, and must not be only dots. Any other id
  is refused as a bad message and dead-lettered. It is never sent. A valid id is percent-encoded into the
  path.
- The `if-match` ETag goes in the `If-Match` header, and a static `If-Match` in `headers` stays on the
  request.
- The reply is the plain resource, so capture and `capture_response_headers` work as on any `PUT`.
- The setting applies only to `update` and `if-match`. Set on any other connection, it is refused at load,
  because it would do nothing.

**It puts each message's resource id back in the request URL**, and so in the receiving server's access
logs. That relaxes owner ruling R3 (ASVS 14.2.1), so it is a listed loosening in
[SECURITY-LOOSENING.md](SECURITY-LOOSENING.md#update_url_form--path-on-a-fhir-connection--the-resource-id-in-the-request-url).
The engine logs a WARNING naming the connection at every construction, and `messagefoundry check` names
every connection that sets it. Set it only on the connection that needs it. FHIR is not a
`connections.toml` transport, so the setting is a `FHIR()` keyword only. This is vault BACKLOG #2550.

**OperationOutcome & delivery semantics.** A 2xx is **delivered** (a returned `OperationOutcome` is captured,
never an error). On an error status the HTTP code decides, refined by the `OperationOutcome`: 5xx → retry; a
4xx whose `issue.code` is in the FHIR **transient** IssueType group (`lock-error`/`throttled`/`timeout`/
`incomplete`), or `408`/`429` → retry; any other 4xx / refused 3xx → **dead-letter**. The HTTP status wins
when in doubt (a 5xx stays transient). `OperationOutcome`/reply bodies are **not** echoed into errors/logs
(they may carry PHI) — only the HTTP status + a redacted URL. For a 2xx whose body is over the byte bound,
see *A 2xx reply over the byte bound* under REST.

**Security & idempotency.** Same hardening as REST (redirects refused, scheme constrained, host gated by
`[egress].allowed_http`, cleartext-credential refusal, optional detached-JWS signing, secrets via `env()`).
Delivery is **at-least-once**, so a retry **re-sends** — the FHIR server operation **must be idempotent**
(the conditional knobs are the native lever). HL7 v2 ↔ FHIR mapping stays in **code-first Handlers**.

```python
from messagefoundry import FHIR, ContentType, File, Send, env, handler, inbound, outbound, router
from messagefoundry.parsing.fhir import FhirPeek, FhirResource

inbound("FHIR-IN_INTAKE", File(directory="./in/fhir", pattern="*.json"),
        router="fhir_router", content_type=ContentType.FHIR)        # FHIR body routes as a RawMessage
outbound("FHIR-OUT_SERVER", FHIR(url=env("fhir_base_url"), interaction="create"))


@router("fhir_router")
def route(msg):
    # cheap routing peek — no [fhir] extra needed
    return ["fhir_handler"] if FhirPeek.parse(msg.raw).resource_type == "Patient" else []


@handler("fhir_handler")
def handle(msg):
    # validate (R4B) then deliver the canonical JSON; a non-conformant resource dead-letters
    return Send("FHIR-OUT_SERVER", FhirResource.parse(msg.raw, version="R4B").encode())
```

See `samples/config/IB_FHIR_INTAKE.py` for a runnable route. The typed codec needs the `[fhir]` extra
(`pip install 'messagefoundry[fhir]'`); the `FhirPeek` routing tier does not.

### SMART Backend Services auth — `with_smart_backend(...)` (FHIR/REST client OAuth2, ADR 0024)

A real **SMART-secured** FHIR server (Epic, Oracle Health) does **not** accept a long-lived static
`bearer_token`: it requires **SMART Backend Services** authorization — OAuth2 `client_credentials` with an
**asymmetric, signed `client_assertion` JWT** (`RS384`/`ES384`), which it exchanges for a **short-lived**
bearer (~5 min, no refresh token). Compose `with_smart_backend(...)` over a `FHIR(...)` or `Rest(...)`
spec ([ADR 0024](adr/0024-smart-backend-services-token-provider.md)) and the connector mints the
assertion, exchanges it at the **token endpoint**, caches the bearer with expiry-awareness, and injects it
**per request** (re-minting on a `401`). No new dependency — the JWT is signed by the ADR 0018 core-
`cryptography` signer. The minted bearer **overrides** any static `bearer_token` on the spec.

**It is not only for SMART servers, and the name hides that.** What reaches the wire is a plain
**RFC 7523 section 2.2 `private_key_jwt`** exchange — `grant_type=client_credentials` plus a signed
assertion — with no FHIR or SMART field in it, so this composes over a bare `Rest(...)` against **any**
authorization server that registers a public key for your client. Prefer it to
`with_oauth2_client_credentials(...)` whenever your partner offers the choice: a shared `client_secret`
is reusable at every endpoint it is registered with, while the assertion's `aud` is this connection's
pinned token endpoint and the key never leaves the engine (BACKLOG #1158). Pass `algorithm="RS256"` for
a generic partner — the `RS384` default below is SMART's own requirement, not this engine's.

**If you stay on `with_oauth2_client_credentials(...)`**, its `auth_style` defaults to `"basic"`. The
client id and secret then ride an `Authorization: Basic` header on every token request.
`auth_style="post"` puts them in the form body. Both styles send the secret itself, so the stronger
option above is a choice you make per connection. Why `basic` stays the default is recorded once, in
that function's docstring in `messagefoundry/transports/http_auth.py` (vault BACKLOG #2206).

| `with_smart_backend(...)` arg | Default | Notes |
|---|---|---|
| `token_url` | — (required) | the authorization server's token endpoint (`https`; `env()`). **Also gated by `[egress].allowed_http`** — it is a second egress host. |
| `client_id` | — (required) | the registered client id (`iss`/`sub` of the assertion; `env()`) |
| `private_key` | — (required) | the assertion signing key as inline PEM (via `env()`) or a PEM file path |
| `algorithm` | `RS384` | `RS384` (RSA) or `ES384` (ECDSA P-384) — the two SMART **SHALL**-support algorithms |
| `scope` | `None` | the requested scopes, e.g. `system/Patient.c` (SMART v2 system scopes — no human). Request the least the connection can work with — see *Least scope* below |
| `key_id` | `None` | the JWT `kid` → the public key registered with the server (for rotation) |
| `audience` | = `token_url` | the assertion `aud`, if the server documents a different audience |
| `private_key_password` | `None` | passphrase for an encrypted key (secret — use `env()`); it must meet the [wrap floor](#encrypted-private-keys-must-meet-the-wrap-floor) |
| `expiry_skew_seconds` | `60` | re-mint this many seconds before the server's stated expiry. The engine caches a token for at most one hour after this skew, whatever `expires_in` says |

```python
from messagefoundry import FHIR, env, outbound
from messagefoundry.transports.smart import with_smart_backend

# Push FHIR to a SMART-secured server (Epic / Oracle Health).
outbound("FHIR-OUT_EPIC", with_smart_backend(
    FHIR(url=env("epic_fhir_base"), interaction="create"),
    token_url=env("epic_token_url"),     # add this host to [egress].allowed_http too
    client_id=env("epic_client_id"),
    scope="system/Patient.c",            # ONLY what this feed writes — see below
    private_key=env("epic_smart_key"),   # inline PEM via env(), or a PEM file path
    algorithm="RS384",
    key_id="epic-2026",
))
```

**Least scope.** A SMART v2 scope is `system/<ResourceType>.<letters>`, where the letters are `c` create,
`r` read, `u` update, `d` delete and `s` search. Ask for the ones this connection actually spends and no
more (ASVS 10.2.3):

A `conditional=` knob **overrides** `interaction` — it decides the HTTP method on its own, so read this
table top to bottom and take the first row that matches:

| the connection you declared | the letters it can use |
|---|---|
| `conditional="conditional-update"` | `u`, `s` — a search-based `PUT` |
| `conditional="if-none-exist"` | `c`, `s` — a `POST` the server searches for first |
| `conditional="if-match"` | `u` — a version-aware update, no search |
| `interaction="create"` (no conditional) | `c` |
| `interaction="update"` (no conditional) | `u` — the one `transaction` entry is an update, and a server authorizes a transaction entry by entry |
| `FhirLookup(...)` (structurally GET-only) | `r`, `s` |
| `interaction="transaction"`/`"batch"` | the Bundle decides, so no fixed set |

`interaction` defaults to `"create"`, so a connection declaring only `conditional="conditional-update"`
issues `PUT` and needs `u` — not the `c` the interaction name suggests.

The **resource** half is yours to choose: the outbound reads the resourceType from each outgoing message,
so name the type the feed writes rather than `*`. `messagefoundry check` prints an advisory `smart-scope`
line naming any connection that requests letters its declared interaction cannot spend. It **never
blocks**: your authorization server registers the scopes it will grant, and a refusal computed here could
take a working feed offline. It also stays quiet when a request is too *narrow* — that is a correctness
question, and asking for a letter the server never registered fails the token request outright.

**Wildcard scope and audience.** `check` also prints an advisory `oauth-request` line (vault BACKLOG
#2334). It names three things:

- on `with_oauth2_client_credentials(...)`, a `scope` token that contains a `*`, such as `*` or
  `claims.*`. A named scope is never graded, because that vocabulary belongs to your partner. It does
  not read a SMART `scope`; the `smart-scope` line above does.
- on `with_smart_backend(...)`, an `audience` that is not exactly the `token_url`. It is sent as
  written, so letter case and a trailing slash count.
- on `with_oauth2_client_credentials(...)`, an `audience` that is a URL on a different scheme, host or
  port from the connection's `url`. An audience that is not a URL is an opaque API identifier, and is
  never graded.

Each of these can be a correct setup, so the line **never blocks**. It compares literal values only.
`check` does not resolve `env()`, so the line also names every setting it could not compare, each
with its reason. The examples in this file write the endpoint and token URLs as `env()`, so a URL
audience on a connection written that way is listed as not compared. Read that list as "not
checked", not as "clean".

Put **every** secret in `env()` (`token_url`/`client_id`/`private_key`/`private_key_password`); the minted
access token and `client_assertion` are runtime-only — never logged or persisted. (The signing key comes
from `MEFOR_VALUE_*`, so a SMART outbound isn't shipped as a loaded `samples/config` route — adapt the
snippet above into your own config dir.) **Out of scope (ADR 0024):** SMART **App Launch** (the human-user
browser flow), the SMART **authorization/resource server** facade (the system-of-record's role; gated on
ADR 0023), JWKS hosting, `.well-known` discovery, and Bulk Data `$export`.

### DICOM — `DICOM(...)` (inbound C-STORE SCP + outbound C-STORE SCU/C-ECHO) and `DICOMweb(...)` (STOW-RS), ADR 0025

A **DICOM** connector (`ConnectorType.DIMSE`) is both an **inbound C-STORE SCP** listener and an
**outbound C-STORE SCU** sender over DIMSE/`pynetdicom` ([ADR 0025](adr/0025-dicom-codec-store-connectors.md));
`DICOMweb(...)` (`ConnectorType.DICOMWEB`) is the modern HTTP imaging lane — an **outbound STOW-RS** store/send
destination. All three carry the object **opaquely** — pair an inbound `DICOM(...)` with `content_type="dicom"`
so each received object routes as a `RawMessage` ([ADR 0004](adr/0004-payload-agnostic-ingress.md)); a
Router/Handler parses it on demand via `messagefoundry.parsing.dicom` (a cheap `DicomPeek` for routing,
`DicomDataset` + SR→HL7 helpers for transform), and a forwarding Handler re-emits the carried bytes to a SCU
or STOW-RS destination. The codec is **headers and Structured Report only — no pixel data**. The DIMSE
connectors need the **`[dicom]` optional extra** (`pip install 'messagefoundry[dicom]'`:
`pydicom>=3.0.2,<3.1` + `pynetdicom>=3.0.4,<3.1`, pure-Python, no numpy), lazily imported; **DICOMweb needs no
extra** (it stores the object as opaque bytes over the shared `rest.py` HTTP plumbing). Still out of scope:
MWL, Query/Retrieve (C-FIND/C-MOVE/C-GET), and pixel-data handling.

| Setting | Default | Meaning |
|---------|---------|---------|
| `ae_title` | — (required) | this engine's Application Entity title — the SCP AE a peer C-STOREs to |
| `port` | `104` | bind port (104 is the registered DICOM port; use e.g. `11112` for a non-privileged dev bind) |
| `presentation_contexts` | `None` → SR + common image storage + Verification | the SOP classes the SCP negotiates (transfer syntaxes default to the standard set) |
| `calling_ae_allowlist` | `None` → any (subject to the IP gate) | only these calling AE titles may associate (fail-closed when set) |
| `require_called_ae_title` | `True` | a peer must address this engine's `ae_title` as the called AE |
| `max_object_bytes` | `134217728` (128 MiB), **but the SCP never honours more than the engine's 16 MiB binary ingress ceiling** | reject a single C-STORE object larger than this (OOM/DoS guard). **The SCP's effective cap is the smaller of this value and 16 MiB**, because the engine records any larger object as `ERROR` and never processes it, and an SCP that accepted one would tell the sender Success for an object the engine dropped (BACKLOG #1910). So the shipped default resolves to 16 MiB on the SCP, and a larger value cannot raise it. When the SCP clamps a value you set, for example 64 MiB or `0`, it logs a `WARNING` at build naming the value, the ceiling and the inflate bound (BACKLOG #1962). It stays silent on 128 MiB, since the shipped default cannot be told from an explicit setting. It is charged **twice**: first against the **raw received Data Set**, before `pydicom` decodes it, so an over-cap object is refused without ever being decoded or re-encoded; then against the re-encoded Part-10 bytes, which the raw length cannot see (the preamble, `DICM` and file meta are added there). Both charges land **before** the durable commit. It **also** bounds the pre-decode **inflate** of a *Deflated Explicit VR LE* object, whose compressed raw length says nothing about how far it inflates: the SCP bound-inflates the raw received Data Set before pydicom touches it, so an over-cap deflate bomb is a DIMSE failure and is never decoded or committed. The inflate bound is never above 16 MiB, the ceiling the codec applies when a Router parses the object (BACKLOG #2104). `0`/`None` does not remove the check on the SCP: it resolves to the same 16 MiB ceiling, and a negative value is refused at build. An over-cap object is refused before any commit, so nothing is recorded for it. The SCP does not answer Success for an object that the engine's ingress, or the codec's inflate ceiling, would then refuse. The C-STORE status each refusal answers, and whether a sender should re-send, is stated once in [`DICOM.md`](DICOM.md) section 3 |
| `max_associations` | `10` | cap on concurrent inbound associations (connection-flood guard) |
| `max_associations_per_second` | **off** | sustained rate at which this SCP **accepts new associations** (ASVS 2.4.1 / 15.2.2, BACKLOG #1114). Over budget the SCP **waits before reading the association request**, so the peer is back-pressured by TCP and then served in full — **nothing is dropped, refused or answered differently**, and a rejected association charges nothing. **The unit is an association, not a message,** and that is a property of DIMSE: `pynetdicom` owns the read loop, so by the time a C-STORE reaches the engine the object is already read and decoded, and pacing there would delay a message the count-and-log invariant has already obliged us to account for. **So an established association is NOT bounded in the objects it may push** — `max_object_bytes` and `timeout_seconds` bound those instead. Unset = no bound, which is a deliberate exception to this table's usual secure-default rule, exactly as on the listen intakes: a guessed rate throttles a real modality, so the number has to come from your own feed profile. **Pair it with `max_associations`,** which must be large enough to hold the peers waiting behind a pace — and keep the resulting wait inside your senders' ACSE timeouts, or a paced modality aborts. |
| `association_burst` | = the rate | tokens the bucket holds, i.e. how large a burst of associations passes unpaced before the sustained rate applies. Only meaningful with `max_associations_per_second` set. Floor of 1 so an SCP can always make progress. |
| `max_pdu_size` | `16384` | cap one PDU's bytes (`0` = unbounded); DoS guard |
| `timeout_seconds` | `30.0` | ACSE/DIMSE/network timeout |
| `tls` | `false` | wrap the association in **DICOM-over-TLS** (required for a non-loopback bind — see below) |
| `tls_cert_file` / `tls_key_file` | — | the SCP's server-identity cert + private key (required when `tls=true`) |
| `tls_key_password` | `None` → unencrypted key | passphrase for a PKCS#8-encrypted `tls_key_file` (`env()`-sourced, mirroring MLLP's `MEFOR_*_TLS_KEY_PASSWORD`). The key must meet the [wrap floor](#encrypted-private-keys-must-meet-the-wrap-floor). An encrypted key supplied with **no/wrong** passphrase **fails fast** at startup/`check` rather than hanging on an interactive TTY prompt (there is no TTY under an NSSM service account / in a container). |
| `tls_ca_file` | — | opt-in **mTLS**: require + verify a calling peer's client certificate |
| `tls_ca_pin` | - | the SHA-256 of `tls_ca_file`. Pins the CA's integrity (BACKLOG #1142): a pin that does not match always refuses. Under `[security].enforcement = enforce` the engine also refuses a CA another account can replace, or one whose permissions or path it cannot read; a matching pin lets the second kind load, with a warning and an `auth.trust_anchor` row. Each check writes its rows under `inbound:<connection name>`. An SCU's CA takes the same checks at start and at every reload, under `outbound:<connection name>`, and there a matching pin is no escape: see [The engine checks the file at every start and reload](#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin) (vault BACKLOG #2371). It pins `tls_ca_file` only. A `tls_crl_file` is read by path with no pin, and a certificate in it that `tls_ca_file` does not already hold refuses the build (BACKLOG #1890). Set without `tls` and `tls_ca_file`, it is refused, since nothing would check it. Set but empty or whitespace, it is refused too; leave it out for no pin. |

The **bind interface** is the service-level `[inbound].bind_host` (or a per-connection `bind_address`) and the **peer-IP gate** is the per-connection **`source_ip_allowlist`** — both are set on the `inbound(...)` call, not as `DICOM()` arguments. **NOTE: `source_ip_allowlist` is *not* a key of the `[inbound]` section in `messagefoundry.toml`.** That section carries only `bind_host`, `ack_after`, `stream_inflight_budget_bytes` and `max_staged_depth`, and an unrecognized key in a known section is **refused at load** — so writing `source_ip_allowlist` under `[inbound]` in the service TOML **fails the start** (`serve` exit 2), naming the section and the key. It used to be accepted silently and do nothing, which is the failure mode the refusal exists to remove. (Verified: `InboundSettings.model_fields` is exactly those four; `[inbound].source_ip_allowlist` raises `unrecognized config key(s)`, while a sibling `bind_host` loads.) `bind_address` is the same story — a per-connection keyword, not a `[inbound]` key. The reachable forms are `inbound("IB_…", DICOM(...), source_ip_allowlist=["10.20.0.0/16"])` and, for the transports available as data, the **top-level** `source_ip_allowlist` key in `connections.toml` (shown in the [`connections.toml` example](#connections-as-data--connectionstoml-adr-0007) above) — `DICOM()` is code-first only, so for a SCP it is the `inbound(...)` keyword. A non-loopback cleartext SCP is **refused at startup** unless `tls=true` (the generalized [cleartext] bind-guard — `check_dimse_tls_exposure`). `serve --allow-insecure-bind` downgrades that refusal to a warning, but the flag is **clamped** exactly as it is for the MLLP/HTTP/TCP listeners: on a PHI-classified instance under the default `[security].enforcement = enforce` the bind is refused *even with it*, so on a stock instance `tls=true` is the only way to bind off-loopback. (`host` / `called_ae_title` / `connect_timeout` on `DICOM()` are for the **Phase-2 outbound SCU** and are unused by the inbound SCP.)

**While the engine pauses intake, the SCP refuses new associations as busy** and lets open ones finish. The `[inbound].max_staged_depth` row in [CONFIGURATION.md](CONFIGURATION.md) is the source of record for how each inbound pauses.

> **Fail-closed peer controls (deny-by-default).** DICOM has no transport authentication on its own, so a **non-loopback** SCP **MUST** set a **verifiable** peer control — either a per-connection `source_ip_allowlist` (an `inbound(...)` keyword — **not** a `[inbound]` service-TOML key, see the note above), or **mTLS** (`tls=true` **and** `tls_ca_file`, which makes the SCP require + verify a client cert). With **neither** set, a non-loopback SCP is **refused at construction** (the connection degrades per ADR 0031 startup fault isolation; surfaced under `check`/dry-run). This is the **authentication** analog of the `check_dimse_tls_exposure` cleartext bind-guard above (which is the orthogonal **confidentiality** guard): TLS-without-mTLS encrypts the channel but does **not** authenticate the peer. A **loopback** bind (`127.0.0.1`/`localhost`/`::1`, the common dev/single-box case) is exempt.
>
> **CAUTION: `calling_ae_allowlist` does not satisfy this gate on its own (BACKLOG #316).** It used to: the three controls were counted as co-equal. But a Calling AE Title is a string the caller asserts about **itself** in the association request — no key, no signature, nothing to verify — and AE Titles are published in conformance statements and visible in any capture. An SCP whose only control was an AE-title list was reachable by anyone who could route to it and knew one string, while passing a check named "fail-closed peer controls". **Keep it — it is still enforced at association time and is a genuinely useful filter** (it catches a misrouted sender and pins intent). It simply has to be **paired** with `source_ip_allowlist` or mTLS off-loopback.
>
> **CAUTION: a `source_ip_allowlist` counts only when it is narrow (vault BACKLOG #2622).** Every entry must meet the HTTP intake gate's prefix floors, applied by the same function; [DEPLOYMENT.md](DEPLOYMENT.md) states them. So `["0.0.0.0/0"]` or `["::/0"]` does not count, and one too-wide entry stops the whole list counting. With no mTLS, an SCP with such a list is refused at construction like one with no list. **mTLS still counts by presence:** `tls` + `tls_ca_file` admits any client certificate that CA signed, with no subject binding. The HTTP gate refuses that shape; this gate does not yet.
>
> **WARNING: the construction gate counts controls, so the wrong spelling passes it.** Set
> `calling_ae_allowlist` (AE titles are attacker-chosen strings on an unauthenticated association —
> trivially spoofable) plus a `[inbound].source_ip_allowlist` in `messagefoundry.toml` and the SCP
> builds and runs happily, because the AE list alone satisfies the "at least one" test — while the
> IP restriction you thought you configured was silently discarded at settings load. The engine's own
> refusal message names the discarded spelling, so do not take it as the authoring surface. Pass it on
> the `inbound(...)` call instead.
>
> **And there is no read-back to check yourself against on a code-first connection.**
> `messagefoundry graph --json` prints the *connector spec's* settings (so `calling_ae_allowlist`
> shows, `source_ip_allowlist` and `bind_address` do not), and `GET /connections/{name}/metadata`
> renders the same spec view. `messagefoundry connection list --json` **does** echo
> `source_ip_allowlist` — but only for connections authored in `connections.toml`, which `DICOM()` cannot
> be. So on a SCP the `inbound(...)` call is both the only place to set it and the only place to
> audit it: review the call, not a read-out.

```python
from messagefoundry import DICOM, ContentType, Message, Send, handler, inbound, router
from messagefoundry.parsing.dicom import DicomDataset, DicomPeek, hl7_map

# Receive stored DICOM objects (C-STORE SCP); each is base64-carried (ADR 0028) and routed as a RawMessage.
inbound("IB_RADIOLOGY_SR",
        DICOM(ae_title="MEFOR_SR_SCP", port=11112, calling_ae_allowlist=["RAD_MODALITY"]),
        router="sr_router", content_type=ContentType.DICOM)


@router("sr_router")
def route(msg):
    if not msg.is_binary:            # a non-carried body → UNROUTED (counted + logged)
        return []
    peek = DicomPeek.parse(msg)      # cheap shallow tag read (recovers the bytes via .raw_bytes)
    return ["sr_to_oru"] if peek.is_structured_report() else []


@handler("sr_to_oru")
def handle(msg):
    ds = DicomDataset.parse(msg)     # headers + SR ContentSequence only — no pixel data
    measurements = ds.measurements()
    if not measurements:
        return None                  # nothing to deliver → FILTERED (counted + logged)
    oru = Message.parse(
        "MSH|^~\\&|MEFOR|RADIOLOGY|POWERSCRIBE|FACILITY|"
        f"{ds.study_date or ''}||ORU^R01|{ds.sop_instance_uid or 'UNKNOWN'}|P|2.5.1"
    )
    oru.add_segment(hl7_map.pid_from_dataset(ds))   # SR→HL7: code-first, HL7-escaped, CR/LF-guarded
    oru.add_segment(hl7_map.obr_from_dataset(ds))
    for set_id, m in enumerate(measurements, start=1):
        oru.add_segment(hl7_map.obx_from_measurement(set_id, m))
    return Send("OB_POWERSCRIBE", oru.encode())
```

A **hardened non-loopback** SCP (bound to an imaging VLAN) pairs DICOM-over-TLS for confidentiality with at
least one peer control for authentication — here an AE-title allowlist, mTLS **and** the peer-IP gate
(secrets are always `env()` references, never inline). Note where each control lives: the TLS/AE settings
are `DICOM()` arguments, while **`bind_address` and `source_ip_allowlist` are `inbound(...)` keywords** —
the whole point of the `[inbound]`-versus-`inbound(...)` note above. Without a `bind_address` (or a non-loopback `[inbound].bind_host` in
`messagefoundry.toml`) this listener binds `127.0.0.1` and is not the non-loopback SCP the heading
describes:

```python
from messagefoundry import DICOM, ContentType, env, inbound

inbound("IB_RADIOLOGY_SR",
        DICOM(ae_title="MEFOR_SR_SCP", port=11112,
              calling_ae_allowlist=["RAD_MODALITY"],            # authentication: only this calling AE
              tls=True,                                          # confidentiality: DICOM-over-TLS
              tls_cert_file=env("DICOM_TLS_CERT"),
              tls_key_file=env("DICOM_TLS_KEY"),
              tls_key_password=env("DICOM_TLS_KEY_PASSWORD"),   # if the key is passphrase-encrypted
              tls_ca_file=env("DICOM_MTLS_CA")),                # mTLS: require + verify the peer's client cert
        router="sr_router", content_type=ContentType.DICOM,
        bind_address="10.20.4.7",                    # the imaging-VLAN NIC — an inbound() keyword
        source_ip_allowlist=["10.20.0.0/16"])        # peer-IP gate — an inbound() keyword, NOT [inbound]
```

The full worked route (with the outbound MLLP + `env()` wiring) ships at
[`samples/config/IB_RADIOLOGY_SR.py`](../samples/config/IB_RADIOLOGY_SR.py).

- **No DICOM ACK to mint.** The connector returns the DIMSE **C-STORE response status** (SUCCESS) to the
  peer; an HL7-style ACK does not apply.
- **Off-loop + commit-before-SUCCESS.** `pynetdicom`'s blocking handlers run **off the asyncio event
  loop**; the received object is bridged onto the loop (`run_coroutine_threadsafe`) and **durably committed
  to the ingress stage before the C-STORE SUCCESS status is returned** — so a SUCCESS means the object is
  persisted, never accepted-and-dropped. A peer that times out and re-sends is idempotent against this.
- **SR → HL7 mapping is a code-first Handler.** `parsing/dicom` supplies `DicomPeek` (tolerant routing
  peek: SOPClassUID, Modality, study/series/instance UIDs, AE titles), `DicomDataset` (headers + an SR
  ContentSequence walk → measurements), and `hl7_map` (SR→HL7 `OBX`/`PID`/`OBR` builders, HL7-escaped and
  CR/LF-guarded) — never pushed through the pipeline; a Handler calls them on demand against the
  `RawMessage`.
- **Security.** A calling-AE + peer-IP allowlist (fail-closed when set), a `max_object_bytes` per-object
  cap and association/DoS caps, a generalized non-loopback **bind-guard** (a non-loopback listener is a
  deliberate operator decision, as with MLLP/TCP), and **DICOM-over-TLS**. The codec reads **headers/SR
  only** — no pixel-data surface.
- **Outbound is built (Phase 2).** The **C-STORE SCU** + **C-ECHO** sender and the **DICOMweb STOW-RS**
  destination ship below. **MWL, Query/Retrieve (C-FIND/C-MOVE/C-GET), and pixel-data handling remain
  out of scope.**

#### `DICOM(...)` outbound — C-STORE SCU + C-ECHO (ADR 0025 Phase 2)

Pair the **same** `DICOM(...)` factory with `outbound(...)` to **forward** a DICOM object to a downstream
PACS over a C-STORE association (full Mirth-sender parity). A forwarding Handler returns the carried object
bytes (`Send("OB_PACS", msg.encode())` for a pass-through, or a re-built object); the SCU recovers the bytes
from the base64 carriage (ADR 0028), runs the blocking association **off the event loop**, and classifies
the C-STORE status onto the retry model. `test_connection` issues a **C-ECHO** (the DIMSE reachability ping
behind the console's "Test Connection"). Egress is gated by `[egress].allowed_tcp` (a raw socket, like X12).

| Setting | Default | Meaning |
|---------|---------|---------|
| `ae_title` | — (required) | this engine's **calling** AE title |
| `host` | — (required for outbound) | the downstream PACS host (`env()`-able) |
| `port` | `104` | the peer's DIMSE port |
| `called_ae_title` | `None` → `ANY-SCP` | the peer SCP's AE title to address |
| `max_object_bytes` | `134217728` (128 MiB) | reject an over-cap object **before** dialing (permanent — no retry) |
| `timeout_seconds` | `30.0` | ACSE/DIMSE/network timeout |
| `connect_timeout` | `10.0` | association-request (TCP connect) timeout |
| `tls` / `tls_ca_file` / `tls_cert_file` / `tls_key_file` | `false` / — | **DICOM-over-TLS**: verify the peer's server cert (`tls_ca_file` pins the anchor); `tls_cert_file`/`tls_key_file` opt into **mTLS**. There is **no `tls_verify=false`** on this connector — chain and hostname are always verified. Since BACKLOG #2193 it carries the **revocation gate** MLLP/REST/SOAP/FHIR/DICOMweb/EMAIL carry: `tls=true` to an off-box PACS **is refused on a stock instance** unless `[tls].crl_file` reaches the hop or the connection declares `tls_revocation_attested` with a reason (CORRECTED 2026-10-04: this row said the hop had no revocation gate and was not refused) |
| `tls_ca_pin` | — | (vault BACKLOG #2371) the SHA-256 of `tls_ca_file`; a mismatch is refused. See [The engine checks the file at every start and reload](#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin) |
| `tls_allow_expired` | `false` | **(#129, ADR 0094)** tolerate an **expired** PACS certificate with chain + hostname still verified. Combined with a `tls_revocation_attested` declaration, this hop can be pinned to a certificate that is **both expired and revoked** with nothing in the engine refusing it — **no posture gate and no escape variable**. It **is reported**: a WARNING at each build, a `tls-allow-expired` line in `messagefoundry check` and a `security_loosenings()` entry, and so `GET /security/posture` (CORRECTED 2026-10-01: this row said `security_loosenings()` never reports it, stale since BACKLOG #333) (see the [MLLP row](#mllp--mllp)) |
| `tls_key_password` | `None` → unencrypted key | passphrase for a PKCS#8-encrypted mTLS-client `tls_key_file` (`env()`-sourced); it must meet the [wrap floor](#encrypted-private-keys-must-meet-the-wrap-floor). Same fail-fast semantics as the inbound SCP (no/wrong passphrase raises at construction, never a TTY hang). |

**Status → retry classification.** C-STORE **Success** (`0x0000`) / a **Warning** (`0xB0xx`, stored with a
caveat) → delivered; **Out of Resources** (`0xA7xx`) or an association/transport failure → transient
`DeliveryError` (retried with backoff); any other hard refusal (Cannot Understand, dataset-does-not-match-SOP,
Not Authorized, SOP-class-not-supported) → permanent `NegativeAckError` → dead-letter. **Idempotency:**
delivery is at-least-once, so a retry re-sends the same object — the receiving PACS must be idempotent on
`SOPInstanceUID`. **PHI:** logs carry only routing-safe identifiers (SOP class/instance UID, peer host).

```python
from messagefoundry import DICOM, Send, env, handler, inbound, outbound, router

# Forward received SR objects unchanged to a downstream PACS (C-STORE SCU).
outbound("OB_PACS",
         DICOM(ae_title="MEFOR_SCU", host=env("PACS_HOST"), port=11112, called_ae_title="REMOTE_PACS"))


@handler("forward_sr")
def forward(msg):
    return Send("OB_PACS", msg.encode())   # re-emit the base64-carried object bytes verbatim
```

#### `DICOMweb(...)` outbound — STOW-RS store/send (ADR 0025 Phase 2)

The modern HTTP imaging lane — a **STOW-RS** `POST {base}/studies` (or `{base}/studies/{study_uid}`) that
**exceeds** both Mirth's and Corepoint's DICOM options (neither ships DICOMweb send out of the box). It is a
**sibling of the REST destination**: it reuses the hardened HTTP plumbing (no-redirect TLS-verifying opener,
cleartext-credential refusal, the retry/dead-letter classification, the `[egress].allowed_http` gate) and
adds only the `multipart/related; type="application/dicom"` framing + `application/dicom+json` response
handling. It needs **no `[dicom]` extra** (the object is opaque bytes).

| Setting | Default | Meaning |
|---------|---------|---------|
| `url` | — (required) | the DICOMweb service **base** URL, e.g. `https://host/dicom-web` (`env()`-able) |
| `study_uid` | `None` → `POST {base}/studies` | when set, store into a known study (`POST {base}/studies/{study_uid}`) |
| `bearer_token` / `basic_user` / `basic_password` | — | OAuth bearer or HTTP Basic (put secrets in `env()`) |
| `headers` | `{}` | static extra headers (no secrets — an `env()` ref *inside* the table is refused at load; `env()` for the whole table is fine) |
| `timeout_seconds` | `30.0` | request timeout |
| `verify_tls` | `true` | TLS cert verification — the same posture-keyed cell as [REST](#rest--rest): `false` is **refused at construction** off loopback, and the `MEFOR_ALLOW_INSECURE_TLS` escape is **clamped inert** while `[security].enforcement = enforce` (the shipped default). **`DICOMweb()` has no `tls_allow_expired`** — it reuses the REST client but does not read that setting, so a DICOMweb hop always enforces certificate expiry |
| `tls_ca_file` | — | **(#1180)** pins this hop to one private CA. See [Pinning a private CA per connection](#pinning-a-private-ca-per-connection-tls_ca_file) |
| `tls_ca_pin` | — | (vault BACKLOG #2371) the SHA-256 of `tls_ca_file`; a mismatch is refused. See [The engine checks the file at every start and reload](#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin) |
| `capture_response` | `false` | capture the STOW-RS `dicom+json` response as a reply (ADR 0013) |

**Status classification.** A 2xx whose `dicom+json` body carries a per-instance **FailedSOPSequence**
(`00081198`) → the instance was rejected → permanent dead-letter; a 409 (all instances failed) / other 4xx /
a refused 3xx → permanent; 5xx / 408 / 429 / connection-timeout → transient retry. A 2xx whose body is
over the byte bound cannot be checked for a FailedSOPSequence, so it is a permanent refusal and is not sent
again: see *A 2xx reply over the byte bound* under REST. **PHI:** the response can
name patient/study identifiers, so it is never logged — only the HTTP status and a redacted URL are.

```python
from messagefoundry import DICOMweb, Send, env, handler, outbound

outbound("OB_DICOMWEB", DICOMweb(url=env("DICOMWEB_BASE"), bearer_token=env("DICOMWEB_TOKEN")))


@handler("stow_sr")
def stow(msg):
    return Send("OB_DICOMWEB", msg.encode())   # STOW-RS the carried object bytes
```

### Timer — `Timer(...)` (clock-driven source, ADR 0011)

An **inbound source that reads no external resource**: it *fires* on a clock and hands an
operator-configured `body` to the pipeline — the shape behind a heartbeat, a nightly extract trigger, or a
scheduled query a Handler fans out. **Source-only** (it generates, never delivers).

| Setting | Default | Meaning |
|---------|---------|---------|
| `body` | — (required) | the payload emitted **verbatim** on every fire, pre-encoded once at construction so each fire is byte-identical (a re-run stays pure). Declare its format with `inbound(..., content_type=...)`: the default `hl7v2` runs the HL7 peek/validate path; `text`/`json` route a `RawMessage`. |
| `interval_seconds` | — | fire every N seconds. The heartbeat **starts at t=0** (fires immediately on start, then every interval). Must be `> 0`. |
| `run_once` | `false` | fire a **single** time, then idle until stop. |
| `cron_expression` | — | a calendar schedule (ADR 0011 amendment, #160) — a standard **5-field** expression (`minute hour day-of-month month day-of-week`) with `*`, lists, ranges and steps; day-of-week is `0-6`, **Sunday = 0** (`7` also accepted). When *both* day-of-month and day-of-week are restricted, a match on **either** fires (the Vixie OR rule). Unlike the interval heartbeat, cron does **not** fire at t=0 — the first fire is the next scheduled minute. Named months/weekdays are out of scope (numeric only). |
| `timezone` | — (system-local) | an IANA zone name (e.g. `"America/New_York"`) the cron schedule matches against, DST-aware. **Only** valid together with `cron_expression`. |
| `encoding` | `utf-8` | charset `body` is encoded with |

Exactly one of `interval_seconds` / `run_once` / `cron_expression`: the three are **mutually exclusive** and
declaring none is an error, so a mis-scheduled timer fails at `messagefoundry check` — as does an
unsatisfiable cron expression (e.g. `* * 30 2 *`, caught by a bounded horizon scan at parse) or an unknown
`timezone`.

- **Leader-gated.** The schedule is a *shared trigger*, so in a cluster **only the leader fires it** —
  otherwise every node would emit the same message. A follower's loop still ticks, so a node that wins
  leadership fires on its next tick with no restart; on a single node this is byte-identical to an ungated
  loop.
- **At-least-once on the *timing* boundary only.** The body is committed to the ingress stage and frozen
  there, so downstream re-runs stay pure. A fire whose durable write fails (DB locked, disk full) is
  **logged and retried on the next tick** — it never kills the source (that would silently stop intake
  while still reporting `running`), and a `run_once` timer retries until it lands.
- **Nothing to bind or probe.** A Timer takes no `bind_address`/`source_ip_allowlist`, and
  `POST /connections/{name}/test` reports `supported=false`.

```python
from messagefoundry import ContentType, Timer, inbound

# A weekday 08:00 trigger in a named zone; the Handler builds the real work from the fired body.
inbound("TIMER-IN_NIGHTLY_EXTRACT",
        Timer(body="EXTRACT", cron_expression="0 8 * * 1-5", timezone="America/New_York"),
        router="extract_router", content_type=ContentType.TEXT)
```

### Loopback — `Loopback()` + `reingress_to=` (request → response → route, ADR 0013)

A **request/response** feed sends a query to a partner and **routes the partner's answer**. The capturing
outbound names a **loopback inbound** with `reingress_to=`; the captured reply is re-ingressed as a *new*
inbound message and routed by that loopback's `router`, exactly like any inbound.

**Works on every store backend** — SQLite, Postgres, and SQL Server all implement response capture and
re-ingress ([capability matrix](CONFIGURATION.md#per-backend-capability-matrix)).

- **`Loopback()`** is an inbound with **no source** — messages arrive *only* via the engine-internal
  re-ingress, never a socket/poll. It takes a `router` and `content_type` (`hl7v2` → `Message`;
  `x12`/`text`/`json` → `RawMessage`); it takes **no** `ack_mode` (forced `NONE` — no peer to ACK), no
  `bind_address`/`source_ip_allowlist` (no socket), and no `strict` validation (no untrusted intake).
- **`reingress_to="<loopback inbound name>"`** on a capturing outbound (`MLLP`/`Tcp`/`Rest`/`Soap`/
  `Database`) **implies `capture_response=True`** and points the reply at that loopback. It is validated at
  `messagefoundry check` / dry-run (the target must exist and be a `Loopback()`), both code-first and via
  `connections.toml` (`reingress_to` is a `[settings]` field).
- A re-ingressed reply's Handler can read the **original request's** captured reply with
  `response_get("<the query outbound>")`. Re-ingress is **exactly-once** (a guarded handoff, no
  double-injection) and loop-bounded by `[pipeline] max_correlation_depth` (default 8): a reply chain
  deeper than the cap dead-letters and the origin is marked `ERROR`. Today's status (`docs/api/test`) is
  visible on the message timeline (`reingressed` / `received (reingress …)` events) and the message
  metadata (`correlation_id` / `correlation_root_id`).

```python
# loopback inbound — NO source; the eligibility result arrives via re-ingress and is routed here.
inbound("IB-LOOP_PAYER_ELIG", Loopback(), router="route_elig_result", content_type=ContentType.HL7V2)

# capturing outbound — declares BOTH "capture" and "where the reply re-enters" in one place.
outbound("MLLP-OUT_PAYER_ELIG", MLLP(host=env("payer_host"), port=2575, reingress_to="IB-LOOP_PAYER_ELIG"))
# a Handler Sends the eligibility query to MLLP-OUT_PAYER_ELIG; its reply re-ingresses into IB-LOOP_PAYER_ELIG.
```

### Pass-through — `PassThrough()` (internal 1:N re-ingress, ADR 0013 generalized)

Another **inert internal inbound** — no socket, no poll. A Handler `Send`s its **transformed** message *into*
a PT inbound (naming it like an outbound) and the engine re-ingresses that body as a **new, independent
inbound message** on that channel, where the PT inbound's **own** Router decides where it goes next. This is
the Corepoint `PT_*` pattern: one logical feed fans out across internal connectors and re-routes deeper
without an external hop. `PassThrough()` takes **no settings** — a PT inbound carries only its `router` and
`content_type`.

- **Loopback vs. PassThrough.** `Loopback()` is the **1:1 reply** sibling: it is fed by a *capturing
  outbound*'s `reingress_to=` and its body is the partner's captured answer. `PassThrough()` is the **1:N
  internal routing** sibling: *any* Handler may target it and the body is the transformed message. Both share
  the same atomic content-addressed re-ingress shape.
- **Atomic, idempotent handoff.** The child ingress row is produced in the **same transaction** that consumes
  the parent's routed row (`transform_handoff`), so a crash/re-run is a no-op, never a double-injection. The
  handoff never crosses the source/listener seam — the connector deliberately **never invokes its handler**
  (that would be the bare-`enqueue_ingress` double-injection trap; a unit test pins it).
- **Loop-bounded.** A PT chain is bounded by `[pipeline].max_correlation_depth` (default 8) exactly like a
  loopback reply chain: work past the cap dead-letters and the origin is marked `ERROR`.
- **Like `Loopback()` otherwise.** No `ack_mode` (forced `NONE` — no external peer), no
  `bind_address`/`source_ip_allowlist` (no socket), and no `strict` validation (no untrusted intake — the body
  is engine-internal, already-stored state). A **store-backend gate** runs on every config-application path
  (start, reload, `reload(dry_run=True)`): all three shipped backends (SQLite, Postgres, SQL Server) support
  PT re-ingress, so it only ever rejects a graph on a backend that doesn't — before any swap or start.

```python
from messagefoundry import MLLP, PassThrough, Send, handler, inbound

inbound("IB_PT_Entry", MLLP(port=2576), router="pt_entry_router")
# The internal hop: no socket; fed only by the Send-into-PT handoff below, then re-routed by its own router.
inbound("PT_Relay", PassThrough(), router="pt_relay_router")


@handler("pt_entry_handler")
def to_passthrough(msg):
    return Send("PT_Relay", msg)     # → re-ingresses as a NEW message on PT_Relay
```

A runnable graph ships at [`harness/config/passthrough/graph.py`](../harness/config/passthrough/graph.py).

## Encrypted private keys must meet the wrap floor

An encrypted private key is opened with a key derived from its passphrase, so the derivation is
held to ASVS 11.4.4 (BACKLOG #1352). Every loader reads the key's wrap **before** anything decrypts
it, and refuses a weak one at `check` or startup. There is no setting to turn this off.

**What passes.** An unencrypted key. Or PKCS#8 PBES2 with PBKDF2-HMAC-SHA-256 at 600,000
iterations or more, or PBKDF2-HMAC-SHA-512 at 210,000 or more, which are the ASVS Appendix C floors.
scrypt passes at its Appendix C floor.

**What is refused.** At least these:

- legacy OpenSSL PEM encryption (a `Proc-Type: 4,ENCRYPTED` header), which derives the key with MD5;
- PBES1, the PKCS#12 PBE schemes, and PBKDF2 over HMAC-SHA-1 (including a PBKDF2 block with no
  `prf` field, which means SHA-1);
- PBKDF2 under its floor. **The common tools write 2048 iterations by default**: `openssl req`
  without `-nodes`, `openssl genpkey -aes256`, and `cryptography`'s `BestAvailableEncryption`. A key
  made any of those ways is refused until you re-wrap it;
- an encrypted key where the loader has no passphrase to give, before any library can prompt.

**Re-wrap a PEM or PKCS#8 key** at the floor, then point the setting at the new file:

```
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000 -in <old key> -out <new key>
```

**A PKCS#12 bundle for `cert import`** must have PBES2 bags at the floor and a **PBMAC1** MAC at
the floor. A MAC keyed by the PKCS#12 KDF is refused even over SHA-256, and that is what most
exports carry, OpenSSL's default included. **The MAC rule holds when the bags are not encrypted**
(`-keypbe NONE -certpbe NONE`): that MAC still runs the passphrase through the PKCS#12 KDF, so it is
refused too. So is `cryptography`'s `NoEncryption` output, whose MAC uses an empty passphrase. An
unencrypted bundle with no MAC at all (`-nomac`) passes with no passphrase, since nothing in it
comes from a password. Re-export with OpenSSL 3.4 or later:

```
openssl pkcs12 -export -keypbe AES-256-CBC -certpbe AES-256-CBC -iter 600000 -pbmac1_pbkdf2 -pbmac1_pbkdf2_md sha256 -in <cert> -inkey <key> -out <new pfx>
```

Or skip PKCS#12 and give the certificate and key as PEM files.

**Three loaders take no passphrase.** The SFTP key, `[logging].forward_tls_client_cert`, and the
native API client's key. An encrypted key there is refused; supply it unencrypted and protect the
file or secret store instead. The SFTP key must also be RSA-2048 or larger.

**A database driver's client key** (`sslkey` in a generic `Database(...)`'s `odbc_params`, with
`sslpassword` for its passphrase) is checked the same way before the connection string reaches the
driver. The driver still decrypts it.

## Declaring a cleartext hop (`cleartext_accepted`)

An **outbound** connection whose hop has no TLS is **refused** at `messagefoundry check` / dry-run /
reload / the serve pre-flight under the default `[security].enforcement = enforce`
([ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md)). No data
label relaxes that — `data_class = "synthetic"` used to allow every cleartext hop silently, and no longer
does. There are exactly three ways such a hop crosses:

| | claim | disposition |
|---|---|---|
| the hop is **on-box** (loopback / `localhost` / empty host) | not a network exposure | ALLOW |
| `cleartext_accepted = true` + `cleartext_reason` | this hop is **not** secure, and we accept that | **WARN** — crossed, loudly logged **and recorded at every construction** |
| `[security].enforcement = warn` | the instance-wide refuse/warn dial is at `warn` | WARN — but **only for the raw transports** (`MLLP()`, `Tcp()`, `X12()`, `DICOM()`, `Email()`, `Ftp()`). The HTTP family (`Rest()`, `Soap()`, `FHIR()`, `DICOMweb()`, `FhirLookup()`) shipped these refusals unconditionally, and ADR 0092 decision 5 forbids a cell getting weaker, so a no-loosen floor turns that WARN back into a REFUSE there. The dial is **not** a substitute for the declaration |

A fourth route makes the opposite claim: the hop *is* secure, by means the engine cannot see. That is
[`tls_hop_attested`](#attesting-a-hop-secure-tls_hop_attested), below. (The `[logging].forward_hop_attested`
sibling in `messagefoundry.toml` is the same claim for the log forwarder — see
[CONFIGURATION.md](CONFIGURATION.md).)

The two claims are deliberately **separate fields with opposite meanings**. Do not describe a peer that
simply cannot do TLS as attested: that writes a false statement into the one field that exists to be
trustworthy when it is audited, and it leaves the audit trail unable to tell a proxy-terminated hop from
plaintext on a flat network.

Both surfaces accept the pair — code-first on `outbound(...)`, or as **top-level** keys in
`connections.toml` (they are governance declarations, not transport settings, so they do **not** go under
`[outbound.settings]`). A `FhirLookup(...)` read connection takes the same two keyword arguments:

```python
outbound(
    "OB_LEGACY_LAB",
    Tcp(host=env("lab_host"), port=env("lab_port")),
    cleartext_accepted=True,
    cleartext_reason="vendor firmware predates TLS; segment is not isolated",
)
```

```toml
[[outbound]]
name = "OB_LEGACY_LAB"
transport = "tcp"
cleartext_accepted = true
cleartext_reason   = "vendor firmware predates TLS; segment is not isolated"
  [outbound.settings]
  host = "10.4.2.15"
  port = 5000
```

| Key | Dir | Type | Default | Meaning |
|-----|-----|------|---------|---------|
| `cleartext_accepted` | out | bool | `false` | this outbound's hop is cleartext and that is accepted. Yields **WARN, never ALLOW** — the hop crosses, but every construction logs it and records a line naming the connection, the cell, the host and the reason. It does **not** reach a `verify_tls = false` hop (encrypted-but-unauthenticated, not cleartext — that keeps the clamped `MEFOR_ALLOW_INSECURE_TLS` escape) or an SMTP `AUTH` over cleartext (refused outright) |
| `cleartext_reason` | out | str | — | **mandatory** when the flag is set (and rejected without it). The engine checks a reason is present and non-blank; it cannot check that it is *true* — a placeholder is a review problem, not a load problem |

**`Tcp()` and `X12()`: the declaration is permanent, not transitional.** Those connectors have **no TLS
support at all** — no `tls` parameter, no `ssl` import — so there is no `tls = true` for them to migrate
to. On every other **outbound** transport (`MLLP()`, `Rest()`, `Soap()`, `FHIR()`, `DICOMweb()`,
`DICOM()`, `Email()`, `Ftp()`, `FhirLookup()`) the declaration should be read as **naming work to be
done**, and removed when the peer gains TLS. Adding TLS to raw TCP and X12 is tracked as BACKLOG #311.

Three caveats on that list. `Http()` is an **inbound listener only** — it binds rather than dials, so it
has no hop to declare; inbound binds are governed by the four exposed-gates and
`serve --allow-insecure-bind` (itself clamped inert on the shipped enforcing-PHI default), not by this
declaration (ADR 0153 decision 2 is Destination-only). On `Ftp()` the declaration reaches
the **anonymous** plain-ftp hop only: a *credentialed* plain-ftp connection is refused outright, because
the credential itself would cross in the clear. And **`Direct()` is deliberately absent from the list —
the declaration does not reach it at all.** Its `use_tls=false` cell consults the raw
`MEFOR_ALLOW_INSECURE_TLS` escape rather than this authority, so setting `cleartext_accepted` on a
Direct outbound is accepted at load and then never consulted; see the
[`Direct(...)` `use_tls` row](#direct-project--direct-smime-over-smtp-outbound-send-adr-0085).

**It is never invisible.** A declared hop appears in `messagefoundry check` (a `cleartext-accepted` line
listing the **whole** accepted set, so a broad rollout is obvious in review), in the connector's
construction WARN + audit record, and in `GET /security/posture`'s loosening list — with a deviation
entry in [SECURITY-LOOSENING.md](SECURITY-LOOSENING.md). That visibility is the mitigation: nothing stops
an operator declaring it on every destination, and the engine does not try to.

## Attesting a hop secure (`tls_hop_attested`)

`tls_hop_attested = true` with a mandatory `tls_hop_attested_reason` says a hop **is** secure, by means
the engine cannot see. A TLS-terminating proxy or sidecar in front of the connection is the usual case.
An isolated segment with its own link-layer encryption is the other. An enforcing refusal of a
cleartext or verify-off hop then **ALLOWs** it
([ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md), owner ruling
2026-09-24). That covers at least a non-loopback inbound bind without TLS, a cleartext egress hop, a
verify-off HTTP-family egress hop and a weakened database TLS hop. It does **not** reach every
verify-off refusal: at least the MLLP, FTPS and email `tls_verify = false` refusals do not read it.

Set it on the declaration that owns the hop:

```python
inbound("IB_ACME_ADT", MLLP(port=2575), router="acme_adt_router", bind_address="0.0.0.0",
        tls_hop_attested=True, tls_hop_attested_reason="TLS terminates at the stunnel sidecar")
```

```toml
[[inbound]]
name = "IB_ACME_ADT"
transport = "mllp"
router = "acme_adt_router"
bind_address = "0.0.0.0"
tls_hop_attested = true
tls_hop_attested_reason = "TLS terminates at the stunnel sidecar"
  [inbound.settings]
  port = 2575
```

`outbound()` and a `[[outbound]]` table take the same pair, and so do `FhirLookup()`,
`DatabaseLookup()` and `DatabaseRef()`. It is a top-level key, **not** a transport setting. Under
`[settings]`, or written into a factory's settings dict from Python, it is refused at load. A flag with
no reason, a blank reason, or a reason with no flag also fail at load. So does an `env()` value, and so
does declaring it together with `cleartext_accepted`, which is the opposite claim.

**Do not attest a hop that is not secure.** A peer that simply cannot do TLS is
[`cleartext_accepted`](#declaring-a-cleartext-hop-cleartext_accepted), which WARNs at every
construction. An attested hop is recorded as secure, so a false attestation hides a plaintext hop.

**It is reported.** `messagefoundry check` prints a `tls-hop-attested` line listing every attested hop
with its reason, and `GET /security/posture` names them in a `tls_hop_attested` loosening. At least
the inbound bind gates and the raw-TCP/MLLP hop guard also log a WARNING with the reason when they
suppress a refusal. Not every cell does: the database weakened-TLS audit line omits the reason, and a
`DatabaseRef` source writes that same line. So those two reports are the complete record. The risk entry is in
[SECURITY-LOOSENING.md](SECURITY-LOOSENING.md). It does not reach a revocation refusal, which is
`tls_revocation_attested`, or SMTP `AUTH` over cleartext, which is refused outright.

## Pinning a private CA per connection (`tls_ca_file`)

`tls_ca_file` names a PEM file holding the CA a partner's server certificate chains to. When it is set,
the hop trusts **only** the CAs in that file. The OS trust store is not loaded, so no public CA can
vouch for the partner's host name. Owner ruling R7 of 2026-09-24 made it a supported parameter on
the HTTP-family factories and `Ftp()` (BACKLOG #1180).

At least these factories take it with this meaning: `Rest()`, `FHIR()`, `Soap()`, `DICOMweb()`,
`FhirLookup()` and `Ftp()`. `MLLP()`, `DICOM()`, `Email()` and `Direct()` already took it for an
outbound hop. In `connections.toml` it goes in the connection's `settings` table. Use `env()` when the
path differs per environment.

```python
from messagefoundry import outbound, FHIR, env

outbound(
    "FHIR-OUT_ACME_ORU",
    FHIR(url=env("acme_fhir_base"), tls_ca_file=env("acme_ca_pem")),
)
```

| Question | Answer |
|---|---|
| Does it beat the instance `[tls]` anchor? | Yes. The connection's own CA wins over `internal_ca_file` in every `trust_anchor_mode` ([ADR 0093](adr/0093-pinned-internal-ca-trust-anchor.md)). |
| Does it turn any check off? | No. Chain, host name and expiry checks stay on. It only chooses which CAs do the verifying. |
| What about `[tls].crl_file`? | On a hop that reads the `[tls]` block, it still applies and turns on leaf revocation checking. That CRL file must then carry a CRL from this CA too, or every handshake on the hop fails. An inbound `Ftp()` poller reads the `[tls]` block too, since vault BACKLOG #2370, so this applies to it as well. |
| Does it reach a token endpoint? | Yes. Where a connection signs in through SMART or OAuth2, the token hop trusts the same file, even when `verify_tls = false`. If the authorization server chains to a different CA, put that CA in the same PEM file. That also widens the data hop to it. No separate token-hop setting exists, by decision for now (vault BACKLOG #2370). |
| What if `verify_tls = false`? | The data hop ignores it, since a verify-off hop trusts nothing. A token hop still reads it, as the row above says. |
| Does it cover SOAP mutual TLS? | Yes. The client-certificate opener verifies the server against the same file. |
| Does it apply on a loopback hop? | Yes. Only the instance `[tls]` anchor exempts loopback. A connection's own CA does not. |
| What if the file is missing? | The integrity check below refuses it, naming the connection and the path. At start that fails the connection's own lane; at a reload it refuses the reload. `messagefoundry check` does not run that check. It builds every connection in one pass, and the build fails with an error that names the setting and, where the build knows it, the connection. So one missing file fails that whole pass. |
| What if it is blank? | On these six factories, and on `Email()` and `Direct()`, a blank literal is refused at load. A blank `env()` value is refused when it resolves, naming the setting, the connection and the environment key (vault BACKLOG #2370). |
| When is it refused as unread? | On `Ftp(tls=False)`, which has no TLS, and on `DICOMweb(verify_tls=False)`, which has no token hop. On the others, a token hop can still read it. |
| What if it is unset? | The hop is built exactly as before, from the instance `[tls]` block or the OS store. |

**It is opt-in.** Every default still trusts the OS store, so an internal hop without it is verified
against every CA the OS trusts. **Protect the file from writes.** It is not a secret, but whoever can
replace it chooses which CA the hop trusts.

### The engine checks the file at every start and reload (`tls_ca_pin`)

The engine checks the `tls_ca_file` of each connection that dials out (vault BACKLOG #2371).
`tls_ca_pin` is optional. It is the file's SHA-256 in hex, with `:` separators allowed. Every
factory that takes `tls_ca_file` for an outbound hop takes it: `Rest()`, `FHIR()`, `Soap()`,
`DICOMweb()`, `FhirLookup()`, `Ftp()`, `Email()`, `Direct()`, and an outbound `MLLP()` or
`DICOM()` with `tls = true`. An inbound `Ftp()` poller dials out too, so its CA takes the same
checks.

**When the check runs, and what a refusal stops.** This follows
[ADR 0031](adr/0031-startup-connection-fault-isolation.md), as amended on 2026-10-06.

| When | What a refused file stops |
|---|---|
| Start, for an outbound or an `Ftp()` poller | That connection only. It reads `failed`, and the rest of the graph comes up. |
| An operator start (`POST /connections/{name}/start`), such as of an `auto_start = false` lane | That connection only. |
| Start, for a `FhirLookup()` | The whole start. A lookup has no lane of its own to fail. |
| Every reload | The whole reload, before anything changes. |

| What the check finds | What happens |
|---|---|
| `tls_ca_pin` is set and the file's SHA-256 does not match it | Refused, whatever `[security].enforcement` says. |
| An account other than the owner can write the file, or replace it through a folder on its path | Refused under `[security].enforcement = enforce`. A WARNING under `warn`. |
| The engine cannot read the file's permissions or its path | Refused under `enforce`, **even with a matching pin**. A WARNING under `warn`. Move the file into a folder whose permissions the engine can read. |
| The file cannot be read at all | Refused, naming the connection and the path. |
| The file's SHA-256 differs from the one the last check saw | An `auth.trust_anchor` audit row with `event` set to `changed`. |

Each check writes its `auth.trust_anchor` rows under `outbound:<connection name>`,
`fhir_lookup:<name>` for a `FhirLookup()`, or `inbound:<connection name>` for an inbound `Ftp()`
poller. A `deployed = false` connection is not checked, since it is never built.

**A CA the hop never reads is not checked, and a pin beside it is refused at load.** That is a CA
behind `use_tls = false` or `tls_verify = false`. On `Rest()`, `Soap()`, `FHIR()`, `DICOMweb()` and
`FhirLookup()` it is also a CA behind `verify_tls = false` or an `http://` url, unless a SMART or
OAuth2 token hop reads it. A pin there would read as pinned while nothing checks it.

**Why a matching pin is no escape here.** On an inbound listener, a matching pin lets a CA load whose
permissions the engine could not read. That works because the listener loads the exact bytes the
check read. A dialling hop does not, yet. It reads the file again by path when it builds its TLS
context, after the check. So a file swapped between the check and the build would be trusted
unchecked until that connection is built again. A restart rebuilds it. A reload rebuilds it only
when its config changed. A later reload checks and audits the file on disk, not the bytes the live
hop loaded. So a `changed` row does not mean the hop now trusts the new file. A pin would vouch for
bytes the hop never loaded. For the same reason the check does not refuse a file the hop itself can
load, such as one holding a `TRUSTED CERTIFICATE` block.

`tls_ca_pin` with no `tls_ca_file` is refused at load, since nothing would check it. So is a pin that
is empty or whitespace; leave it out for no pin. On the eight factories above, a literal pin that
is not 64 hex characters is refused at load too, and an `env()` pin once it resolves. On `MLLP()`
and `DICOM()` a pin with no `tls_ca_file`, or without `tls = true`, is refused when the connection
is built instead, and a malformed one when the check runs.

On an inbound listener the same key means something different. On `Http()`, and on an inbound
`MLLP()` or `DICOM()`, it is the CA a **calling client's** certificate must chain to.

## Per-connection retention, document pruning & diagnostics overrides

A connection may **override** several service-wide `[…]` defaults for just itself. Each is set the same
two ways as `retry`/`buildup` — **code-first** on `inbound(...)`/`outbound(...)`, **or** as a key in
`connections.toml` (ADR 0007) — and each defaults to **inherit the global setting** when omitted.

### Retention overrides ([ADR 0027](adr/0027-per-connection-retention.md))

Override the global `[retention]` body-null windows per connection. `None` (omitted) = inherit the global
window; `0` = keep this connection's bodies **forever**; `>0` = days.

| Key | Dir | Type | Default | Meaning |
|-----|-----|------|---------|---------|
| `messages_days` | in | int | inherit the global body window — set as **`[security].delete_message_bodies_after_days`** (`[retention].messages_days` moved there under ADR 0118 and is **rejected at config load**) | past N days, null this **inbound's** received message bodies (keyed on the receiving inbound), keeping the message row — its PHI columns, `metadata` included, are blanked. `0` = keep forever |
| `dead_letter_days` | out | int | inherit `[retention].dead_letter_days` | past N days, null the bodies of **this outbound's** dead-lettered rows (keyed on the outbound that dead-lettered them). A dead row stays replayable until its body is purged. `0` = keep forever |

### Embedded-document pruning ([ADR 0042](adr/0042-embedded-document-pruning.md), #47)

A separate **inbound** lever that evicts only the bulky base64 **embedded document** (a `mfb64:v1:`
carriage value / an HL7 `OBX-5` ED embed) **in place** to a small tombstone — keeping the surrounding,
readable message — distinct from `messages_days`, which nulls the **whole** body.

| Key | Dir | Type | Default | Meaning |
|-----|-----|------|---------|---------|
| `prune_documents_after` | in | int | `None` = **never prune** (back-compat) | after N **days**, strip each embedded document for this inbound. Must be `> 0` |
| `prune_documents_min_bytes` | in | int | `None` = strip **any** size | skip an embed whose decoded size is **below** this byte threshold (keep small embeds, evict only the bulky ones). Setting it **requires** `prune_documents_after` (else a wiring error) |

### Diagnostics / event-log overrides ([ADR 0021](adr/0021-inbound-ack-nak-capture-response-sent.md), #46)

Override the `[diagnostics]` master switches for one connection. **Tri-state:** omitted = inherit the
matching master switch; `true`/`false` = explicit per-connection override.

| Key | Dir | Type | Default | Meaning |
|-----|-----|------|---------|---------|
| `capture_ack` | in | bool | inherit `[diagnostics].response_sent` | record the **"Response Sent"** ACK/NAK metadata for this inbound (the AA body only on an encrypted store; a NAK body is never stored) |
| `capture_connection_errors` | in | bool | inherit `[diagnostics].connection_events` | record this connection's **lifecycle + pre-ingress failure** events (established/closed, allowlist/capacity/oversize/peer-reset/framing) |

### `stall` — Max Message Stall ([ADR 0014](adr/0014-alerting-rules-engine.md), #50)

An **outbound** override of the `[delivery].stall_max_oldest_seconds` global: raise a `message_stall`
alert when this lane's **oldest undelivered message** has waited too long.

| Key | Dir | Type | Default | Meaning |
|-----|-----|------|---------|---------|
| `stall` | out | `StallThreshold` | inherit `[delivery]` (off unless set) | `StallThreshold(max_oldest_seconds=…)` — `None` keeps the stall alert **off** (it overlaps `buildup`'s age dimension, so it's opt-in to avoid double-paging). In `connections.toml` it is an `[outbound.stall]` table with `max_oldest_seconds` (see the example below) |

```python
from messagefoundry import MLLP, inbound, outbound
from messagefoundry.config.models import StallThreshold

# Inbound: keep this feed's bodies only 7 days, and prune embedded documents >256 KiB after 1 day.
inbound("IB_ACME_RAD", MLLP(port=2576), router="rad_router",
        messages_days=7, prune_documents_after=1, prune_documents_min_bytes=256 * 1024,
        capture_ack=True)                         # force-capture the ACK even if the master switch is off

# Outbound: keep this destination's dead-letter bodies 90 days; alert if a message stalls >10 min.
outbound("OB_PACS_RAD", MLLP(host="pacs", port=11112),
         dead_letter_days=90, stall=StallThreshold(max_oldest_seconds=600))
```

```toml
# connections.toml — the same overrides as data.
[[inbound]]
name = "IB_ACME_RAD"
transport = "mllp"
router = "rad_router"
messages_days = 7
prune_documents_after = 1
prune_documents_min_bytes = 262144
capture_ack = true
  [inbound.settings]
  port = 2576

[[outbound]]
name = "OB_PACS_RAD"
transport = "mllp"
dead_letter_days = 90
  [outbound.settings]
  host = { env = "pacs_host" }
  port = 11112
  [outbound.stall]
  max_oldest_seconds = 600
```

## Connection lifecycle — `deployed` & `auto_start`

Two per-connection booleans decide whether a connection is **wired** and whether it **starts**. Both are
set the same two ways as the overrides above — **code-first** on `inbound(...)`/`outbound(...)`, **or** as a
key in `connections.toml` (ADR 0007) — and both **default to `true`** (the always-on behaviour), so a
connection that sets neither is byte-identical to before.

| Key | Dir | Type | Default | Meaning |
|-----|-----|------|---------|---------|
| `deployed` | in/out | bool | `true` | `false` = the connection is **present in config but not wired** ([ADR 0111](adr/0111-not-deployed-connections.md)): no connector is built, **its `env()` values are never resolved**, no listener binds, no delivery worker spawns, and a `Send` to it is **recorded-and-dropped** (never queued). It stays in the graph, in `validate`/`graph --json`, and on `/connections` — surfaced as `not_deployed`, distinct from `stopped`. |
| `auto_start` | in/out | bool | `true` | `false` = the connection **is** deployed (built, `env()` resolved) but its listener/lane is **not started at boot**; it reports `stopped`, and an operator starts it at runtime via `POST /connections/{name}/start`. A boot-time gate only. |

**Three states that look alike and are not.** *Not deployed* is easy to confuse with a **simulated** or a
**parked** connection; conflating them loses messages or chases a phantom outage. They differ at every step:

| State | Built / `env()` resolved? | Receives rows? | On a `Send` to it | Disposition | Use for |
|-------|-----|-----|-----|-----|-----|
| **Not deployed** — `deployed=false` ([ADR 0111](adr/0111-not-deployed-connections.md)) | **No** — `env()` never resolved | No | recorded + dropped, **no row queued** | `NOT_DEPLOYED` (or the message finalizes `PROCESSED` if a *deployed* sibling also received it) | a feed kept in config for history / traceability / a future go-live but deliberately dark — a partner not live yet, a retired-but-kept send |
| **Simulated** — `simulate=true` / `[shadow].simulate_all_egress` (#15) | Yes — fully wired | Yes | delivered to nothing (egress suppressed) | `PROCESSED` | parallel-run / shadow: prove the transform without touching the live peer |
| **Parked** — DR run-profile ([ADR 0048](adr/0048-third-tier-disaster-recovery-standby.md)) / scheduler ([ADR 0095](adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)) | usually yes | Yes | **queued + retried, retained** | pending until it drains | a lane temporarily down (out-of-window, below DR threshold) that will resume and drain its backlog |

The operational payoff: *not deployed* is the **only** one of the three whose `env()` values are never
resolved — so a connection whose credentials/secrets **don't exist yet** is legal, `messagefoundry check`
passes, and the engine starts **healthy** rather than DEGRADED. `stopped` means *"should be running, isn't"*;
`not_deployed` means *"off by design."* **Start / restart and resend are refused (`409`)** on a not-deployed
connection — deploying it is a **config change** (flip the flag, supply the values, reload), not a runtime
action.

One more outbound state sits outside that ladder: **`log_halted`** ([ADR 0189](adr/0189-a-delivery-tier-log-halt-latch-read-at-the-claim-gate-rather-than-a-gate-at-every-door.md)).
The engine cannot write its application log and has fail-closed (#122, [ADR 0162](adr/0162-fail-closed-application-log-write-guard-detect-roll-and-stop.md)),
so no lane in the process delivers and every outbound reports it at once. It is deliberately not
`stopped`: nothing on that row is the fix, and start is refused until the disk is. Queued rows are
retained PENDING throughout. `failed`, `filtered` and `not_deployed` still win over it on the display,
because each of those is a fact about that one connection. See [SERVICE.md](SERVICE.md) for recovery.

```python
from messagefoundry import MLLP, env, inbound, outbound

# A partner that isn't live yet: keep it in the graph, but don't wire it or resolve its (absent) secrets.
outbound("OB_PARTNER_ADT", MLLP(host=env("partner_host"), port=env("partner_port", cast=int)),
         deployed=False)

# A test-only receiver that exists but is started by hand, not at boot:
inbound("IB_LAB_ORU", MLLP(port=2580), router="lab_router", auto_start=False)
```

```toml
# connections.toml — the same two flags as data.
[[outbound]]
name = "OB_PARTNER_ADT"
transport = "mllp"
deployed = false          # present, not wired — the env() settings below are never resolved while false
  [outbound.settings]
  host = { env = "partner_host" }
  port = { env = "partner_port", cast = "int" }

[[inbound]]
name = "IB_LAB_ORU"
transport = "mllp"
router = "lab_router"
auto_start = false        # deployed, but started at runtime, not at boot
  [inbound.settings]
  port = 2580
```

> `deployed=false` **wins over** `auto_start`: a not-deployed connection is never built, so its `auto_start`
> value is moot. To bring a not-deployed connection online, set `deployed=true` (and supply any `env()`
> values it needs), then reload — **no other change**.

## Inline fast path — `inline` (code-first only, ADR 0057)

**Leave `inline` off.** It is a per-inbound boolean on `inbound(...)`, default `False`.
[ADR 0057](adr/0057-inline-step-a-fast-path.md) records that it ships default-off permanently. It cut
commits per message as designed, and throughput moved by less than the measurement noise. It is
documented here so a reader who meets it in code knows what it does.

When it is `True`, the router worker runs the route and the transform for an eligible message itself.
It then commits one handoff straight from the ingress stage to the outbound stage, skipping the routed
stage. An inbound is eligible only when all of these hold:

- the whole graph declares no live lookup (the database or FHIR lookups behind `db_lookup` and
  `fhir_lookup`);
- its `ack_after` resolves to `ingest`;
- it is not a `Loopback()` inbound.

Each message then faces its own checks. At least, the router must pick exactly one handler, and that
handler must return one or more plain `Send`s to deployed outbound connections. A message that fails a check takes the
ordinary staged path, which may run its transform a second time.

```python
inbound("IB_LAB_ORU", MLLP(port=2580), router="lab_router", inline=True)  # not recommended
```

**`connections.toml` has no `inline` key.** A `[[inbound]]` table that carries one fails to load with
`unknown key(s) inline`, whether the value is `true` or `false`.

## Pipeline claim mode — `[pipeline].claim_mode` (default `pooled`, ADR 0066)

How the engine drains the staged queue. This is a service setting in `messagefoundry.toml`, not a
per-connection knob, and it is read **once at startup** — a `/config/reload` does **not** change it
(restart to change).

- **`pooled` — the default (since #744).** The engine runs **one shared `StageDispatcher` per stage**
  (ingress / routed / outbound, plus response for loopback feeds). A small pool of claimer tasks
  batch-claims work across all lanes, so idle and loaded connections no longer each run their own
  claim loop. This **collapses the per-connection claim storm** (at ~1,500 connections the old
  per-lane loops saturated a server-DB store on lock contention *independent of message volume*) and,
  on the single-node rate-walk, **held zero message loss at high fan-out where `per_lane` dropped
  messages**. It is now the recommended default for every deployment.
- **`per_lane` — the opt-out.** Set `[pipeline].claim_mode = "per_lane"` to restore the pre-ADR-0066
  topology: one router + one transform worker per inbound and one delivery worker per outbound, each
  with its own claim loop. It is **byte-identical** to the historical engine (enforced by a test
  sentinel) — the escape hatch if you need the old behavior.

```toml
# messagefoundry.toml — restore the pre-ADR-0066 per-lane workers (default is "pooled").
[pipeline]
claim_mode = "per_lane"
```

The flip changes **only how work is claimed**, never the reliability invariants: **at-least-once**
delivery, **strict per-lane FIFO** (#285/T6), the crash-recovery re-run, and the poison-guard all hold
in both modes, and the store finalizer stays the single disposition authority. Two caveats travel with
running at the scale pooled unlocks:

> **Caveat (a) — exactly-once degrades under load (not pooled-specific).** MessageFoundry has **no
> inbound de-duplication.** Delivery is at-least-once and the `delivered_keys` ledger only suppresses a
> *re-delivery* of an already-ingested message — it cannot recognize a **fresh inbound**. So when
> throughput pushes ACK latency past an upstream partner's **resend timeout**, the partner resends,
> the engine ingests it as a new message, and the downstream receiver sees it **twice**. This is the
> same in `per_lane`; it simply *surfaces at the scale pooled is designed to reach*. The
> **"outbound receivers must be idempotent"** contract (an idempotency key, a natural upsert, or a
> de-dup — see the per-connector notes above) is what contains it. Keep partner resend timeouts
> generous and receivers idempotent.

> **Caveat (b) — failover-under-load is covered; residual recovery *time* is host-dependent.** The
> active-passive **failover** paths hold under `pooled`: `test_load_failover_{postgres,sqlserver}` —
> a real two-node cluster, SIGKILL-the-leader under sustained MLLP — gate **no acknowledged loss**,
> **strict per-lane FIFO** (#285), a single live leader, and a **bounded duplicate rate**, all green
> under the pooled default. (The wake-less recovered-backlog drain that once stranded acknowledged
> messages on promotion is fixed by the dispatcher's greedy sweep/seed re-arm; the T17 infra-fault
> spin is bounded by **ADR 0070** / #766.) What stays **reported, not gated** is the *functional
> recovery time* after a kill — a killed process's port rebind is near-instant on Linux but can lag on
> Windows — so size `[cluster]`/`[store]` lease + timeout settings against your host, and keep partner
> resend timeouts generous (caveat (a)).

## Resource management & limits (ASVS 13.1.2 / 13.1.3 / 13.2.6)

How the engine bounds connections, threads, and retries **per external service**, what happens **when
a limit is reached**, and how each service's resources are released — the resource-management
contract a reviewer needs. The two tables below cover **every** hop in the communications inventory
([ASVS-L2-PHASE0-CHANGES.md](ASVS-L2-PHASE0-CHANGES.md) §5): Table A is the
13.1.2/13.2.6 concurrency axis, Table B the 13.1.3 resource-strategy axis. They carry the **same row
set**, and `tests/test_communications_inventory.py` fails the build if they diverge or if a stated
default drifts from the constant in the code.

Facts that are easy to get wrong, stated plainly first:

- **The MLLP, raw-TCP, X12 and HTTP listeners have no accept-rate throttle.** The bound is
  `max_connections` (default 256)
  and nothing paces the accept rate. Past the cap the client's TCP connection **is** accepted by the
  asyncio server and then **immediately refused and closed at the application layer**; the
  active-client counter is never incremented for the refused peer. The peer therefore observes a
  successful connect followed by an immediate close — not a refused connect and not a backlog wait.
  A peer failing `source_ip_allowlist` is refused the same way. **The telemetry is not uniform:** the
  **MLLP, raw-TCP, X12 and HTTP** listeners emit an ADR 0021 `at_capacity` (and
  `peer_not_allowlisted`) connection_event; the **DICOM** listener refuses identically but emits **no
  connection event at all** — `transports/dicom.py` contains zero `_emit_event` call sites. X12 sat
  in that silent set until BACKLOG #1665 and no longer does: it now records the same seven kinds as
  its raw-TCP twin, so an X12 refusal at either gate is no longer evidence-free.
  The slow-loris guard is the **separate**
  `receive_timeout` (default 60 s), not `max_connections`; the HTTP listener additionally answers a
  synchronous `408` when a request read exceeds it.
- **`receive_timeout` bounds SILENCE, not a message, and on the MLLP, raw-TCP and X12 listeners a
  second bound covers the difference.** It is applied **per read**, so it resets on every byte
  received: a peer trickling one byte at a time is never idle by it. Those three listeners therefore
  also run `max_frame_seconds` (default 60 s), which bounds how long one frame may take to
  **complete** and closes the connection with a `frame_deadline` reason when it is exceeded (BACKLOG
  #1725 for MLLP, vault BACKLOG #2606 for raw TCP and X12). **Bytes outside a frame count too**, so
  a peer cannot hold a slot with bytes that never make a frame. The clock works per read:
  * A read that completes no frame starts the clock, if it is not already running.
  * A read that completes a frame stops it, or restarts it when that read also opens the next frame.
  * On MLLP and raw TCP, up to two bytes directly after a frame's end byte belong to that frame when
    each is CR, LF or the codec's `trailer`. They start nothing, however late they arrive.
  * **In a read that completes no frame, any other byte starts the clock, keep-alives included.**
    Noise in the same read as a completed frame starts nothing. A sender that holds
    a quiet socket open with them is closed at `max_frame_seconds`, even where `receive_timeout` is
    longer or off.
  * On X12 the frame is the interchange, from its `ISA` to its `IEA`. X12 has no line-end allowance
    yet, so a newline after the `IEA` that arrives in a read of its own starts the clock. That is a
    known gap, not the intended rule.
  * Time the engine withholds, for pacing or an intake pause, is not counted.

  Vault BACKLOG #2847 moved MLLP onto this rule. Its clock used to start only at a start byte.
  The two bounds run **together** and
  neither replaces the other — a peer that opens a socket and sends nothing never opens a frame, so
  only the idle bound reaches it. **Raise `max_frame_seconds` whenever you raise `max_frame_bytes` or
  `max_interchange_bytes`.** The **HTTP** listener spends that same
  `receive_timeout` **differently**: one budget covers the **whole** request — request line, headers,
  authentication and body — and a synchronous `408` answers a request that outruns it, so an HTTP
  request is bounded end to end without a second key. The **DICOM** SCP is a different shape
  again, with `timeout_seconds` on its pynetdicom timers rather than `receive_timeout`; see its own
  paragraph below.
- **`max_connections` counts sockets, not hosts, so the MLLP, raw-TCP and X12 listeners carry a
  per-peer term as well.** `max_connections_per_host` (default 32, an eighth of the socket cap) bounds the connections
  one peer address may hold at once, refused the same pre-ingress way as the socket cap and carrying
  a `max_connections_per_host` reason on its `at_capacity` event (BACKLOG #1725). Without it one
  unauthenticated peer could take every slot a listener has, since `source_ip_allowlist` ships off.
  **It keys on the source address, so it raises the floor on a single-address peer and does not
  bound a distributed one** — eight addresses restore the full 256. **Two deployment notes:** behind
  a source-NAT proxy every partner shares one address and this becomes the effective capacity, so
  set it to `None`/`0` there; and the refusal is logged once per host per episode rather than per
  attempt, so a peer hammering a filled budget cannot fill the log volume. The raw-TCP and X12
  listeners took the same key and default from vault BACKLOG #2606. **The HTTP listener has the key
  but it ships OFF**: it answers one request per connection, so behind a reverse proxy any per-host
  cap would be its whole capacity. Set it there only where the listener sees real client addresses.
  The DICOM SCP has no per-host connection term.
- **An allowlist refusal is logged at most once per address per minute.** On the MLLP, raw-TCP, X12
  and HTTP listeners, a peer outside `source_ip_allowlist` earns one WARNING per 60 s however often
  it reconnects, and the listener writes at most 20 such lines per 60 s across every address. Each
  line carries the listener's running count of refusals, logged or not. The `peer_not_allowlisted`
  connection event still records every refusal. The DICOM SCP uses the same throttle (vault BACKLOG
  #2606).
- **The DICOM C-STORE SCP is a different shape** and none of the paragraph above describes it. It has
  no `max_connections` and no engine-side active-client counter: its bound is `max_associations`
  (**default 10**, `transports/dicom.py:165`), enforced inside pynetdicom, which **rejects the
  association** rather than accepting it and closing at the application layer. Its idle/response bound
  is `timeout_seconds` (**30 s**) applied to the ACSE/DIMSE/network timers, not `receive_timeout`. A
  peer failing the per-connection `source_ip_allowlist` (an `inbound(...)` keyword — **not** a
  `[inbound]` service-TOML key, which is accepted and discarded; see the [SCP peer-control
  note](#dicom--dicom-inbound-c-store-scp--outbound-c-store-scuc-echo-and-dicomweb-stow-rs-adr-0025))
  is refused with a DIMSE **not-authorized status on an
  already-established association** (`dicom.py:254-262`) and logged. `transports/dicom.py` has zero
  `_emit_event` call sites, so no ADR 0021 `connection_event` is written for either refusal.
- **The DATABASE connector's pool acquire is bounded.** `acquire_timeout` (default 30 s, per
  connection on `Database(...)`, `DatabasePoll(...)` and `DatabaseLookup(...)`) wraps the driver's
  `pool.acquire()`; on expiry the operation fails as a **transient** delivery error and enters the
  `RetryPolicy` path. It never waits indefinitely.
- **The DATABASE connector has no per-statement timeout.** It exposes `connect_timeout` (default
  15 s, a **login** timeout only, passed to the driver as pyodbc's `timeout=`, SQL Server preset
  only), `pool_max` and
  `acquire_timeout`, and there is **no** `timeout_seconds` on this connector. A long-running
  statement is therefore unbounded; keep lookup/write statements indexed and narrow. (The *store's*
  own SQL Server / Postgres connections do apply `[store].command_timeout`, default 30 s.)
- **The store's message-pipeline pool acquire is bounded on both server backends.**
  `[store].acquire_timeout` (default **30 s**, must be > 0) caps one borrow from the SQL Server or
  Postgres store pool, and the throwaway pool a `DatabaseRef` reference sync opens takes its own
  `acquire_timeout` (same default). It is a *distinct* bound from the two either backend already had:
  `[store].connect_timeout` (default 15 s) bounds the **login** and `[store].command_timeout`
  (default 30 s) the **statement** — neither bounds the wait for a free pooled connection. The
  `timeout=` the Postgres backend hands `asyncpg.create_pool` is a pool-construction parameter
  carrying `[store].connect_timeout`; it is **not** a bound on waiting for a free connection either.
  `[store].pool_size` (default 40) and the warm-pool pre-open (`[store].warm_pool`, timeout
  `[store].warm_pool_timeout` default 15 s) size the pool; they are not a deadline.

  **What it covers, stated as a scope rather than a completeness claim.** On **SQL Server**
  `_acquire` is the sole borrow site, so it bounds every store call. On **Postgres** it bounds at
  least the message-pipeline borrows — the transactional claim/handoff sites and the internal
  `_fetchall` / `_fetchone` / `_execute` helpers, which were routed through the same chokepoint for
  that reason. Take the scope as written; the two backends reach it differently and this setting is
  not a statement about every code path that can touch a pool.

  **Two Postgres session writes wait without the bound, on purpose (BACKLOG #2283).**
  `rotate_session` and `revoke_user_sessions` mostly run after their caller's own change has
  committed: a password reset, a disable, a role change, a completed second factor. Nothing retries
  them, so they wait for a free connection rather than fail after that change. Callers with no
  earlier write, such as "sign out everywhere else", wait the same way. On SQL Server both stay
  bounded, because `_acquire` is that backend's sole borrow site. There, at the limit, the request
  fails after the change has committed. A revoke then leaves the account's other sessions
  unrevoked. A rotation leaves the session on its old token, now carrying the factor it just proved.

  **Behaviour at the store-pool acquire limit.** The borrow raises `StoreAcquireTimeout` with a
  numeric, PHI-free message naming the backend and the knob. It is an ordinary `Exception`, so it
  reaches the stage worker's existing handling and is treated exactly like any other transient store
  failure — the row stays claimable, the stage handoff re-runs idempotently, and nothing is
  accepted-and-dropped. It is deliberately **not** a `TimeoutError` (since Python 3.11 an `OSError`
  subclass, which connector-error handling reads as a network fault). A borrow abandoned at the limit
  never strands a pooled connection: if the pool hands one over after the borrower gave up it is
  released back, so a wedged pool does not shrink by a slot per retry. For a `DatabaseRef` sync the
  set fails like any other source failure — the last-good snapshot keeps serving reads and the
  AlertSink fires; because the runner walks the declared sets sequentially, this bound is also what
  stops one unresponsive reference server from stalling every *other* set's refresh.

  **Sizing.** 30 s sits far above a healthy wait (cold ODBC acquires measured 340–958 ms on the
  dogfood box), so reaching it means the pool is wedged or the database is unresponsive, not that the
  pool is busy. Read p95/p99 from the acquire-wait histogram in `pool_status()` before lowering it.
  There is no "0 disables" value — an unbounded pool wait is what the setting exists to remove.

  **SQLite is out of scope for this setting and does not need it**: its four-connection read pool
  (`_READ_POOL_SIZE`) is borrowed with `await pool.get()`, which carries no deadline, but it is
  in-process with no network leg — a borrow waits only for a sibling read to finish, itself bounded by
  `PRAGMA busy_timeout` (5000 ms) and the query.

*Outbound* concurrency is bounded either way: in `per_lane` mode by **exactly one delivery worker per
outbound connection**, and in the default `pooled` mode by the per-stage processing-slot budget
`[pipeline].pooled_max_processing_lanes` (default 256) that caps how many outbound lanes deliver
concurrently — so concurrent borrows from any connection/driver pool stay bounded and a pool's
`pool_max` is not exhausted under normal flow. **Maximum parallel connections to a backend HTTP
service is an *indirect* bound via that lane budget: there is no per-connection HTTP
connection-count knob** (the stdlib opener exposes none) — the same framing 13.2.6 is assessed on.

**Timeouts are per-connector, not universal.** Only the MLLP/TCP/X12/DICOM families expose both a
`connect_timeout` and a `timeout_seconds`; the REST/SOAP/FHIR/DICOMweb HTTP family exposes
`timeout_seconds` only (a single per-request wall clock — there is no separate connect timeout);
REMOTEFILE (SFTP/FTP/FTPS) exposes **no** timeout argument, and its bounds are hard-coded module values in `transports/remotefile.py`, not operator-configurable. All three protocols start from a 30 s value. On FTP and FTPS it is a whole-socket timeout, on the control and data connections alike. On SFTP it covers the TCP connect, the SSH banner exchange and authentication. A separate `SFTP_CHANNEL_READ_TIMEOUT_SECONDS` (120 s) then bounds opening the SFTP session (BACKLOG #1936) and each read from the established SFTP channel (BACKLOG #1195). Both refusals are transient. The read bound is per read, not per transfer, so a slow transfer that keeps making progress never trips it. The session-open bound releases the worker thread once it passes. In one narrow race inside paramiko it can leave a separate helper thread parked instead; the `_open_sftp_within` docstring says what paramiko does there. An upload that stops making progress is closed after `SFTP_WRITE_STALL_SECONDS` (120 s, per step, BACKLOG #2082), and that refusal is transient too; the `_WriteWatchdog` docstring says what paramiko does there. **The SFTP bounds are not complete.** paramiko retries a timed-out socket write without limit, and only the upload is watched for it, so at least the small requests every other operation sends could still wait on a server that keeps its TCP window shut;
DATABASE exposes `connect_timeout` + `acquire_timeout` and no statement timeout; local FILE exposes
none (filesystem I/O is unbounded by design). The MLLP/TCP/X12/HTTP listeners expose
`receive_timeout`; the DICOM SCP instead applies `timeout_seconds` to its three pynetdicom timers. For
**synchronous** request→response feeds (REST/SOAP, X12 270/271) set a **short** `timeout_seconds`.

**Retry strategy (13.1.3).** Delivery failures retry per the connection's `RetryPolicy`. **The
default `retry_max_attempts` is 100 — finite** (with backoff: `retry_backoff_seconds` 5 s,
multiplier 2.0, capped at 300 s), which is a 28,215 s (7 h 50 m 15 s) window before a row gives up.
Two properties make that safe as a default: attempts are counted **per row**, so an outage burns the
cap on roughly the lane heads rather than the whole backlog; and an exhausted row **dead-letters into
the replayable DLQ** rather than being discarded. For synchronous HTTP (REST/SOAP) **keep the finite
`retry_max_attempts` and set a short `timeout_seconds`** to prevent cascading delays / resource
exhaustion; failures classified *permanent* (e.g. an MLLP `AR` reject) go straight to the
dead-letter path rather than retrying. `retry_max_attempts=None` remains expressible, and still means
retry forever for a partner that must never be advanced past. **Three surfaces express it, and each
one spells it differently — the word `"forever"` is the same, the KEY and the FILE are not** (BACKLOG
#1217):

| Surface | Where | What you write |
|---|---|---|
| code-first Python | an `outbound(...)` call | `retry=RetryPolicy(max_attempts=None)` |
| global default | `messagefoundry.toml`, `[delivery]` (or `MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS=forever`) | `retry_max_attempts = "forever"` |
| per-outbound override | `connections.toml`, `[outbound.retry]` | `max_attempts = "forever"` |

`"forever"` is case-insensitive and whitespace-tolerant on both text surfaces; every other string
(`""`, `"none"`, `"null"`, `"sometimes"`) is still a load error. **`connections.toml` accepts neither
of the other two spellings**: it takes only `[[inbound]]`/`[[outbound]]` tables, so a `[delivery]`
table there fails with `unknown top-level key(s) delivery`, and `retry_max_attempts` is not an
`[[outbound]]` key, so a flat one fails `_reject_unknown`. See
[CONFIGURATION.md](CONFIGURATION.md)'s `[delivery]` catalog for the global. Under strict FIFO a
retry-forever head blocks its lane until it succeeds or an operator purges it, so it is a written
decision, not a default. **Every infrastructure hop in Table B that performs a
synchronous request/response is single-shot** — AD, OIDC, SMART, generic OAuth2, the AI broker, both
Vault clients, both SMTP sinks, the webhook sink, syslog and SNTP: one attempt, no retry loop, which
is what the requirement's "disable or strictly limit retries" clause asks for. The **store backends
are the deliberate exception**: SQLite waits out a lock via `PRAGMA busy_timeout` (5000 ms) and a
failed stage handoff re-runs idempotently on the next claim. That is durability, not a
synchronous-request retry.

**Resource release & recovery.** Sockets, cursors, and pool connections are released in `try/finally`
(e.g. `transports/mllp.py`, `transports/database.py`, the `ftplib`/`paramiko` contexts in
`transports/remotefile.py`); long-running workers are **cooperatively cancelled** on stop. The staged
queue is at-least-once, so an in-flight row left by a crash is recovered on startup
(`reset_stale_inflight`), never leaked. The alert dispatcher bounds its own memory with a
**1000-item** queue that **drops with a warning** rather than growing (and the per-user
security-event notifier has a second one of its own).

**Thread inventory — the resource class the requirement names by example.** The engine runs off-loop
work on at least **four** distinct thread pools, plus `aiosqlite`'s per-connection worker thread on the SQLite
store, and only one of the pools carries a knob.

1. **The event loop's default `ThreadPoolExecutor`**, bound to CPython's `min(32, os.cpu_count() + 4)`
   with **no setting for it** (the engine never calls `loop.set_default_executor` outside a bench-only,
   env-gated shim, `pipeline/connscale_shim.py`). It carries **five** classes of work:
   - **Router and Handler execution** — `route_only` and `transform_one` go through `asyncio.to_thread`
     once per message per stage (SEC-013/CWE-1322: arbitrary user Python must never run on the loop).
     These carry **no timeout at all**: a hung Handler holds a default-pool worker until the process is
     restarted. That is the acknowledged residual on this pool, and the reason the pool is sized well
     above the per-stage lane concurrency.
   - **Bounded infrastructure hops** — `db_lookup`, `fhir_lookup`, the AI broker POST, every SMTP send,
     every LDAP bind, the DICOM association work. Each carries a finite timeout (Table B), so *these*
     workers are released by their timeout rather than by any pool cap.
   - **File I/O** — local FILE, which is unbounded by design, and SFTP/FTP/FTPS, whose bounds are
     hard-coded, differ by protocol and leave at least one SFTP step unbounded. The "Timeouts are
     per-connector, not universal" paragraph above says what each covers; Table B has the per-row detail.
   - **Inbound strict validation** — the listener runs `hl7apy` strict validate off-loop via
     `asyncio.to_thread` (`pipeline/wiring_runner.py:3259`, `:3543`), bounded by the per-inbound
     `validation.strict_timeout_s` (engine default `STRICT_VALIDATE_TIMEOUT_SECONDS` = **5 s**, in
     `pipeline/ingress_guards.py`, which `wiring_runner` re-exports as
     `_STRICT_VALIDATE_TIMEOUT_SECONDS`). An operator resend into a strict inbound (BACKLOG #1911)
     validates on this pool the same way, under the same timeout. The timeout frees the *listener* but cannot kill the worker — an
     orphaned validate holds its thread until it returns, bounded in turn by the 16 MiB / segment
     caps enforced before it.
   - **The store's own SQL Server I/O** — `aioodbc.create_pool()` is built with **no** `executor=`
     (`store/sqlserver.py:1953`), so every store statement is dispatched onto **this** pool via
     `loop.run_in_executor(None, …)`; on a SQL Server deployment that makes the store the pool's
     dominant consumer. Its release bound is `[store].command_timeout` (**30 s**), set as a pyodbc
     connection attribute per acquire. Postgres (`asyncpg`) runs its statements on the loop; it uses
     this pool only for the server's hostname lookup when a new connection opens, and builds that
     connection's TLS context on the store's own executor (item 4). SQLite
     instead runs each `aiosqlite` connection on its **own dedicated thread**, outside every pool
     listed here.
2. **Two per-stage fusing executors**, each `[pipeline].pooled_fusing_workers` wide (**default 8**),
   built only under `[pipeline].fuse_thread_hops` (**default `false`**, SQL Server + `pooled` claim mode
   only, ADR 0071 B5). Under fusion the fused stage's route/transform body runs on *these* pools, not
   the default one, so the fused-stage concurrency is that value.
3. **One dedicated single-worker `ThreadPoolExecutor` per alternate-credential File endpoint**
   (`transports/wincred.py`, `mefor-filecred`). Impersonation must never leak onto a shared pool, so
   this work is deliberately **not** on the default executor — and it carries **no engine-owned
   timeout**: a wedged share pins that endpoint's one thread indefinitely.
   It cannot starve the shared pool, which is the mitigating half, and that now holds on the
   **release** path too, which is where it did not: `close()` shuts the worker down without joining
   it and waits out an in-flight call on the event loop for `_CLOSE_DRAIN_TIMEOUT_S` (**5** s), then
   logs a WARNING and returns (BACKLOG #1195). A blocking join is the natural spelling, and it would
   have run on the shared default executor, inheriting the wedged share's unbounded hold.
4. **One two-worker `ThreadPoolExecutor` for the Postgres store's TLS contexts**
   (`store/postgres.py`, `mefor-store-tls`, BACKLOG #300). The pool builds a fresh verifying context
   for each new store connection here, reading the OS trust store, `[store].ssl_root_cert` and
   `[store].ssl_crl_file`. Each of those builds is bounded by `[store].connect_timeout`, counted from
   when it is queued. A path that hangs on read strands at most these two threads, and never a
   thread from the shared pool. The one build at store open is not on this executor: it runs on the
   event loop, unbounded, as it did before.

At saturation further `to_thread` calls **queue on the executor rather than failing**. So the release
mechanism differs per class: a timeout for the bounded hops, the 5 s strict-validate backstop and
`[store].command_timeout` for the store hop, cooperative cancellation on stop for the workers, and —
for the Router/Handler and the SMB worker — nothing but a restart.

### Per-tick poll ceilings

The three **poll** sources — `File(...)`, `Sftp(...)`/`Ftp(...)` and `DatabasePoll(...)` — each take at
most **500 items per tick** (`poll_max_files`, `poll_max_rows`). The ceiling **ships on**, and `None` or `0`
(in any spelling, including the text `"0"`) turns it off. At least a negative value, a fraction below one and
text that is not a number are refused when the connection is built, before it starts. A larger fraction
is cut down to a whole number.

**It is a deferral, not a drop.** A file the scan does not reach is still in the drop directory; a row
the poll does not fetch is still in the table, unmarked. The next tick takes it. On `DatabasePoll(...)`
a later tick reaches the rest only if `mark_statement` takes each handled row out of what
`poll_statement` selects; without that, a poll can select the same rows every time. Even with it, at
least one case would defeat the deferral: 64 or more rows that cannot become a body, sorting ahead of
the rest, end every poll at the skip cap described below, so the rows behind them would never be
reached. Nothing is quarantined,
errored, or accepted-and-dropped, so the count-and-log invariant is untouched: an item that was never
read was never received, and there is no disposition to record.

**Why these three default on when the MLLP message pacer ships off.** On a listen socket a rate bound
has to refuse or stall a sender mid-conversation, and the right number comes from a real feed profile
the project does not have — so that one stays opt-in ([`transports/mllp.py`](../messagefoundry/transports/mllp.py),
ruled 2026-08-11). A poll source has no sender to refuse. The two cases differ in what a bound does to
the partner, not in appetite for risk.

**Why 500.** At the shipped poll intervals it allows 500 items/s on `File(...)` (`poll_seconds` 1.0) and
100/s on the remote and database sources (`poll_seconds` 5.0). The published measurements are ~450 msg/s
at intake and ~97 msg/s sustained end-to-end from one engine process
([`docs/THROUGHPUT.md`](THROUGHPUT.md), [`docs/SYSTEM-REQUIREMENTS.md`](SYSTEM-REQUIREMENTS.md)), so the
ceiling sits at or above every rate this engine has been measured achieving. It cannot be the thing that
throttles a feed the engine could otherwise have kept up with, and ingesting faster than the engine
drains would only move the backlog from the source system into this engine's store.

**When to raise it.** The drain rate is `poll_max_files ÷ poll_seconds`, so a long interval shrinks it: a
30,000-file nightly drop on a 60-second poll needs 60 ticks at the default. Raise the ceiling, shorten
the interval, or set the knob to `0` for that connection.

**What it bounds, and what it does not.** It bounds the ingest — the read, the pre-ingest scan, the
pipeline hand-off and the durable commit. The `File(...)` source still lists and sorts the whole
directory each scan, because taking the first N in name or mtime order requires seeing all of them. On
the database source the ceiling is charged at the **fetch**, so the rest of the result set is never
pulled out of the driver. One poll asks the driver for at most `poll_max_rows` plus the rows it had to
step over, capped at 64 of those.

**Files left for a retry do not spend the budget.** A locked or vanished file, a malfunctioning
pre-ingest scan hook, a handler failure, and a listing entry refused as an unsafe name all leave the
item where it is. Charging those would let one permanently stuck item consume the whole ceiling on every
tick and starve the healthy items behind it. Only an item the tick finished with — handed off, or
quarantined to the error directory — charges. **One gap in that rule:** a quarantine whose move to
the error directory fails still charges, although the file stays where it was. A file that can never
be quarantined would therefore spend the budget on every tick, which is the starvation this rule exists
to prevent.

**A database row that cannot become a body does not spend it either, and the two sources reach that
by different routes.** A file source charges on **completion**, so it simply does not count an item it
left in place. The database ceiling is charged at the **fetch**, for the memory reason above, so the
row has to be decoded under the open cursor and replaced from the same cursor — the shortfall is
re-fetched, never the whole result set. Do not read this as parity of mechanism; what the two share is
that a budget can only be charged by something that makes progress. Two bounds keep the replacement
from becoming a log flood: a `body_column` that names no column `poll_statement` selects is **static**
and is reported once per poll before any row is read, and everything else is per-row and capped at 64
skips, after which the poll stops fetching and defers the rest. Each skipped row is logged and emits a
`row_undecodable` connection event. It is **not marked**: `mark_statement` is your `UPDATE`, and
marking a row that never became a message would record data DONE that was never ingested. Nor is there
a store disposition to record — a row the source could not read was never a received message, the same
reading this page already applies to a file the scan never opened.

### Table A — concurrency limits & behaviour at the limit (ASVS 13.1.2 / 13.2.6)

| Service/hop | Concurrency bound (setting + default) | Behaviour when the limit is reached | Fallback / recovery |
|---|---|---|---|
| MLLP listener (inbound) | `max_connections` default 256 concurrent clients, plus `max_connections_per_host` default 32 from any one peer address | connection accepted, then immediately refused and closed with an `at_capacity` connection_event; the counter is not incremented. The per-host refusal carries a `max_connections_per_host` reason, which is the only thing distinguishing the two budgets | the peer reconnects; a slot frees as soon as any client finishes or trips `receive_timeout` or `max_frame_seconds`, except that a per-host refusal clears only when one of that same peer's own connections ends |
| MLLP destination | 1 in-flight delivery per outbound connection (`per_lane`), else the `pooled_max_processing_lanes` budget | a lane waits for a slot; the socket itself is per-delivery unless `persistent=true` | transient failure re-queues into the `RetryPolicy` path; a stale persistent connection is not reused past `idle_timeout_seconds` |
| Raw TCP listener (inbound) | `max_connections` default 256 concurrent clients, plus `max_connections_per_host` default 32 from any one peer address (vault BACKLOG #2606) | accepted then immediately refused and closed with an `at_capacity` connection_event | as MLLP |
| X12 listener (inbound) | `max_connections` default 256 concurrent clients, plus `max_connections_per_host` default 32 from any one peer address (vault BACKLOG #2606) | connection accepted, then immediately refused and closed at the application layer; the active-client counter is not incremented. An ADR 0021 `at_capacity` connection_event is emitted, as on the raw-TCP listener (BACKLOG #1665); an allow-list refusal emits `peer_not_allowlisted` and a WARNING log, throttled to one per address per 60 s | as MLLP |
| Raw TCP / X12 destination | as MLLP destination — one delivery per outbound lane | a lane waits for a processing slot; a fresh connection is dialled per delivery | transient failure re-queues into the retry path |
| HTTP web-service listener (inbound) | `max_connections` default 256; `max_connections_per_host` available but **off** by default (vault BACKLOG #2606); `max_header_bytes` 64 KiB and `max_body_bytes` 16 MiB bound one request | at capacity the connection is accepted then refused and closed (`at_capacity`); an over-declared `Content-Length` is refused before buffering; a slow read gets a synchronous `408` | the partner retries; slots free on completion or `receive_timeout` |
| File endpoint — local filesystem | one poll worker per inbound connection; one delivery lane per outbound | no connection limit exists — the bounds are the poll interval `poll_seconds` (default 1.0), `max_file_bytes` (16 MiB) and `poll_max_files` (500 files per scan, [deferring the rest to the next scan](#per-tick-poll-ceilings)) | an oversize or unreadable file is skipped/errored and left for the operator; the next poll continues |
| File endpoint — UNC / SMB share | as local File, plus one dedicated impersonation worker thread per endpoint | the OS redirector queues; no engine-side cap | an SMB failure surfaces as a transient delivery/poll error and re-queues |
| SFTP (remote-file) | one session per poll or per delivery — no session pool | sessions are serialized by the lane budget; there is no server-side connection cap the engine enforces; one poll takes at most `poll_max_files` (500) files and [defers the rest](#per-tick-poll-ceilings) | a refused/limited server surfaces as a transient error and re-queues per `RetryPolicy` |
| FTP / FTPS (remote-file) | one session per poll or per delivery — no session pool | as SFTP | as SFTP |
| Reference-set sync (`FileRef`) | one read per set per `refresh_seconds` pass (default 3600); no concurrency knob — the OS / SMB redirector queues on a UNC path | a slow or unreachable path stretches that set's sync; the sync is isolated per reference set | the previous encrypted snapshot keeps serving reads |
| REST destination | no per-connection HTTP connection cap exists; the indirect bound is `[pipeline].pooled_max_processing_lanes` (default 256) | requests queue behind the lane budget; the backend's own 429/503 is classified transient | transient → `RetryPolicy` with backoff; permanent → dead-letter |
| SOAP destination | as REST — indirect via the lane budget | as REST | as REST |
| FHIR destination + `fhir_lookup` | as REST; `fhir_lookup` additionally runs off the event loop on the thread executor | as REST; a lookup that cannot run raises into the Handler | transient → retry; a `fhir_lookup` failure fails the message, never silently degrades |
| DICOMweb STOW-RS destination | as REST — indirect via the lane budget | as REST | as REST |
| DICOM C-STORE SCP (inbound) | `max_associations` default 10; `max_pdu_size` 16384; `max_object_bytes` 128 MiB, capped at the engine's 16 MiB binary ingress ceiling | over the association cap pynetdicom rejects the association; `max_pdu_size` bounds a fragment rather than an object, so `max_object_bytes` is charged against the raw received Data Set **before** it is decoded — and so before the durable commit | the modality re-sends; nothing is half-committed |
| DICOM C-STORE SCU / C-ECHO | one association per delivery, bounded by the lane budget | the association request fails on `connect_timeout` | out-of-resources status → retry; a hard refusal → dead-letter |
| EMAIL (SMTP) destination | one SMTP connection per send, bounded by the lane budget | the relay's own limit surfaces as an SMTP error | transient → retry; permanent → dead-letter |
| DIRECT (S/MIME over SMTP) | one SMTP connection per send, bounded by the lane budget | as EMAIL | as EMAIL |
| DATABASE destination / poll source / `db_lookup` | `pool_max` default 5 connections per connection definition; the poll source additionally fetches at most `poll_max_rows` (500) rows per poll, [deferring the rest](#per-tick-poll-ceilings); a `db_lookup` call fetches at most `max_rows` (500) plus one, and [refuses a larger result](#a-lookup-that-selects-too-many-rows-fails-the-message) | a borrow that cannot be satisfied within `acquire_timeout` (default 30 s) fails **transiently** with a PHI-free "pool exhausted or DB unresponsive" error | the row re-queues into the `RetryPolicy` path; the pool self-heals as borrows return |
| Reference-set sync (`DatabaseRef`) | `pool_max` default 5, in a **throwaway pool built per sync** | a borrow that cannot be satisfied within `DatabaseRef(acquire_timeout=…)` (default 30 s) raises `StoreAcquireTimeout`, failing that set's sync | the sync task is isolated per reference set; the previous snapshot keeps serving reads and the AlertSink fires. The bound also keeps one wedged source from stalling the sequential pass over the other sets |
| Internal sources — Timer / Loopback / PassThrough | n/a — they open no socket and reach no external system | n/a | n/a |
| Engine API + `/ui` + `/ws/stats` (`[api].port`) | uvicorn's own defaults (no `limit_concurrency` / `timeout_keep_alive` is passed); per-actor 429 throttles bound abuse: login 10 per IP and 60 global per 60 s, PHI reads 120 per actor per 60 s, admin writes 12 per actor per 15 s | over a throttle the request gets `429` and an audit row; the connection stays usable | the caller backs off; the window rolls |
| Reverse proxy → engine segment (`[api].trusted_proxies`) | bounded by the proxy's own connection limits — the engine sets none on this hop | whatever the proxy does at its limit; the engine sees fewer connections | operator-owned (proxy config) |
| Store — SQLite (`[store].backend = sqlite`) | one writer connection plus a **bounded read pool of 4** read-only WAL connections (`store/store.py` `_READ_POOL_SIZE`; deliberately not a setting); no network | writes serialize behind the single writer lock; a read that finds all four borrowed **waits on the pool queue with no deadline** (`await pool.get()`), and lock contention inside SQLite waits out `PRAGMA busy_timeout` 5000 ms | the borrow is returned in `finally`; every pooled connection is closed on store close |
| Store — SQL Server (`[store].backend = sqlserver`) | `[store].pool_size` default 40, pre-warmed by `[store].warm_pool` | a borrow that cannot be satisfied within `[store].acquire_timeout` (default 30 s) raises `StoreAcquireTimeout` — an ordinary `Exception`, handled like any other transient store failure | the row stays claimable and the stage handoff re-runs idempotently; a connection handed over after the borrower gave up is released back, so the pool does not shrink per retry; `reset_stale_inflight` recovers in-flight rows on restart |
| Store — Postgres (`[store].backend = postgres`) | `[store].pool_size` default 40 (`asyncpg` `max_size`) | the same `[store].acquire_timeout` bounds at least the **message-pipeline** borrows (claim/handoff plus the internal `_fetchall`/`_fetchone`/`_execute` helpers) — see the coverage note above, which is a scope, not a completeness claim. The `timeout=` given to `asyncpg.create_pool` is a pool-construction parameter, not an acquire deadline | as SQL Server on the bounded paths |
| Active Directory — login binds (`[auth].ad_server`) | one `authenticate()` = **two sequential binds** plus 1–2 SUBTREE searches; concurrency is bounded by the API login rate limiter and the thread executor | at the login limiter the request gets `429`; a DC that is at capacity fails the bind | the login fails closed with `LdapError`; the user retries |
| Active Directory — session reconciler (`ad_session_recheck_seconds`) | one bind per signed-in directory user per pass, capped by `ad_session_recheck_max_users` (200); interval floored at 60 s | the remainder is deferred to later passes (least-recently-probed first), degrading to a longer effective interval rather than a bind storm | the mass-revoke breaker (`ad_session_revoke_max` 5 **and** `ad_session_revoke_max_fraction` 0.34) aborts a pass that would revoke too much |
| Kerberos / SPNEGO SSO (`kerberos_spn`) | no engine socket — one SPNEGO server step per login against the OS provider | the OS provider's own limits apply | a failed step is an audited login reject; a boot preflight degrades SSO legibly when no provider exists |
| OIDC IdP — token endpoint (`oidc_token_endpoint`) | one POST per login, bounded by the login rate limiter | the IdP's own limit surfaces as an HTTP error | the login fails closed; the user retries |
| OIDC IdP — JWKS fetch (`oidc_jwks_uri`) | one GET per cache miss, bounded by `oidc_jwks_ttl_seconds` (3600) and the amplification floor `oidc_jwks_min_refetch_seconds` (300) | a refetch inside the floor is not made; the cached key set is used | a fetch failure fails the verification closed |
| SMART token endpoint (`smart_token_url`) | one POST per token mint; the token is cached until expiry minus `smart_expiry_skew_seconds`, for at most one hour | the delivery fails and re-queues | re-minted on the next attempt or on a `401` via `invalidate()` |
| OAuth2 token endpoint (`oauth2_token_url`) | one POST per token mint, cached until expiry minus its skew, for at most one hour | the delivery fails and re-queues | re-minted on the next attempt or on a `401` |
| AI broker (`[ai].endpoint`) | one POST per assist request; bounded at the API route by the `ai:assist` RBAC gate, the fail-closed `[ai].allowed_endpoints` SSRF allow-list and the 60 s per-request timeout. **There is NO per-actor pacing on `POST /ai/chat`** — it depends on plain `require(Permission.AI_ASSIST)`, not `require_paced`/`require_step_up`, so a holder of `ai:assist` can loop assist POSTs unthrottled | the LLM's own 429/503 surfaces as an `AiBrokerError` → HTTP `502` to the caller | the assist call fails; nothing is queued or retried |
| DR backup destination (`[backup].destination`, ADR 0049) | **one writer** — leader-gated under `[cluster].enabled`, so exactly one node writes the shared destination; once per `schedule_at` pass plus any on-demand run. No engine-side cap: the OS/SMB redirector queues | a slow or full destination stretches the run; nothing is dropped and the next scheduled pass still fires | a failed or verify-failed run is logged + audited and is **never** counted as a good backup when pruning to `retention_keep` |
| Vault Transit — store DEK unwrap (`MEFOR_STORE_VAULT_ADDR`, `[store].key_provider = vault`, ADR 0019) | one HTTPS request per DEK unwrap (startup / rotation), not per message | a failure is fail-closed — the store does not open | operator fixes Vault and restarts |
| Vault Transit — bulk at-rest cipher (`MEFOR_STORE_TRANSIT_KEY`, `[store].cipher_provider = vault_transit`, ADR 0138) | **one synchronous HTTPS round trip per encrypted CELL** on every store write and read, plus one `generate_hmac` per audit row; issued **on the event loop** (`_enc`/`_dec` are sync, with no `to_thread`). No concurrency cap of its own — the effective bound is the stage/lane budget | Vault's own rate limit or a slow Transit **stalls the event loop across the whole engine**; a per-operation failure raises `CipherError` and the stage errors/dead-letters that row | the store stays open; the row is retried by the normal stage re-claim |
| Vault KV v2 (`MEFOR_SECRETS_VAULT_ADDR`) | one HTTPS request per secret resolution at config load / connector construction | fail-closed — the connection refuses to build | operator fixes Vault and reloads |
| Alerts — SMTP sink (`[alerts].email_smtp_host`) | one connection per send, serialized on **its own** background drain task behind **its own** bounded 1000-item queue | over-cap events are **dropped with a warning** rather than growing the queue | a send failure is swallowed + logged; the alert is not retried |
| Alerts — per-user security-event email (`[auth].notify_security_events`) | one connection per notification, serialized on a **second, independent** drain task with its **own** bounded 1000-item queue — so the SMTP relay sees up to **two** concurrent sessions from this engine, not one | at cap the event is **dropped with a warning**; the audited `GET /me/security-events` feed still records it when it is the user's own event, but not an administrator's change to their account (`auth/notifications.py` states the rule) | the send failure is swallowed + logged, never propagated onto the login or admin path; recovery is the pull feed, for the events it carries |
| Alerts — webhook sink (`[alerts].webhook_url`) | one POST per event on the same single drain task and the same bounded 1000-item queue | as the SMTP sink — over-cap events are dropped with a warning | best-effort; a failure is swallowed + logged, never retried |
| Syslog forwarder (`[logging].forward_host`) | a **single** socket, synchronous send, one record at a time | a stalled collector costs at most the socket timeout per record and the record is then **dropped** | an unreachable collector at startup is skipped with a warning and the service still starts |
| SNTP clock-sync probe (`[logging].ntp_peer`) | exactly **one** datagram per process start; never on the message path | a silent peer raises `socket.timeout` | skew beyond `time_sync_max_skew_seconds` warns loudly, or refuses to start under `time_sync_fail_closed` |
| Forward / egress web proxy (`[egress].proxy_url`) | no separate bound — the proxied request occupies the destination connector's own lane | the proxy's own limit surfaces as an HTTP error on the destination request | handled by the destination's retry policy |
| Loopback ECH sidecar (`ech_sidecar`) | one loopback request per destination request; no separate bound | the sidecar's own limit surfaces as an HTTP error | handled by the destination's retry policy; misconfiguration fails closed at build |

### Table B — per-service resource strategy (ASVS 13.1.3)

| Service/hop | Timeout setting + default | Release procedure | Failure handling | Retry posture |
|---|---|---|---|---|
| MLLP listener (inbound) | `receive_timeout` 60 s bounds an idle read (slow-loris) and `max_frame_seconds` 60 s bounds how long a frame may take to complete, on the clock the `receive_timeout` bullet under [Resource management & limits](#resource-management--limits-asvs-1312--1313--1326) describes, which is what reaches a peer that trickles bytes and is therefore never idle; the ACK **write** carries its own fixed 5 s bound, so a peer that takes the bytes and then stops reading cannot hold the connection either. That write bound is not operator-configurable — an ACK is engine-generated and receipt-sized, so there is no partner-sized body to size a budget against. With `tls = true`, a new connection has a fixed 10 s to finish its TLS handshake or the listener aborts it, and a connection the listener closes has a fixed 5 s for the TLS close exchange (on stop, the socket is closed as soon as its close notice is sent, except under uvloop, below). On the stdlib event loop (always on Windows), `source_ip_allowlist`, `max_connections` and `max_connections_per_host` apply **before** the handshake (BACKLOG #1606): the listener accepts plain TCP, refuses or admits the socket exactly as a plaintext listener does, and only then starts TLS. So a socket still in its handshake holds a real slot, and a peer outside the allowlist never gets a handshake. **Under uvloop the loop still runs the handshake, and all three apply only after it**, so there the handshake bound limits how long such a socket lives, not how many a peer can open. The engine runs on uvloop wherever it is installed, which the engine's own `uvloop` dependency does for CPython outside Windows. Neither TLS bound is operator-configurable: both are engine-fixed work with nothing partner-sized in them | the client handler's outer `finally` closes the writer, with a 5 s shutdown grace; stop also closes a socket still in its TLS handshake. Under uvloop, whose server offers no `close_clients()`, stop leaves such a socket to the 10 s bound and refuses it unread if it finishes the handshake after stop began, and stop can also wait up to the 5 s close-exchange bound for a peer that does not answer its close notice | a TLS handshake over its bound, or one that fails, is aborted with a DEBUG line only and no connection event, and gives its slot back; a decode/parse/validate failure NAKs synchronously and records `ERROR` before any ingress row; a frame over its deadline closes with a `frame_deadline` reason, having received nothing to drop; an ACK over its write bound drops the connection as a `peer_reset`; a fault inside the inbound handler, such as a store outage at the ingress commit, is answered with a fixed-text `AE` (`CE` in enhanced mode), then the connection closes and the event is `handler_error`; an inbound that sends no replies keeps the socket and sends nothing. That NAK has no message row, so the ACK capture stream does not hold it; the `handler_error` event is its record (BACKLOG #1619) | n/a — the sender retries |
| MLLP destination | `connect_timeout` 10 s, `timeout_seconds` 30 s (drain + ACK read) | the socket is closed per delivery, or reused and aged out via `idle_timeout_seconds` / `max_connection_age_seconds` when `persistent` | transient errors re-queue; a `NegativeAckError` (AR) dead-letters immediately | `RetryPolicy` — **default `retry_max_attempts` is 100, finite**; lower it, or set `None` to retry forever |
| Raw TCP listener (inbound) | `receive_timeout` 60 s bounds an idle read (slow-loris) and `max_frame_seconds` 60 s bounds one frame on the same clock as MLLP's (vault BACKLOG #2606 and #2847), which is what reaches a peer that trickles bytes; the reply **write** carries its own fixed 5 s bound, so a peer that takes the bytes and then stops reading cannot hold the connection either. Not operator-configurable — a reply is engine-generated and receipt-sized, so there is no partner-sized body to size a budget against | as MLLP — handler `finally` closes the socket with a shutdown grace | parse failures record `ERROR` on the ingress path; a reply over its write bound drops the connection as a `peer_reset` | n/a |
| X12 listener (inbound) | `receive_timeout` 60 s; `max_frame_seconds` 60 s bounds how long one interchange may take to complete, on the same clock as MLLP's (vault BACKLOG #2606); `max_interchange_bytes` bounds one ISA/IEA frame; the reply **write** carries its own fixed 5 s bound, so a peer that takes the bytes and then stops reading cannot hold the connection either. Not operator-configurable, for the same reason as the raw-TCP row | as MLLP — handler `finally` closes the socket with a shutdown grace | parse failures record `ERROR` on the ingress path; an allow-list refusal emits `peer_not_allowlisted` plus a WARNING log, and a capacity refusal emits `at_capacity`; a reply over its write bound drops the connection on a logged warning **and** the `peer_reset` its release path already carries. This listener emits the same seven kinds as the raw-TCP row above (BACKLOG #1665) | n/a |
| Raw TCP / X12 destination | `connect_timeout` 10 s, `timeout_seconds` 30 s | a fresh connection per delivery, closed in `finally` | transient vs permanent classification as MLLP | `RetryPolicy` |
| HTTP web-service listener (inbound) | `receive_timeout` 60 s bounds the **whole** request read; over budget returns `408` | handler `finally` closes the connection with a shutdown grace | an over-size body is refused before buffering | n/a |
| File endpoint — local filesystem | **none** — filesystem I/O is unbounded by design | file handles are context-managed; the source file is moved/deleted/left per `after_read` | an unreadable/oversize file is skipped or moved to `error_subdir` | `RetryPolicy` on the outbound write |
| File endpoint — UNC / SMB share | **none engine-owned** — bounded only by the OS SMB redirector | the impersonation token is reverted (`RevertToSelf`) and the worker thread is per-endpoint isolated | a share failure surfaces as a transient poll/delivery error | `RetryPolicy` |
| SFTP (remote-file) | 30 s on the TCP connect, the SSH banner exchange and authentication (`timeout`, `banner_timeout` and `auth_timeout` on `paramiko.SSHClient.connect`), plus 120 s on opening the SFTP session (BACKLOG #1936), on **each read** from the established SFTP channel, and on each step of an upload that stops making progress (BACKLOG #2082). All are hard-coded in `transports/remotefile.py`; `Sftp()` exposes no timeout argument, so none is operator-configurable. The bounds are **not complete**: the "Timeouts are per-connector, not universal" paragraph under [Resource management & limits](#resource-management--limits-asvs-1312--1313--1326) says what each covers and where a gap is left | the `paramiko` session is closed in `finally` per poll or delivery | **Delivery:** at connect, a rejected host key is **permanent**, and an authentication refusal is permanent and flagged as a credential fault. A banner, key-exchange or authentication timeout, a connection dropped before the key exchange completes, and an `OSError`/`EOFError` are transient (BACKLOG #1999; the bullet under [Remote file](#remote-file--sftp--ftp) says where the rules are stated). After connect, a missing remote path is permanent, and at least the session-open and read timeouts are transient. With `validate_directory` on, the pre-upload directory check re-raises any failure but a credential refusal as transient, these included. A write that stops making progress for 120 s (`SFTP_WRITE_STALL_SECONDS`, per step, BACKLOG #2082), an `EOFError` and a helper thread that cannot start are transient; a `paramiko.SFTPError` is permanent. **Source:** the poller does not act on that split; a failed connect, listing or retrieve is logged and tried again on the next poll | `RetryPolicy` |
| FTP / FTPS (remote-file) | 30 s **whole-socket** — the same hard-coded module fallback, handed to `ftplib.FTP_TLS(timeout=…)` / `ftplib.FTP(timeout=…)`, which sets it on the control **and** data connections. `Ftp()` exposes no timeout argument, so it is **not** operator-configurable | the `ftplib` session is closed in `finally` per poll or delivery | `ftplib.all_errors` maps to transient, with at least two exceptions: a 5xx reply, and a 4xx at the login that names the credential. While the session opens, both are classed as the bullet under [Remote file](#remote-file--sftp--ftp) states (BACKLOG #2083). After it opens, a 5xx is permanent | `RetryPolicy` |
| Reference-set sync (`FileRef`) | **none engine-owned** — filesystem / SMB-redirector I/O, the same posture as the File connector | the file handle is context-managed and closed per pass | a load error is logged and the previous encrypted snapshot is retained | one attempt per `refresh_seconds` (default 3600) — **no inner retry** |
| REST destination | `timeout_seconds` 30 s — the **only** timeout (no separate connect timeout on the HTTP family) | the `urllib` response is context-managed and closed per request | HTTP status is classified transient vs permanent; redirects are never followed | `RetryPolicy`; the finite `retry_max_attempts` default is what a synchronous feed needs — **keep it and set a short `timeout_seconds`** |
| SOAP destination | `timeout_seconds` 30 s | as REST | as REST | as REST |
| FHIR destination + `fhir_lookup` | `timeout_seconds` 30 s on both (the lookup carries its own per-connection value), plus the same 30 s Handler-side result bridge (`pipeline/wiring_runner.py::_LOOKUP_RESULT_TIMEOUT_SECONDS`) that releases the transform worker without cancelling the in-flight request | as REST; the lookup runs on the thread executor and returns the connection immediately | a lookup failure raises into the Handler and fails the message — never a silent empty result | destination: `RetryPolicy`. `fhir_lookup`: **single-shot, no retry** |
| DICOMweb STOW-RS destination | `timeout_seconds` 30 s | as REST | STOW-RS status classified transient vs permanent | `RetryPolicy` |
| DICOM C-STORE SCP (inbound) | `timeout_seconds` 30 s applied to **all three** pynetdicom timers (ACSE, DIMSE, network) and to the off-loop commit future | the association is released by pynetdicom; the AE is shut down cooperatively on stop | an over-cap object fails the DIMSE operation before the durable commit | n/a — the modality re-sends |
| DICOM C-STORE SCU / C-ECHO | `timeout_seconds` 30 s on the three AE timers, `connect_timeout` 10 s on the association request | the association is released after each C-STORE, off the event loop | out-of-resources → transient; hard refusal → permanent | `RetryPolicy` |
| EMAIL (SMTP) destination | `timeout_seconds` 30 s passed to the `smtplib` constructor (covers connect and each command) | the SMTP session is closed per send | SMTP errors classified transient vs permanent | `RetryPolicy` |
| DIRECT (S/MIME over SMTP) | `timeout_seconds` 30 s on the `smtplib` constructor | as EMAIL; key/cert material is loaded once at construction | as EMAIL | `RetryPolicy` |
| DATABASE destination / poll source / `db_lookup` | `connect_timeout` 15 s (**login** timeout only, SQL Server preset) and `acquire_timeout` 30 s on the pool borrow — **no per-statement timeout exists on this connector**. For `db_lookup` there is additionally a 30 s Handler-side **result bridge** (`pipeline/wiring_runner.py::_LOOKUP_RESULT_TIMEOUT_SECONDS`) that releases the transform worker; it does **not** cancel the statement, which completes on the loop and only then releases its connection | every acquire is paired with a `pool.release()` in `finally`; the pool is closed on connection stop | an acquire expiry raises a **transient** PHI-free `DeliveryError`; SQLSTATE drives transient vs permanent | `RetryPolicy`. `db_lookup` itself is **single-shot** — it raises into the Handler |
| Reference-set sync (`DatabaseRef`) | `connect_timeout` 15 s (**login** timeout) and `acquire_timeout` 30 s on the pool borrow | the connection is released and the throwaway pool closed in nested `finally` blocks | a sync error (including an acquire expiry) is logged, the AlertSink fires and the previous snapshot keeps serving | one attempt per `refresh_seconds` (default 3600) — **no inner retry** |
| Internal sources — Timer / Loopback / PassThrough | n/a — no socket, no timeout | the worker task is cooperatively cancelled on stop | n/a | n/a |
| Engine API + `/ui` + `/ws/stats` (`[api].port`) | uvicorn defaults (the engine passes no `timeout_keep_alive`) | the ASGI lifespan calls `engine.stop()`, cancelling every worker | throttled requests get `429` + an audit row | n/a — the caller retries |
| Reverse proxy → engine segment (`[api].trusted_proxies`) | **none the engine owns** — the proxy's timeouts govern | connection lifetime is the proxy's | operator-owned | n/a |
| Store — SQLite (`[store].backend = sqlite`) | `PRAGMA busy_timeout` 5000 ms on the writer and on every read-pool connection; **the pool borrow itself carries no timeout**; no network timeout applies | connections are closed on store close | a busy database retries inside the store layer | n/a |
| Store — SQL Server (`[store].backend = sqlserver`) | three distinct bounds: `[store].connect_timeout` 15 s (**login**, passed as pyodbc `timeout=`), `[store].command_timeout` 30 s (**statement**, applied per acquire as the pyodbc connection attribute) and `[store].acquire_timeout` 30 s (the **pool borrow**); `[store].warm_pool_timeout` 15 s bounds the warm-up | every acquire releases back to the pool; the pool is closed on shutdown; a borrow the pool satisfies after the borrower gave up is released back rather than stranded | a driver error — or a `StoreAcquireTimeout` — propagates to the stage worker and the row stays claimable | stage handoffs re-run idempotently; `reset_stale_inflight` recovers on restart |
| Store — Postgres (`[store].backend = postgres`) | `[store].connect_timeout` 15 s (`create_pool(timeout=…)`), `[store].command_timeout` 30 s as `asyncpg`'s per-statement bound, and `[store].acquire_timeout` 30 s on the message-pipeline pool borrows (see the coverage note above) | as SQL Server | as SQL Server | as SQL Server |
| Active Directory — login binds (`[auth].ad_server`) | `[auth].ad_connect_timeout` 10 s on the LDAP TCP connect and `[auth].ad_receive_timeout` 10 s on every LDAP response read — threaded into **every** `ldap3` `Server`/`Connection` construction | the service-account connection is context-managed; the user bind is unbound in a `finally`, so a **rejected** password releases it too (the common adversarial case) | fails closed with `LdapError`; the login is rejected and audited | **single-shot** — two binds, no retry loop |
| Active Directory — session reconciler (`ad_session_recheck_seconds`) | the same `ad_connect_timeout` / `ad_receive_timeout` | as the login path — context-managed connections | a pass that fails is retried on the next interval; strike state is process-local | **single-shot per pass**; `ad_session_recheck_strikes` (2) required before a revoke |
| Kerberos / SPNEGO SSO (`kerberos_spn`) | **none engine-owned** — the OS provider owns any KDC timeout | the SPNEGO context is per-request | a failed step raises `LdapError` and audits a login reject | **single-shot**, single-leg — no NTLM fallback, no multi-leg handshake |
| OIDC IdP — token endpoint (`oidc_token_endpoint`) | 10 s — `auth/oidc/flow.py`'s **own** `exchange_code(timeout=…)` default (`AuthService._oidc_exchange` passes none). The JWKS leg's 10 s is a **separate** literal, `oidc_http.DEFAULT_IDP_TIMEOUT_SECONDS`; the two coincide but are independent | the response is context-managed; the body is size-capped | a non-200 or oversize body fails the login closed | **single-shot** — one POST per login |
| OIDC IdP — JWKS fetch (`oidc_jwks_uri`) | 10 s — `oidc_http.DEFAULT_IDP_TIMEOUT_SECONDS`, the constant `jwks_fetcher` is the only consumer of | the response is context-managed; the size cap is enforced on the socket read | a fetch failure fails verification closed | **single-shot**, further damped by the refetch floor |
| SMART token endpoint (`smart_token_url`) | `smart_timeout_seconds` 30 s | the response is context-managed; the token is cached in memory | a mint failure fails the delivery | **single-shot** — re-minted only on the next attempt or a `401` |
| OAuth2 token endpoint (`oauth2_token_url`) | `oauth2_timeout_seconds` 30 s | as SMART | as SMART | **single-shot** |
| AI broker (`[ai].endpoint`) | 60 s — a **hard-coded module constant, not operator-configurable** (`[ai]` has no timeout field) | the response is context-managed; the call runs off the event loop via `to_thread` | a mis-configuration, an un-allowlisted host, or an HTTP error raises to the API route | **single-shot** — one POST per assist, no retry |
| DR backup destination (`[backup].destination`, ADR 0049) | **no engine-owned timeout** — filesystem / SMB-redirector I/O, the same posture as the File connector | handles are context-managed; the archive is fsync'd, then verified, and only then renamed onto its canonical name | a failed or verify-failed run is logged + audited and keeps a `.failed` name, so it is never a keep-N candidate — in that prune or any later one (ADR 0049) | **single-shot per scheduled pass** — retried only by the next daily pass |
| Vault Transit — store DEK unwrap (`MEFOR_STORE_VAULT_ADDR`, `[store].key_provider = vault`, ADR 0019) | **30 s, inherited — not MEFOR-owned.** The client is built as `hvac.Client(url=…, token=…)` with **no timeout argument**, so the bound is `hvac.adapters.Adapter.__init__`'s own `timeout=30` default (`requests` itself has **no** default timeout — without hvac's, this hop would block forever). `hvac>=2.3.0` is the pinned floor; **no MEFOR setting exists** | the `hvac` client is short-lived per unwrap | **fail-closed** — the store refuses to open | **single-shot** — one request per unwrap |
| Vault Transit — bulk at-rest cipher (`MEFOR_STORE_TRANSIT_KEY`, `[store].cipher_provider = vault_transit`, ADR 0138) | **30 s, inherited — not MEFOR-owned**: the same no-timeout `hvac` client build, so the same `hvac.adapters.Adapter` `timeout=30` default applies to **every cell round trip** | a **single long-lived** `hvac.Client` held for the store's lifetime (`TransitCipher.__init__`), not per operation | a per-operation failure raises `CipherError` at runtime — it does **not** refuse to open the store | **single-shot** per cell; the stage's own re-claim is what retries |
| Vault KV v2 (`MEFOR_SECRETS_VAULT_ADDR`) | **30 s, inherited — not MEFOR-owned**: the same `hvac.Client(url=…, token=…)` construction with no timeout argument, so the same `hvac.adapters.Adapter` `timeout=30` default applies | as Transit | **fail-closed** — the connector refuses to build | **single-shot** — one request per read |
| Alerts — SMTP sink (`[alerts].email_smtp_host`) | `[alerts].email_timeout` 30 s on the `smtplib` constructor | one connection per send, closed after the send | the failure is **swallowed and logged**, never propagated onto the message path | **single-shot** — no retry |
| Alerts — per-user security-event email (`[auth].notify_security_events`) | the same `[alerts].email_timeout` 30 s on the `smtplib` constructor (it reuses the operator transport) | the session is closed per send; the send runs off the event loop via `to_thread` | swallowed and logged, never propagated onto the login/admin path | **single-shot** — no retry |
| Alerts — webhook sink (`[alerts].webhook_url`) | `[alerts].webhook_timeout` 10 s | the response is context-managed | swallowed and logged, best-effort | **single-shot** — no retry |
| Syslog forwarder (`[logging].forward_host`) | 5 s pinned on the socket for both `tcp` and `tls` (the TLS handshake runs under it); UDP is connectionless and carries none | a single long-lived socket owned by the logging handler | on timeout the handler drops **that record** and continues | **single-shot** per record — no retry |
| SNTP clock-sync probe (`[logging].ntp_peer`) | 2 s pinned with `sock.settimeout`, so a silent peer cannot block `serve()` | the datagram socket is closed after the single probe | skew warns loudly, or refuses to start under `time_sync_fail_closed` | **single-shot** — one probe per start |
| Forward / egress web proxy (`[egress].proxy_url`) | **inherits the destination connector's `timeout_seconds`** — the proxy hop has no separate timeout | released with the destination request; the per-connection `ProxyHandler` never mutates the shared opener | a proxy error surfaces as the destination request's failure | the destination's `RetryPolicy` |
| Loopback ECH sidecar (`ech_sidecar`) | **inherits the connection's `timeout_seconds`** | released with the destination request | fails closed at build on a missing or non-loopback sidecar | the destination's `RetryPolicy` |

## Competitive parity — full connector catalog

We target parity with the three leading on‑prem HL7 engines — **Mirth Connect (NextGen)**,
**Corepoint**, and **Rhapsody**. A framing note: vendor "800+ connectors" claims count every
*system/format* reachable through a transport; all three actually expose ~12–20 *transport types*.
Matching "everything they do" is therefore a realistic **~18 connector types**, not 800 — and because
MessageFoundry transforms are Python, a transport we don't ship can often be scripted in a Handler.

Legend: ✅ native · ~ partial / via extension / via another transport · ❌ none.

| Method | Mirth | Corepoint | Rhapsody | MF today | MF code / status |
|--------|:-----:|:---------:|:--------:|:--------:|------------------|
| **MLLP / LLP** (HL7 lower‑layer over TCP) | ✅ | ✅ | ✅ | ✅ | `IB`/`OB` shipped |
| **Raw TCP** client/server (configurable framing) | ✅ | ✅ | ✅ | ✅ | `TCP-IN/OUT` shipped |
| **File / Directory** (local) | ✅ | ✅ | ✅ | ✅ | `FILE-IN/OUT` shipped |
| **FTP / FTPS** | ✅ | ✅ | ✅ | ✅ | `FTP-IN/OUT` shipped — `Ftp()`, source + destination, stdlib `ftplib` (no extra); `tls=True` = FTPS with verifying TLS |
| **SFTP** | ✅ | ✅ | ✅ | ✅ | `SFTP-IN/OUT` shipped — `Sftp()`, source + destination, `[sftp]` extra; host-key verification on by default |
| **SMB / network share** | ✅ | ✅ | ✅ | ✅ | `File()` on a UNC path, with an optional **alternate Windows credential** (`credential_*`, ADR 0132) |
| **S3 / cloud blob** | ✅ | ~ | ✅ | ❌ | not built — the one remaining remote-file scheme |
| **HTTP/HTTPS** listener + sender (REST) | ✅ | ✅ | ✅ | ✅ | `REST-OUT` (`Rest()`) + `REST-IN` (`Http()`, ADR 0023) both shipped, incl. **intake authentication** on the listen socket (`intake_auth` — API key / bearer / mTLS subject, ADR 0154) |
| **SOAP / Web Services** | ✅ | ✅ | ✅ | ~ | `SOAP-OUT` shipped incl. WS-\* mTLS/WS-Security (ADR 0015); a SOAP body is **received** via `Http()`, and the *synchronous* envelope reply shipped with ADR 0154 (`reply_from`). Still `~` for one reason: a partner **error** body is not relayed (`capture_error_responses`), so the reply path is correct only when the partner succeeds |
| **Database** reader/writer | ✅ (JDBC) | ✅ | ✅ (JDBC) | ✅ (ODBC) | `DB-OUT` + `DB-IN` shipped (SQL Server preset, production — a live aioodbc round-trip runs in CI); `dialect='generic'` reaches any DB with an OS-installed ODBC driver. **No JDBC** — MF is pure Python, no JVM |
| **SMTP** (email send) | ✅ | ✅ | ✅ | ✅ | `SMTP-OUT` shipped — `Email()`/`SMTP()` (ADR 0029); **plus** `Direct()`, Direct-Project S/MIME over SMTP (ADR 0085), which none of the three ships natively |
| **Email reader** (POP3/IMAP) | ~ | ~ | ✅ | ❌ | `MAIL-IN` planned |
| **JMS** (Java messaging) | ✅ | ❌ | ✅ | ❌ | `JMS-IN/OUT` planned |
| **IBM MQ / MSMQ** | ~ | ❌ | ✅ | ❌ | not on roadmap |
| **Kafka / streaming** | ~ | ❌ | ✅ | ❌ | not on roadmap |
| **DICOM** (imaging) | ✅ | ~ | ✅ | ✅ | `DICOM-IN` C-STORE SCP (Phase 1) + `DICOM-OUT` C-STORE SCU/C-ECHO + `DICOMWEB-OUT` STOW-RS all shipped (ADR 0025); DICOMweb send exceeds both incumbents |
| **Serial (RS‑232)** + X/Y‑Modem/Kermit + **ASTM E1381/E1394/E1318** | ~ | ❌ | ✅ | ❌ | **declined-by-design (v0.2+)** — legacy/niche lab-instrument connectivity, no feed demand ([BACKLOG #27](BACKLOG.md)) |
| **FHIR** endpoint/client | ✅ | ✅ | ✅ | ~ | `FHIR-OUT` shipped (`FHIR()`, ADR 0022) + SMART Backend Services client auth (ADR 0024); the inbound **server facade** is deferred (BACKLOG #20) |
| **Internal channel‑to‑channel** | ✅ | ✅ | ✅ | ✅ | the routing graph (wired by name) — plus two first-class internal inbounds: `Loopback()` (a captured reply) and `PassThrough()` (1:N internal re-ingress), ADR 0013 |
| Printer / command‑line / screen‑scrape | ~ | ❌ | ✅ | ❌ | not on roadmap (niche) |

Two shipped MessageFoundry transports have **no row above** because they have no clean incumbent to grade
against: the **Timer** clock-driven source (`Timer()`, ADR 0011) and — folded into the SMTP row — the
**Direct Project** S/MIME-over-SMTP destination (`Direct()`, ADR 0085).

**Priority of the gaps we'll close:**

- **Tier 1 — table stakes (all three have these): now shipped, bar one.** Raw TCP, HTTP/REST (**both**
  directions), `SOAP-OUT`, Database (`DB-IN` + `DB-OUT`), SFTP, FTP/FTPS, UNC/SMB, and the **FHIR** client
  all ship — as does `SOAP-IN`'s *synchronous* envelope reply (ADR 0154 `reply_from`), bar the
  partner-error relay noted in its row above. What is left on this tier: **S3 / cloud blob**, and the
  `FHIR-IN` inbound facade (a consumer of the shipped `Http()` listener, not new substrate).
- **Tier 2 — present in 2 of 3:** JMS (Mirth + Rhapsody) and the **Email reader** (POP3/IMAP) are the open
  ones — SMTP *send* shipped (ADR 0029). **DICOM is full-lane** — the `DICOM-IN` C-STORE SCP (Phase 1) plus
  the `DICOM-OUT` C-STORE SCU/C-ECHO and the `DICOMWEB-OUT` STOW-RS sender (Phase 2, ADR 0025) ship; the
  DICOMweb send path **exceeds** both incumbents.
- **Tier 3 — Rhapsody‑only, lower priority:** Kafka/streaming (worth adding for modern credibility),
  IBM MQ/MSMQ, Serial, printer/command‑line.

Each new type needs a `ConnectorType` value, a `transports/` module, a `register_source`/
`register_destination` call (which is what makes it *built*), and a `wiring.py` factory.

### Per‑transport feature gaps (not just new types)

- **MLLP — now shipped:** TLS/SSL (`tls`, WP-13b / ADR 0002), keep‑connection‑open/pooling (`persistent`,
  ADR 0067), max buffer size (`max_frame_bytes`), and enhanced-mode commit ACK codes (CA/CE/CR via
  `ack_mode="enhanced"`). **Still open:** custom start/end frame bytes on `MLLP()` itself (a non-standard
  sentinel is `Tcp(framing=None, start=…, end=…)` today), MLLP **release-2 block framing**, and
  response‑on‑same‑connection (the synchronous downstream reply, an ADR 0013 follow-on).
- **File — now shipped:** file‑age sorting (`sort="mtime"`), Corepoint-style **batch splitting** (an
  `MSH`/`FHS`/`BHS` batch file becomes N hand-offs), and the remote schemes — FTP/FTPS (`Ftp()`), SFTP
  (`Sftp()`), UNC/SMB (`File()` on a UNC path). **Still open:** **S3 / cloud blob**, and a cron
  *expression* on the File poll itself — a time-of-day / day-of-week **active window** is available per
  connection via `schedule` (ADR 0095), and cron *firing* via `Timer(cron_expression=…)`.
- **Monitor:** honor the `IBC`/`OBC` "waiting = healthy" convention in connection health.

## Standards & formats — parity & roadmap

Formats are **orthogonal to transports**: any format can ride any connector (an X12 837 over MLLP, a
C‑CDA over a file, a FHIR bundle over HTTP). This section is the **format/standard** parity story; the
catalog above is the **transport** one.

**Where MF stands today:** HL7 v2.x is the default, with **X12 EDI**, **FHIR**, **XML/SOAP**, and (Phase 1)
**DICOM** modeled lanes now shipped. [`parsing/`](../messagefoundry/parsing/) is python‑hl7 (tolerant peek,
hot path) + hl7apy (opt‑in strict) for v2, plus pure codecs for X12 (`parsing/x12` — tolerant peek/edit
*and* opt‑in strict implementation‑guide validation via the `[x12]` extra), FHIR (`parsing/fhir`), XML/SOAP
(`parsing/xml` — hardened‑lxml XPath read/set + XSD + XML‑DSig, the `[xml]` extra), and DICOM headers/SR
(`parsing/dicom`); there is still no C‑CDA, NCPDP, or HL7 v3 **model** in the engine. The competitors are
format‑agnostic and cover the full clinical catalog.

A useful split, because it sets the cost:

- **"Free in Python" text formats** — JSON, delimited/CSV, and fixed‑width are handled **in a Handler
  today** with the standard library (`json`, `csv`) — `RawMessage` even exposes `.json()` and a
  DTD‑rejecting `.xml()` accessor — so no engine change is needed to read or emit them. They're a
  documentation + helper‑ergonomics item, not a build. (*Generic* XML has since graduated to a real
  modeled lane, `parsing/xml` — see the table.)
- **"Modeled standards"** — CDA/C‑CDA, FHIR, X12/EDI, NCPDP, DICOM, and HL7 v3 each need a real
  **parse + model + validate lane** parallel to the v2 lane (a document/resource model, a field/path
  façade so transforms stay code‑first, and a standard‑specific validator). Each is its own workstream.

Legend: ✅ native · ~ partial / via generic XML/JSON · ❌ none.

| Format / standard | Mirth | Corepoint | Rhapsody | MF today | MF plan |
|-------------------|:-----:|:---------:|:--------:|:--------:|---------|
| **HL7 v2.x** | ✅ | ✅ | ✅ | ✅ | shipped (python‑hl7 + hl7apy) |
| **JSON** | ✅ | ✅ | ✅ | ✅ | `content_type="json"` + `RawMessage.json()`; transforms are stdlib `json` in a Handler |
| **Delimited / CSV / fixed‑width** | ✅ | ✅ | ✅ | ~ | scriptable in Handler now (stdlib `csv`); ship helper |
| **Generic XML** | ✅ | ✅ | ✅ | ✅ | shipped — `parsing/xml` (`[xml]` extra): hardened‑lxml `XmlMessage` XPath read/set + XSD strict tier + XML‑DSig, plus the DTD‑rejecting core `RawMessage.xml()` (BACKLOG #31) |
| **Raw / binary pass‑through** | ✅ | ✅ | ✅ | ✅ | stored/routed as opaque bytes today |
| **FHIR** (R4/R5, JSON + XML) | ✅ | ✅ | ✅ | ✅ | shipped — `parsing/fhir` (`[fhir]` extra): `FhirPeek` routing tier + validated `FhirResource` (R4B default / R5 / STU3) + FHIRPath, ADR 0022. **JSON only** — FHIR‑XML is deferred to the hardened‑lxml path |
| **C‑CDA / CDA / CCD** (HL7 v3 XML doc) | ✅ | ✅ | ✅ | ❌ | no CDA **model** — modeled lane, **Tier 1** (the shipped XML lane is the substrate it would build on) |
| **X12 / EDI** (270/271, 834, 835, 837…) | ✅ | ✅ | ✅ | ✅ | shipped — `parsing/x12`: dependency‑free tolerant `X12Peek`/`X12Message` (ADR 0012) + opt‑in **strict implementation‑guide** validation over pyx12's HIPAA maps (`[x12]` extra, #32), whose walk also emits a conforming 999/997. No *automatic* TA1/997/999 generation on the wire |
| **NCPDP** (SCRIPT, Telecom) | ✅ | ~ | ✅ | ❌ | modeled lane — **Tier 2** |
| **DICOM** object / SR | ✅ | ~ | ✅ | ~ | headers/SR codec shipped (`parsing/dicom`, ADR 0025 Phase 1, pairs w/ `DICOM-IN`); no pixel data |
| **HL7 v3 messaging** (non‑CDA XML) | ✅ | ✅ | ~ | ❌ | modeled lane — **Tier 3** (low demand) |
| **IHE profiles** (XDS/PIX/PDQ) | ~ | ~ | ✅ | ❌ | transport+format combo — later |

**Roadmap priority (modeled standards):**

- **Tier 1 — FHIR (shipped) and C‑CDA (open).** The two formats every modern RFP asks for. **FHIR
  shipped** (ADR 0022) and pairs with the shipped `FHIR-OUT` / `REST-*` transports. **C‑CDA is the open
  one:** it most often arrives base64‑embedded in a v2 `MDM^T02`/`ORU` `OBX-5` (which MF already carries as
  bytes — the lane adds *understanding* it), and the shipped `[xml]` lane is the substrate step 2 below
  now builds on. See the CCD phasing note.
- **Tier 2 — X12/EDI (shipped) and NCPDP (open).** Eligibility/claims **X12 shipped** — tolerant codec
  (ADR 0012) plus strict IG validation (#32); pharmacy **NCPDP** is still open, needed for e‑prescribing
  and lower frequency than FHIR/CDA in a pure clinical shop.
- **Tier 3 — DICOM object/SR and HL7 v3 messaging.** DICOM (headers/SR, no pixel data) is **shipped
  (ADR 0025 Phase 1)** and pairs with the `DICOM-IN` C-STORE SCP transport; v3 messaging (as distinct
  from CDA) sees little real‑world demand.

**C‑CDA phasing (representative of how a modeled lane lands):**
1. *Pass‑through (today):* route/store a CCD as opaque bytes — as a file, or base64 in v2 `OBX-5`.
2. *Read‑only lane:* an XML model + XPath façade + XSD validation + an `OBX-5` base64 extract — enough
   to route on and validate. The generic half of this **shipped** with `parsing/xml` (#31); what a CDA
   lane still adds is the document/section model and its conformance profile.
3. *Transform:* v2 ↔ C‑CDA helpers (the high‑value, high‑effort part).

**Dependency note.** A modeled lane means a new parser/validator dependency. The shipped lanes each ride an
optional extra — `[dicom]` (`pydicom>=3.0.2,<3.1` + `pynetdicom>=3.0.4,<3.1`, pure‑Python, no numpy), `[fhir]`
(`fhir.resources` + `fhir-core` + `fhirpathpy`), `[x12]` (`pyx12`), and `[xml]` (`lxml` + `xmlschema` + `signxml`) — all
lazily imported, so an install that never touches a lane pays nothing. Still to be *evaluated*, not yet
chosen: an **NCPDP** parser (the XML/CDA question is settled — `lxml` is in tree under `[xml]`). Per the
project guardrails, each must be **verified as real and reputable, added to `pyproject.toml`, and
re‑locked** before use — no ad‑hoc installs. Each modeled lane is a substantial architectural addition,
so it follows the **plan‑first** rule (a written plan before code).
