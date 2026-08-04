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
  `timer`/`rest`/`database`/`database_poll`/`soap`/`sftp`/`ftp`) and **the factory is the schema**; an
  unknown transport/key/router fails loud at load (`messagefoundry check`), exactly like a bad
  `inbound()` call. The remaining connectors (`X12`/`FHIR`/`DICOM`/`DICOMweb`/`Email`/`Direct`/
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
> merely warned. **Seven** cells carry that gate: **MLLP-over-TLS, REST, SOAP, FHIR, DICOMweb (https),
> EMAIL/SMTP, and the PostgreSQL store hop**. On a stock instance that means `MLLP(..., tls=True)`, an
> `https://` `Rest()`/`Soap()`/`FHIR()`/`DICOMweb()` destination and an `Email()` STARTTLS relay are all
> refused **once they point off-box** — including the worked examples below, which are written to show
> the connector, not to pass the posture.
>
> **At the shipped default there are exactly two ways across**, and neither is a per-connection setting:
> keep the hop on **loopback**, or set the process-wide environment variable
> **`MEFOR_TLS_REVOCATION_ATTESTED=1`** — a *blanket* attestation that a revocation-checking PKI or
> terminator backs **every** hop in the process, logged at WARNING at each construction. The
> per-connection `tls_revocation_attested` field the connectors read has **no authoring surface** (no
> factory parameter, no `connections.toml` key), so do not plan a per-hop revocation posture around it;
> and routing egress through a revocation-checking proxy does **not** change the decision — the
> authority has an input for it that no call site sets. Anything else is a *posture change* rather than
> a fix: `[security].handles_real_patient_data = false` silences the gate instance-wide and
> `[security].enforcement = warn` downgrades it to a WARN.
>
> **The engine's other verifying TLS hops are not gated at all** — the DICOM C-STORE SCU with
> `tls=true`, FTPS, the `Database(...)` destination / `DatabasePoll(...)` source, the SQL Server store
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
| `max_connections` | in | `256` | cap on concurrent client connections (connection-flood guard). `None`/`0` = unlimited. |
| `receive_timeout` | in | `60.0` | close a client idle this many seconds (slowloris guard). `None`/`0` = no timeout. |
| `max_frame_bytes` | both | `16 MiB` | reject a single MLLP frame larger than this before buffering it whole (OOM guard); applies to inbound frames and outbound ACKs. `None`/`0` = unlimited. |
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
| `tls_verify` | out | `true` | verify the server's certificate. `false` is MITM-able and is **refused at construction**. `MEFOR_ALLOW_INSECURE_TLS=1` downgrades that refusal to a loud warning **only where the clamp allows it** (#200, [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) decision 2): the escape is inert on an instance that is **both** PHI-classified **and** at `[security].enforcement = enforce`. That is the shipped default, so **on a stock instance the refusal stands with the variable set** — treat the env var as a lab tool, not a deployment option. Nothing else opens this hop: `cleartext_accepted` deliberately does **not** reach a verify-off hop (it has TLS — see [Declaring a cleartext hop](#declaring-a-cleartext-hop-cleartext_accepted)), and `tls_hop_attested` has no authoring surface. If the partner's certificate has merely lapsed, `tls_allow_expired` below is the narrower lever — read that row before reaching for it. |
| `tls_check_hostname` | out | `true` | require the server cert to match `host` (SNI + hostname check). |
| `tls_allow_expired` | out | `false` | **(#129, ADR 0094)** honour a partner **server cert whose validity period has lapsed** (`notAfter` past) while STILL validating the chain + hostname + key-usage — the **granular** alternative to `tls_verify=false` for the narrow expired-cert case. It is genuinely narrower (a wrong-host or untrusted-chain peer is still rejected), but do not book it as "not MITM-able": **expiry is the control that retires a certificate**, so a hop that ignores it will keep authenticating a **compromised key indefinitely** — and on the two connectors with no revocation gate (**DICOM-SCU, FTPS**) nothing else would catch that certificate either. **No posture gate covers this setting at all.** It needs no `MEFOR_ALLOW_INSECURE_TLS`; `[security].enforcement = enforce` does not clamp it; verification stays on, so no #200 cleartext/verify-off refusal keys on it; and it is **absent from `security_loosenings()`**, so `GET /security/posture`, the serve-time loosening warning and `messagefoundry check` will **not** report a connection that has it set. The only disclosure is the WARNING logged at each connector build — so a "two-week bridge" set when a partner's cert lapses has nothing that expires it or surfaces it: record the connection name and a removal date in your own risk register. Relaxes both validity bounds (a not-yet-valid cert is also accepted). `false` (default) = **byte-identical** (an expired cert is rejected as before). It is a factory parameter on **six** outbound connectors only — **MLLP, FTPS (`Ftp(tls=True)`), DICOM C-STORE SCU, REST, SOAP, FHIR** — and is **not** honoured by the engine's other verifying TLS hops, including **`DICOMweb()`** (which reuses the REST client but does not read it), the `Database(...)` destination / `DatabasePoll(...)` source, and the `Email()`/`Direct()` SMTP TLS legs. |
| `encoding_characters` | out | — (off) | **(Corepoint `-override` parity)** re-encode each outgoing message with a different set of HL7 delimiters (the 5 MSH chars in MSH order — MSH-1 + the 4 MSH-2 chars, e.g. `"#@*!%"`) before framing. Validated at build (exactly 5, all distinct). Unset = payload **byte-identical**. |
| `hl7_raw_separators` | out | `false` | **(BACKLOG #107) escape-hatch for a partner that cannot decode HL7 escapes:** emit the four reserved **structural** separators as RAW bytes (`\F\ \S\ \R\ \T\` → the message's own field/component/repetition/subcomponent char) instead of their escape sequences. Reserved chars are read from the payload's own MSH; re-serialized via the parsed model, never string-slicing. `false` (default) = payload **byte-identical**. Enabling it can produce **non-conformant** output (a formerly-escaped `^` now reads as a component separator) — that is the point; use only for such a broken partner. Composes after `encoding_characters` (delimiter rewrite first, then raw-separator emit). A non-HL7 payload fails the delivery loud (`DeliveryError`). **HL7v2/MLLP outbound only.** |
| `verify_ack_control_id` | out | `false` | **(BACKLOG #82)** tighten the *accept* decision: accept a **positive** ACK (MSA-1 AA/CA) only if its MSA-2 (message control id) echoes the sent message's MSH-10 — a reply carrying a different id is a correlation failure (retryable `DeliveryError` → retried per the at-least-once path). Both ids are read **separator-aware** from the message (never hardcoded `\|^~\&`). If the sent MSH-10 is absent/unreadable there is nothing to correlate, so the check is skipped and the message delivers as before. Does not alter a **negative** ACK's handling. `false` (default) = **byte-identical** (no correlation). |
| `send_min_interval_seconds` | out | — (off) | **(BACKLOG #82)** minimum **seconds between sends** on this outbound lane: the engine holds each `send` until at least this many seconds have elapsed since the lane's previous send **began**, so a partner that cannot absorb bursts sees a bounded send rate. **Per-envelope** — a batched `BHS…BTS` send (ADR 0082) counts as **one** interval (it throttles the send *rate*, not a per-message rate; a strict per-message cap is a future refinement). A pure **wait** at the delivery seam: it never reorders (strict per-lane FIFO holds — the row is already claimed) and is cancellable by the connection's stop. Independent outbounds pace **independently** (a per-lane clock, not a shared bucket). `None`/`0` (default) = **no pacing**, delivery **byte-identical**. A negative value is rejected at wiring. |

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
```

- **No HL7 ACK.** A `Tcp(...)` source does **not** generate an HL7 acknowledgement. If a Handler
  returns a payload it is framed back to the sender on the same connection (so a framed
  application-level reply is possible); returning `None` sends nothing.
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
| `connect_timeout` | out | `10.0` | TCP connect timeout (s) |
| `timeout_seconds` | out | `30.0` | send / await-reply timeout (s) |
| `persistent` | out | `false` | **(ADR 0067 §9 / BACKLOG #97)** reuse **one** lazily-established connection across deliveries (opt-in; default `false` = connect-per-send, byte-identical). A stale socket is redialed once **before any byte is written** (uncharged); any post-write failure is charged + retried. A returned TA1/business interchange is a complete transaction on a healthy transport, so the connection **stays cached** across a captured reply (and a TA1\*R reject). |
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
```

See `samples/config/IB_PARTNER_X12.py` + `samples/messages/x12_270_eligibility.edi` for a runnable
example, and `messagefoundry.parsing.x12` for the codec a Router/Handler uses.

- **No X12 ACK on the *inbound*.** An `X12(...)` source does **not** generate a TA1/997/999. If a
  Handler returns a payload it is written back **verbatim** on the same connection; returning `None`
  sends nothing.
- **Synchronous request/response on the *outbound* (ADR 0016).** With `capture_response`/`reingress_to`
  the destination blocks for the returned interchange and classifies a **TA1** interchange ack:
  **TA1\*A** → accepted; **TA1\*R** → permanent reject → **dead-letter**; **TA1\*E** →
  accepted-with-warning (delivered, **not** retried, logged). A business **271/277/278** returned
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
| `max_body_bytes` | `16 MiB` | the MLLP frame cap's HTTP twin — an over-declared `Content-Length` (or a read past the cap) is refused `413` **before the body is buffered whole** (OOM guard). `None`/`0` = unlimited. |
| `max_header_bytes` | `64 KiB` | cap the request line + headers (header-flood guard). A falsy value falls back to the 64 KiB default — this one cap can't be switched off. |
| `tls` | `false` | serve **HTTPS** (TLS 1.2+, the same per-connection inbound TLS builder MLLP uses). |
| `tls_cert_file` / `tls_key_file` | — | the server-identity cert + its private key (required when `tls`). A PEM **path** (a plain string — unlike `DICOM()`, these two are not typed for `env()`). |
| `tls_key_password` | — | passphrase for an **encrypted** `tls_key_file` — a **secret**, supply via `env()`. |
| `tls_ca_file` | — | trust anchor — opt-in **mTLS** (require + verify a client certificate). |
| `intake_auth` | `"none"` | **peer credential required to submit a message** ([ADR 0154](adr/0154-synchronous-captured-downstream-reply-and-intake-authentication-for-the-inbound-http-listener-adr-0023-deferred-tail.md) D6): `none` \| `api_key` \| `bearer` \| `mtls_subject`. A sibling of `source_ip_allowlist` — it authorises *submitting*, never *reading*; it mints no identity and opens no session. A missing or wrong credential is refused `401` **before any request body byte is read**, so it costs an anonymous peer nothing to be turned away. |
| `intake_api_key` | — | the credential for `api_key`/`bearer` — a **secret**, `env()` only (a literal, a `default=` or a `cast=` is refused at the factory). |
| `intake_api_key_next` | — | rotation slot, accepted **alongside** `intake_api_key` so a partner key rotates with no outage: set it, have the partner cut over, promote it, then clear it. Leaving it set keeps a retired credential live. |
| `intake_api_key_header` | `"x-api-key"` | which header carries the `api_key` credential. A header **name**, not a secret. |
| `intake_client_subjects` | — | `mtls_subject` allow-list, entries **qualified**: `"CN:partner.example"` / `"SAN:DNS:partner.example"`. Qualifying the namespace is what stops a spoofed commonName colliding with a pinned SAN; a bare `partner.example` is refused at the factory rather than silently matching nothing. |
| `intake_auth_health` | `"require"` | whether `GET`/`HEAD` health probes must authenticate too. **`"allow"` is a real exemption**: it hands anyone who can reach the socket an unauthenticated "is MessageFoundry up, and where" oracle. Set it only when a load-balancer check cannot carry the credential. |
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
disposition + the AlertSink, exactly as a post-ACK MLLP failure does. A **pre-ingress** refusal answers
synchronously and emits an ADR 0021 `connection_event`: `403` (not in `source_ip_allowlist`), `408` (the
request didn't fully arrive within `receive_timeout`), `413` (over `max_body_bytes` **or**
`max_header_bytes`), `400` (malformed request line / header, a bad or duplicated framing header), `503` (at
`max_connections` — the connection is accepted, then refused and closed at the application layer).
`GET`/`HEAD` are static, non-PHI health probes and write **no** ingress row; any other method is `405`.

**Synchronous captured-downstream reply (`reply_from`, ADR 0154 increment B).** Naming `reply_from` makes
the HTTP turn **block** until the named outbound's reply has been captured **and committed to the store**,
then returns that reply as the response body — a proxy API rather than a receipt. The **committed row is
the sole authority** for the returned bytes: every in-process signal is only a latency hint and the waiter
re-reads the store, which is what keeps this correct under engine sharding, HA failover, every claim mode,
and any race between the capturing worker and the reader. A reply is therefore returned only once it is
durable and replayable. An inbound **without** `reply_from` keeps the `202`-on-receipt path above byte for
byte.

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


@router("acme_orders_router")
def route(msg):
    return ["acme_orders"] if msg.json().get("kind") == "order" else []   # else UNROUTED
```

### File — `File(...)`

| Setting | Dir | Default | Meaning |
|---------|-----|---------|---------|
| `directory` | both | — (required) | folder to poll / write into |
| `pattern` | in | `*.hl7` | filename glob to pick up |
| `poll_seconds` | in | `1.0` | poll interval |
| `min_age_seconds` | in | `0` | skip files modified within this window (partial writes) |
| `after_read` | in | `move` | `move` (→ `.processed`), `delete`, or `leave` (process **in place** — never move/delete the source file, for a read-only share / a directory another system owns; a hashed dedup ledger ensures a left file is ingested **once**, #142) |
| `sort` | in | `name` | process order: `name` or `mtime` |
| `recursive` | in | `false` | also scan subdirectories |
| `max_file_bytes` | in | `16 MiB` | route files larger than this to the error dir instead of reading them into memory (OOM guard). `None`/`0` = unlimited. |
| `validate_directory` | in | `false` | validate the poll directory **at startup** (#114): a missing/unusable dir reports the connection **`failed`** (ADR 0031) instead of the default deferral to run time. No mkdir — a merely-missing dir fails. A `leave` source validates read-only (a read-only share passes); `move`/`delete` also require write. **Inbound only** — on an outbound it is a `WiringError` at bind (an outbound target directory is never validated at startup; it is `mkdir`ed on write). |
| `processed_subdir` / `error_subdir` | in | `.processed` / `.error` | where read/failed files go |
| `filename` | out | `{MSH-10}.hl7` | output name (supports `{HL7-path}` placeholders). Resolved values are sanitized to a **single safe filename** — path separators/unsafe chars stripped, leading dots removed, and `.`/`..`/reserved device names fall back — so a message field can never write outside the directory. |
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

MessageFoundry's file surface has three parts: the **directory sources** (the local `File(...)` and
remote `Sftp(...)`/`Ftp(...)` connectors) that ingest drop-directory files into the pipeline; the
**opt-in HTTP uploaded-logs upload** (POST `/uploads` + the web-console delegate POST
`/ui/uploaded-logs/upload`, [ADR 0134](adr/0134-offline-uploaded-logs-viewer-connection-decoupled-upload-browse-resend-deletion-phi-at-rest-posture-stdlib-multipart.md))
for operator diagnostic logs; and the **attachment download** route (GET
`/messages/{message_id}/attachments/{attachment_id}`, [ADR 0105](adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md))
that serves a detached document back out. The **directory source's** handling of an untrusted drop
directory is fixed policy (the HTTP uploaded-logs surface has its own policy block below):

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
- **Maximum size.** `max_file_bytes` (default **16 MiB**, matching the MLLP frame cap). An oversize file
  is rejected by a `stat()` **before** it is read into memory (OOM / DoS guard); `None`/`0` disables it.
- **Decompression is off by default; opt-in single-stream gzip is bomb-guarded** (ADR 0123). With no
  `decompress=` set the connector reads raw bytes only and there is no unpacked-size surface. When
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
  place to retry** next scan — never an accept-and-drop. Use `min_age_seconds` to skip files still being
  written.
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
- **Consent affordance (ASVS 14.2.8).** The `/ui/uploaded-logs/upload` form states, above its submit
  button, that the original filename and the uploader's username are stored and shown to authorized
  operators and recorded in the audit log — **submitting the form is the consent**; the POST `/uploads`
  OpenAPI docstring states the same for programmatic callers.

**Downloads are made safe at serve (ASVS 1.3.4).** The attachment download route (GET
`/messages/{message_id}/attachments/{attachment_id}`, and its `/ui` delegate) serves the stored bytes
**verbatim** (the preserve-the-original invariant forbids rewriting a clinical payload) but neutralizes
them at the response: the sender-influenced OBX-5.2 MIME is forced through `_safe_attachment_content_type`
to `application/octet-stream` on any non-clean value **and** on any **browser-active** type (`html`,
`xml`, `script`, `svg` subtypes + `multipart`, matched case-folded, length-bounded); the response carries
`Content-Disposition: attachment` (a download, never an inline render), `X-Content-Type-Options: nosniff`
(no MIME re-sniff), and `Content-Security-Policy: default-src 'none'; sandbox` (an opaque origin with
scripts/forms disabled), re-asserted on the `/ui` delegate from **outside** the console's own CSP writers
so a browser-active representation can never execute in the application origin.

### Remote file — `Sftp(...)` / `Ftp(...)`

**One** connector type (`REMOTEFILE`) with two factories, each **source *and* destination** — the `File(...)`
poll/write shape against a remote server, selected by an internal `protocol` setting:

- **`Sftp(...)`** — SSH file transfer over **paramiko**, behind the **`[sftp]` extra**
  (`pip install 'messagefoundry[sftp]'`, lazily imported so an install that never uses SFTP skips it).
  **Host-key verification is ON by default** (the system host keys plus an optional extra `known_hosts`,
  paramiko `RejectPolicy`); an unknown key is **refused** unless `MEFOR_ALLOW_INSECURE_TLS` is set (and
  loudly logged when it is). **This one cell reads the raw escape and is *not* clamped** — unlike the
  `tls_verify` / `encrypt` cells elsewhere in this document, the variable still works here on a
  production-PHI enforcing instance, so it is the SFTP setting to audit for rather than assume inert.
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
| `private_key` | both | — | **`Sftp` only** — PEM private-key text or a path; a **secret**, via `env()` |
| `key_password` | both | — | **`Sftp` only** — passphrase for an encrypted `private_key`; a **secret**, via `env()` |
| `known_hosts` | both | — | **`Sftp` only** — an *additional* `known_hosts` file (the system host keys are always loaded) |
| `tls` | both | `false` | **`Ftp` only** — `true` selects **FTPS** (explicit TLS); `false` is plain FTP |
| `tls_allow_expired` | both | `false` | **`Ftp` only** — honour an FTPS server cert whose validity period has lapsed while still verifying chain + hostname (#129, ADR 0094). Same contract, and the same unreported risk, as the [MLLP `tls_allow_expired` row](#mllp--mllp): **no posture gate, no escape variable and no loosening register covers it**, so nothing but the per-build WARNING records that it is set — and the FTPS hop has **no revocation gate either**, so an expired *and* revoked partner certificate crosses here with nothing refusing it. Put the connection name and a removal date in your own risk register |
| `pattern` | in | `*.hl7` | filename glob to pick up |
| `poll_seconds` | in | `5.0` | poll interval |
| `min_age_seconds` | in | `0.0` | **accepted but not honoured on a remote source today** — the connector never reads it (a remote directory listing carries no reliable mtime). Only `File(...)` implements it; use `after_read`/the partner's own write-then-rename to avoid partial reads. |
| `after_read` | in | `move` | `move` (→ `processed_subdir`), `delete`, or `leave` (process **in place**, #142 — a durable dedup ledger keyed on a hash of the **full remote path** + size ensures a left file is ingested once) |
| `max_file_bytes` | in | `16 MiB` | move a file larger than this to `error_subdir` instead of retrieving it (OOM guard). `None`/`0` = unlimited. |
| `validate_directory` | in | `false` | validate `remote_dir` **at startup** (#114): unreachable/unusable reports the connection **`failed`** (ADR 0031) instead of deferring to run time. **Inbound only** — on an outbound it is a `WiringError` at bind (the upload dir is `ensure_dir`ed on write, never validated at startup). |
| `processed_subdir` / `error_subdir` | in | `.processed` / `.error` | where read / failed files go |
| `filename` | out | `{MSH-10}.hl7` | upload name (supports `{HL7-path}` placeholders, sanitized to a **single safe filename** exactly as `File(...)`) |
| `overwrite` | out | `false` | overwrite vs. uniquify a name collision (never a silent clobber) |
| `encoding` | out | `utf-8` | charset the payload is encoded with before upload (the **source** hands the retrieved bytes to the pipeline and never uses it) |

- **Atomic publish.** An upload writes an unguessable temp `.part` name then **renames**, so a poller on
  the far side never sees a partial file; a failed rename removes the temp before the delivery is
  classified (transient → retry, permanent → dead-letter).
- **Mostly the same file policy as `File(...)`.** A remote source is one of the *directory sources* the
  [file handling & quarantine policy](#file-handling--quarantine-policy-asvs-511) above governs — the
  content-type-aware magic-byte sniff (a drop whose leading bytes contradict its declared `content_type` is
  quarantined before its bytes reach the pipeline), `max_file_bytes`, `.error` quarantine (never a silent
  drop), and the fail-closed pre-ingest `set_scan_hook` AV/ICAP seam all apply. **Three File-source
  behaviours do *not* carry over:** the HL7 **batch split** (a multi-message `MSH`/`FHS`/`BHS` file is one
  hand-off here, not N), opt-in gzip `decompress` (ADR 0123, local `File(...)` only), and
  `min_age_seconds` (above).
- **Leader-gated.** The remote directory is a *shared* external resource, so in a cluster only the leader
  lists, downloads, or moves its files — otherwise two nodes would double-ingest the drop.
- **No timeout knob.** Neither factory exposes one — the 30 s value is a hard-coded module fallback in
  `transports/remotefile.py`, handed to `paramiko.SSHClient.connect(timeout=…)` (the **TCP connect only**;
  the SFTP channel read/write is unbounded) and to `ftplib.FTP_TLS/FTP(timeout=…)` (the **whole socket**).
  See [Table B](#table-b--per-service-resource-strategy-asvs-1313).
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
| `headers` | `{}` | extra **static** headers (no secrets — these aren't `env()`-resolved) |
| `bearer_token` | — | `Authorization: Bearer …` (a **secret** — supply via `env()`) |
| `basic_user` / `basic_password` | — | HTTP Basic auth (secrets — via `env()`) |
| `timeout_seconds` | `30` | per-request timeout |
| `verify_tls` | `true` | TLS cert verification. `false` is MITM-able and is **refused at construction** for a non-loopback host. `MEFOR_ALLOW_INSECURE_TLS` relaxes it to a loud warning **only while `[security].enforcement` is not `enforce`** — the escape is **clamped** (#200, ADR 0092 decision 2) and is therefore **inert on the shipped default**, where the refusal stands with the variable set. `cleartext_accepted` does **not** reach this hop (it has TLS — it is encrypted-but-unauthenticated, not cleartext), and `tls_hop_attested` has no authoring surface. A **loopback** URL is allowed unchanged, which is what makes this usable in a lab |
| `tls_allow_expired` | `false` | **(#129, ADR 0094)** tolerate an **expired** server cert while chain + hostname stay verified — the narrow alternative to `verify_tls=false`. Same contract and the same reporting gap as the [MLLP row](#mllp--mllp): **no posture gate, no escape variable, and `security_loosenings()` never reports it** |
| `encoding` | `utf-8` | request-body charset |

**Delivery semantics.** A **2xx** is delivered. **5xx / 408 / 429 / connection / DNS / TLS / timeout**
raise `DeliveryError`, so the lane **retries** with backoff. **Other 4xx** (and a refused **3xx
redirect**) raise a permanent `NegativeAckError`, so the message **dead-letters immediately** rather
than blocking the FIFO lane on a request the endpoint will never accept.

**Security.** Redirects are **refused** (a 3xx can't divert PHI to another host — ASVS 15.3.2), the URL
scheme is constrained to `http`/`https`, and the outbound host is gated by the fail-closed
`[egress].allowed_http` allowlist (WP-11c). Standard library only (`urllib`) — no new dependency.

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
- **`dialect="generic"`** — a **generic ODBC path** for any other ODBC-reachable database (PostgreSQL,
  Oracle, MySQL, …). No new Python dependency: you install the target's **ODBC driver at the OS level**
  and name it in `odbc_driver`; see [*Generic ODBC*](#generic-odbc-postgresql--oracle--mysql) below.

(The SQL Server *store* backend is a **separate** layer, also production; the connector doesn't depend on
it.) The **inbound** direction is the DB poll source below (`DatabasePoll(...)`).

The Handler produces a **JSON-object** body; the connector binds its keys to the `:name` parameters in
`statement` (translated to positional ODBC `?` — always parameterized, never string-built) and runs it.

| Setting | Default | Meaning |
|---------|---------|---------|
| `server` | — (required) | DB host (the `[egress].allowed_db` allowlist key). Use `env()` for a DEV/PROD-specific host. |
| `database` | — | database name — **required** for `dialect="sqlserver"`; optional for `"generic"` |
| `statement` | — (required) | parameterized SQL / proc call with `:name` placeholders, e.g. `INSERT INTO obs (mrn, val) VALUES (:mrn, :val)` |
| `dialect` | `sqlserver` | `sqlserver` preset · `generic` ODBC (see [*Generic ODBC*](#generic-odbc-postgresql--oracle--mysql)) |
| `auth` | `sql` | `sql` · `integrated` (Windows) · `entra` (ActiveDirectoryDefault) — **SQL Server preset only** |
| `username` / `password` | — | SQL-auth credentials (`password` is a **secret** — via `env()`) |
| `port` | `1433` | server port |
| `encrypt` | `true` | TLS to the DB (**SQL Server preset only** — see the generic-ODBC note below). `false` is a weakened hop and is **refused at construction**; `MEFOR_ALLOW_INSECURE_TLS` relaxes it **only while `[security].enforcement` is not `enforce`** — the escape is **clamped** (#200, ADR 0092 decision 2) and is **inert on the shipped default** |
| `trust_server_certificate` | `false` | accept an untrusted cert. Same weakened-hop cell as `encrypt=false` — **refused**, with the same **clamped** escape that does nothing on a stock instance. Import the DB CA instead (below) |
| `connect_timeout` | `15` | connection timeout (s) |
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

#### Generic ODBC (PostgreSQL / Oracle / MySQL)

`dialect="generic"` (#66) targets **any ODBC-reachable database** without a new Python dependency: the
connector still rides the already-present `aioodbc` driver — you install the *target's* **ODBC driver at
the OS level** (e.g. psqlODBC, Oracle Instant Client ODBC, MySQL Connector/ODBC) and name it in
`odbc_driver`. The parameterized-`:name` binding, error classification, pooling and `[egress].allowed_db`
gate are identical to the SQL Server preset.

| Setting | Default | Meaning |
|---------|---------|---------|
| `odbc_driver` | — (required for `generic`) | the **exact OS-registered ODBC driver name**, e.g. `PostgreSQL Unicode`, `MySQL ODBC 8.0 Unicode Driver`, `Oracle in instantclient_21_13` |
| `odbc_params` | — | a mapping of **driver-specific ODBC keywords** → values, e.g. `{"PORT": 5432, "SSLmode": "verify-full"}`. Values are **literals** (not `env()`-resolved — put per-env/secret values in the top-level fields) and are brace-quoted (injection-safe); keys must be valid ODBC keywords and may not re-set `DRIVER`/`SERVER`/`DATABASE`. |
| `odbc_user_key` | `UID` | ODBC keyword the top-level `username` is emitted under (some drivers want `USER`) |
| `odbc_password_key` | `PWD` | ODBC keyword the top-level `password` is emitted under (some drivers want `PASSWORD`) |

The DSN is built as `DRIVER={odbc_driver};SERVER=<server>;[DATABASE={database};][<user>={username};<pwd>={password};]<odbc_params…>`. `server` is emitted as the near-universal `SERVER` keyword (it is still the egress key); everything else driver-specific goes in `odbc_params`.

> **TLS is the operator's responsibility on the generic path.** MessageFoundry reads SQL Server's
> `Encrypt`/`TrustServerCertificate` to *refuse* a weakened DB hop, but it cannot introspect an arbitrary
> driver's TLS posture — so the weakened-TLS refusal does **not** apply here. Configure **verifying** TLS
> via the driver's own keyword in `odbc_params` (psqlODBC `SSLmode=verify-full`, MySQL
> `SSLMODE=VERIFY_IDENTITY`, Oracle wallet). Never point PHI at an unverified generic hop. So the
> delegation is never *silent*, a generic connection with **no** ssl/tls/encrypt keyword in `odbc_params`
> logs a **WARNING** at construction (dropped to DEBUG once a TLS keyword is set); this exemption is
> recorded in the [ADR 0092 amendment (2026-07-12)](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md).

> **Scope / limitations.** Native async DB drivers (`asyncpg`-as-connector, `oracledb`, `mysqlclient`) are
> **out of scope** (dep-heavy) — the generic path is ODBC-only. The `test_connection` reachability probe
> runs `SELECT 1` (works on PostgreSQL / MySQL / SQL Server; Oracle needs `SELECT 1 FROM DUAL`, so its
> probe reports an error even though delivery works). Read-only `db_lookup` (ADR 0010) stays SQL-Server-only.

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
| `encoding` | `utf-8` | charset for the body bytes handed to the pipeline |
| `dialect` / `odbc_driver` / `odbc_params` / `odbc_user_key` / `odbc_password_key` | `sqlserver` / … | same as `Database(...)` — `dialect="generic"` polls any OS-installed ODBC driver (PostgreSQL / Oracle / MySQL); see [*Generic ODBC*](#generic-odbc-postgresql--oracle--mysql) |
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
| `headers` | `{}` | extra **static** headers (no secrets — not `env()`-resolved) |
| `bearer_token` | — | `Authorization: Bearer …` (a **secret** — via `env()`) |
| `basic_user` / `basic_password` | — | HTTP Basic auth (secrets — via `env()`) |
| `timeout_seconds` | `30` | per-request timeout |
| `verify_tls` | `true` | TLS cert verification — the same posture-keyed cell as [REST](#rest--rest): `false` is **refused at construction** off loopback, and the `MEFOR_ALLOW_INSECURE_TLS` escape is **clamped inert** while `[security].enforcement = enforce` (the shipped default) |
| `tls_allow_expired` | `false` | **(#129, ADR 0094)** tolerate an **expired** server cert with chain + hostname still verified. **No posture gate, no escape variable, and it is never reported by `security_loosenings()`** — see the [MLLP row](#mllp--mllp) |
| `encoding` | `utf-8` | envelope charset |

**Fault & delivery semantics.** The response is inspected for a SOAP `Fault` (which can arrive as an HTTP
500 **or** an HTTP 200 body). A **Sender/Client** fault → `NegativeAckError` → **dead-letter** (the
request is rejected; a retry won't help). A **Receiver/Server** fault → `DeliveryError` → **retry**. An
unrecognized fault is treated as permanent (so a rejected request can't loop the lane). With no fault, the
HTTP status decides (2xx delivered, 5xx retry, other 4xx / refused 3xx dead-letter); a connection/timeout
error retries. Fault bodies are **not** echoed into errors/logs (they may carry PHI) — only the fault role
+ HTTP status.

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
| `client_key_password` | — | key passphrase (a **secret** — via `env()`) |
| `ws_security` | `false` | stamp `<wsse:Security>` (a `Timestamp` + optional `UsernameToken`) |
| `ws_username` / `ws_password` | `basic_*` | `UsernameToken` credentials (secrets — via `env()`) |
| `ws_password_type` | `text` | `text` (PasswordText; **recommended over mTLS**) or `digest` (PasswordDigest, computed in `send()`) |
| `ws_addressing` | `false` | stamp `<wsa:Action>` (from `soap_action`), `<wsa:To>` (from `url`), `<wsa:MessageID>` (per-call) |
| `ws_timestamp_ttl_seconds` | `300` | the `Created`→`Expires` window |

**Operational notes (read before going live):**
- **Populate `[egress].allowed_http`.** A WS-\* mTLS destination carries PHI, so its host must be listed
  — and on a **PHI** instance (every built-in env name by default,
  [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)) leaving it
  empty does **not** mean "unrestricted". With no `[egress]` allowlist at all, `serve` refuses to start;
  with any other list set, it flips `[security].block_unlisted_outbound` on and an empty `allowed_http`
  then refuses *every* HTTP destination. Empty-means-unrestricted survives only on a synthetic instance.
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
| `sender` | str / `env()` | — (required) | `From:` address. |
| `recipients` | list[str] / str / `env()` | — (required) | `To:` address(es). |
| `port` | int / `env()` | `587` | `587` = STARTTLS submission; `465` = implicit TLS (`SMTP_SSL`). |
| `subject` | str / `env()` | `""` | Static subject (a per-message subject is a Phase-2 follow-up). |
| `username` | str / `env()` / None | `None` | SMTP `AUTH` user — put the secret in `env()`. |
| `password` | str / `env()` / None | `None` | SMTP `AUTH` password — `env()` only. AUTH is sent **over TLS only**; a cleartext-credential config is refused. |
| `use_tls` | bool | `True` | STARTTLS by default. `False` puts the message **body** (PHI) on the wire in the clear, so it is doubly gated. **The opt-in** is one of exactly two things you can actually set: `MEFOR_ALLOW_INSECURE_TLS` (process-global — it weakens *every* connector in the process, and it is read through the **clamped** check, so it cannot relax an enforcing production-PHI hop), or this connection's `cleartext_accepted = true` with its mandatory `cleartext_reason` (per-hop, audited — see [Declaring a cleartext hop](#declaring-a-cleartext-hop-cleartext_accepted), and prefer it). **And** the hop then goes through the shared authority (#200, ADR 0092 as amended by ADR 0153): loopback ALLOWs, a `cleartext_accepted` hop **WARNs + audits** (never a silent allow), a non-enforcing instance WARNs, everything else REFUSES — **no data label relaxes it**. The engine also honours a connection-level `tls_hop_attested` on this gate, but **no factory keyword and no `connections.toml` key sets it**, so it is not a route you can take — see the note in that section. SMTP AUTH over cleartext stays refused OUTRIGHT, by any route. Matches the raw-TCP / X12 / plaintext-DICOM / anonymous-FTP cleartext egress paths. |
| `timeout_seconds` | float | `30.0` | |
| `encoding` | str | `"utf-8"` | |

The egress host is **gated by `[egress].allowed_smtp`** — add the host or the destination is refused at
config load/reload. On a **PHI** instance (every built-in env name by default,
[ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)) an **empty**
`allowed_smtp` does **not** mean "unrestricted": with no counted `[egress]` allowlist `serve` refuses to
start, and with one set it flips `[security].block_unlisted_outbound` on, so an empty
`allowed_smtp` refuses *every* SMTP destination. Empty-means-unrestricted survives only on a synthetic
instance — see [CONFIGURATION.md `[egress]`](CONFIGURATION.md#egress). (The key is
`[security].block_unlisted_outbound`; `[egress].deny_by_default` moved there under ADR 0118 and is
**rejected at config load**.)

⚠️ **`allowed_smtp` is one of the two lists that does *not* count as "egress is restricted".** The
open-egress startup gate reads only `allowed_mllp`/`allowed_tcp`/`allowed_http`/`allowed_db`/
`allowed_remote`/`allowed_file_dirs`, so a PHI instance whose **only** declared egress is this `Email()`
relay populates `allowed_smtp`, declares its one destination — and still **exits 2** with *"outbound
egress is UNRESTRICTED … refusing to start"*. A mail-only deployment must set
**`[security].block_unlisted_outbound = true`**; that is the arm of the gate it can actually satisfy.
The same is true of `allowed_direct` for a Direct-only instance.
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
# ...and note allowed_smtp alone does NOT satisfy the open-egress startup gate on a PHI instance —
# see CONFIGURATION.md §[egress].
```

### Direct Project — `Direct(...)` (S/MIME over SMTP, outbound send, ADR 0085)

An **outbound destination only** — the Direct Project's trusted-correspondent lane. The Handler produces the
clinical **body** (content-agnostic — an HL7 string, a CDA/XML document, plain text); this connector **SIGNs**
it with the sender's key + cert (authenticity + integrity), **ENCRYPTs** the signed blob to the partner's
`recipient_cert` (confidentiality — sign-then-encrypt, so the signature is itself confidential), and submits
the S/MIME message to `host:port` over STARTTLS SMTP. PHI is therefore protected **end-to-end**, independent
of the transport TLS. Crypto is core `cryptography` (`serialization.pkcs7`) and SMTP is stdlib `smtplib` —
**no new dependency, no extra**.

| Setting | Default | Meaning |
|---------|---------|---------|
| `host` | — (required) | the SMTP / HISP relay host (the `[egress].allowed_direct` key; use `env()`) |
| `sender` | — (required) | the Direct `From:` address |
| `recipients` | — (required) | the Direct `To:` address(es) — a list or a single string |
| `signing_cert` | — (required) | path to the sender's PEM/DER signing **certificate** |
| `signing_key` | — (required) | path to the sender's PEM/DER signing **private key** |
| `signing_key_password` | — | passphrase for an encrypted `signing_key` — a **secret**, via `env()` |
| `recipient_cert` | — (required) | path to the partner's PEM/DER **encryption** certificate (the encryption target) |
| `trust_anchor` | — (required) | path to the PEM/DER CA the `recipient_cert` must chain to |
| `port` | `587` | `587` = STARTTLS submission; `465` = implicit TLS (`SMTP_SSL`) |
| `subject` | `""` | static `Subject` |
| `username` / `password` | — | optional SMTP `AUTH` credentials (secrets — via `env()`) |
| `use_tls` | `true` | STARTTLS by default. `false` is refused unless `MEFOR_ALLOW_INSECURE_TLS` is set, and SMTP `AUTH` over cleartext is **refused outright**. ⚠️ **This is not the same posture as `Email(...)` — the shipped enforcing default does not close it.** `Direct()` consults the **raw** escape variable directly: it does **not** route through the shared cleartext-hop authority, so `[security].enforcement = enforce` does **not** clamp it and `cleartext_accepted` / `cleartext_reason` on the outbound are **not consulted** (declaring them changes nothing here). With the variable set, a cleartext-SMTP Direct hop crosses on a production-PHI enforcing instance. The S/MIME body stays signed + encrypted either way — but the SMTP envelope (sender, recipients, subject) does not. |
| `timeout_seconds` | `30.0` | passed to the `smtplib` constructor (covers connect and each command) |
| `encoding` | `utf-8` | charset the body is encoded with before signing |

**Fail-loud at construction.** Every piece of crypto material is loaded and cross-checked when the connector
is built — so `messagefoundry check` / dry-run / start catches it, never the first message: a malformed
key/cert, a `signing_key` whose public half **does not match** `signing_cert`, and a `recipient_cert` **not
issued by** any supplied `trust_anchor` (PHI is never encrypted to a certificate from an untrusted issuer).
The trust check is deliberately **one level** (the recipient cert chains directly to a supplied anchor, or is
a self-signed correspondent cert pinned as its own anchor) — full multi-level path building is deferred. No
hostname/SAN match is done: a Direct address is an email, not a TLS SNI. Errors name the *setting* only,
never the material or a cert subject (which can identify a patient's provider).

**Delivery semantics.** Egress is gated by **`[egress].allowed_direct`** — kept separate from
`allowed_smtp` so a Direct HISP relay can be permitted without opening the general mail relay. Both an SMTP
failure and an S/MIME **encode** failure raise `DeliveryError`, so the lane **retries** per its
`RetryPolicy`. Delivery is **at-least-once** and a Direct mailbox has no idempotency key, so a rare duplicate
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
# allowed_direct alone does NOT satisfy the open-egress startup gate either: a Direct-only PHI
# instance also needs [security].block_unlisted_outbound = true — see CONFIGURATION.md §[egress].
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
| `interaction` | `create` | `create` (`POST {base}/{ResourceType}`) / `update` (`PUT {base}/{ResourceType}/{id}`) / `transaction` / `batch` (`POST {base}` with a `Bundle`) |
| `conditional` | — | opt-in: `if-none-exist` (conditional create) / `conditional-update` (search-based PUT) / `if-match` (version-aware PUT) |
| `conditional_query` | — | FHIR search params for `if-none-exist` / `conditional-update` (e.g. `identifier=sys\|val`) |
| `headers` | `{}` | extra **static** headers (no secrets — not `env()`-resolved) |
| `bearer_token` | — | `Authorization: Bearer …` (SMART/OAuth — a **secret**, via `env()`) |
| `basic_user` / `basic_password` | — | HTTP Basic auth (secrets — via `env()`) |
| `timeout_seconds` | `30` | per-request timeout |
| `verify_tls` | `true` | TLS cert verification — the same posture-keyed cell as [REST](#rest--rest): `false` is **refused at construction** off loopback, and the `MEFOR_ALLOW_INSECURE_TLS` escape is **clamped inert** while `[security].enforcement = enforce` (the shipped default) |
| `tls_allow_expired` | `false` | **(#129, ADR 0094)** tolerate an **expired** server cert with chain + hostname still verified. **No posture gate, no escape variable, and it is never reported by `security_loosenings()`** — see the [MLLP row](#mllp--mllp) |
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
is in the **URL** query), and `if-match` (optimistic lock on a known id via an `If-Match` ETag derived from
the resource's `meta.versionId`).

**OperationOutcome & delivery semantics.** A 2xx is **delivered** (a returned `OperationOutcome` is captured,
never an error). On an error status the HTTP code decides, refined by the `OperationOutcome`: 5xx → retry; a
4xx whose `issue.code` is in the FHIR **transient** IssueType group (`lock-error`/`throttled`/`timeout`/
`incomplete`), or `408`/`429` → retry; any other 4xx / refused 3xx → **dead-letter**. The HTTP status wins
when in doubt (a 5xx stays transient). `OperationOutcome`/reply bodies are **not** echoed into errors/logs
(they may carry PHI) — only the HTTP status + a redacted URL.

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

| `with_smart_backend(...)` arg | Default | Notes |
|---|---|---|
| `token_url` | — (required) | the authorization server's token endpoint (`https`; `env()`). **Also gated by `[egress].allowed_http`** — it is a second egress host. |
| `client_id` | — (required) | the registered client id (`iss`/`sub` of the assertion; `env()`) |
| `private_key` | — (required) | the assertion signing key as inline PEM (via `env()`) or a PEM file path |
| `algorithm` | `RS384` | `RS384` (RSA) or `ES384` (ECDSA P-384) — the two SMART **SHALL**-support algorithms |
| `scope` | `None` | the requested scopes, e.g. `system/*.rs` (SMART v2 system scopes — no human) |
| `key_id` | `None` | the JWT `kid` → the public key registered with the server (for rotation) |
| `audience` | = `token_url` | the assertion `aud`, if the server documents a different audience |
| `private_key_password` | `None` | passphrase for an encrypted key (secret — use `env()`) |
| `expiry_skew_seconds` | `60` | re-mint this many seconds before the server's stated expiry |

```python
from messagefoundry import FHIR, env, outbound
from messagefoundry.transports.smart import with_smart_backend

# Push FHIR to a SMART-secured server (Epic / Oracle Health).
outbound("FHIR-OUT_EPIC", with_smart_backend(
    FHIR(url=env("epic_fhir_base"), interaction="create"),
    token_url=env("epic_token_url"),     # add this host to [egress].allowed_http too
    client_id=env("epic_client_id"),
    scope="system/*.rs",
    private_key=env("epic_smart_key"),   # inline PEM via env(), or a PEM file path
    algorithm="RS384",
    key_id="epic-2026",
))
```

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
`pydicom>=3.0.2,<4` + `pynetdicom>=3.0.4,<4`, pure-Python, no numpy), lazily imported; **DICOMweb needs no
extra** (it stores the object as opaque bytes over the shared `rest.py` HTTP plumbing). Still out of scope:
MWL, Query/Retrieve (C-FIND/C-MOVE/C-GET), and pixel-data handling.

| Setting | Default | Meaning |
|---------|---------|---------|
| `ae_title` | — (required) | this engine's Application Entity title — the SCP AE a peer C-STOREs to |
| `port` | `104` | bind port (104 is the registered DICOM port; use e.g. `11112` for a non-privileged dev bind) |
| `presentation_contexts` | `None` → SR + common image storage + Verification | the SOP classes the SCP negotiates (transfer syntaxes default to the standard set) |
| `calling_ae_allowlist` | `None` → any (subject to the IP gate) | only these calling AE titles may associate (fail-closed when set) |
| `require_called_ae_title` | `True` | a peer must address this engine's `ae_title` as the called AE |
| `max_object_bytes` | `134217728` (128 MiB) | reject a single C-STORE object larger than this **before** the durable commit (OOM/DoS guard) |
| `max_associations` | `10` | cap on concurrent inbound associations (connection-flood guard) |
| `max_pdu_size` | `16384` | cap one PDU's bytes (`0` = unbounded); DoS guard |
| `timeout_seconds` | `30.0` | ACSE/DIMSE/network timeout |
| `tls` | `false` | wrap the association in **DICOM-over-TLS** (required for a non-loopback bind — see below) |
| `tls_cert_file` / `tls_key_file` | — | the SCP's server-identity cert + private key (required when `tls=true`) |
| `tls_key_password` | `None` → unencrypted key | passphrase for a PKCS#8-encrypted `tls_key_file` (`env()`-sourced, mirroring MLLP's `MEFOR_*_TLS_KEY_PASSWORD`). An encrypted key supplied with **no/wrong** passphrase **fails fast** at startup/`check` rather than hanging on an interactive TTY prompt (there is no TTY under an NSSM service account / in a container). |
| `tls_ca_file` | — | opt-in **mTLS**: require + verify a calling peer's client certificate |

The **bind interface** is the service-level `[inbound].bind_host` (or a per-connection `bind_address`) and the **peer-IP gate** is the per-connection **`source_ip_allowlist`** — both are set on the `inbound(...)` call, not as `DICOM()` arguments. ⚠️ **`source_ip_allowlist` is *not* a key of the `[inbound]` section in `messagefoundry.toml`.** That section carries only `bind_host`, `ack_after` and `stream_inflight_budget_bytes`, and every settings section is pydantic `extra="ignore"` — so writing `source_ip_allowlist` under `[inbound]` in the service TOML is **accepted silently and does nothing**. (Verified: `InboundSettings.model_fields` is exactly those three; a loaded `[inbound].source_ip_allowlist` leaves no attribute behind, while a sibling `bind_host` survives.) `bind_address` is the same story — a per-connection keyword, not a `[inbound]` key. The reachable forms are `inbound("IB_…", DICOM(...), source_ip_allowlist=["10.20.0.0/16"])` and, for the transports available as data, the **top-level** `source_ip_allowlist` key in `connections.toml` (shown in the [`connections.toml` example](#connections-as-data--connectionstoml-adr-0007) above) — `DICOM()` is code-first only, so for a SCP it is the `inbound(...)` keyword. A non-loopback cleartext SCP is **refused at startup** unless `tls=true` (the generalized [cleartext] bind-guard — `check_dimse_tls_exposure`). `serve --allow-insecure-bind` downgrades that refusal to a warning, but the flag is **clamped** exactly as it is for the MLLP/HTTP/TCP listeners: on a PHI-classified instance under the default `[security].enforcement = enforce` the bind is refused *even with it*, so on a stock instance `tls=true` is the only way to bind off-loopback. (`host` / `called_ae_title` / `connect_timeout` on `DICOM()` are for the **Phase-2 outbound SCU** and are unused by the inbound SCP.)

> **Fail-closed peer controls (deny-by-default).** DICOM has no transport authentication on its own, so a **non-loopback** SCP **MUST** set a **verifiable** peer control — either a per-connection `source_ip_allowlist` (an `inbound(...)` keyword — **not** a `[inbound]` service-TOML key, see the ⚠️ above), or **mTLS** (`tls=true` **and** `tls_ca_file`, which makes the SCP require + verify a client cert). With **neither** set, a non-loopback SCP is **refused at construction** (the connection degrades per ADR 0031 startup fault isolation; surfaced under `check`/dry-run). This is the **authentication** analog of the `check_dimse_tls_exposure` cleartext bind-guard above (which is the orthogonal **confidentiality** guard): TLS-without-mTLS encrypts the channel but does **not** authenticate the peer. A **loopback** bind (`127.0.0.1`/`localhost`/`::1`, the common dev/single-box case) is exempt.
>
> ⚠️ **`calling_ae_allowlist` does not satisfy this gate on its own (BACKLOG #316).** It used to: the three controls were counted as co-equal. But a Calling AE Title is a string the caller asserts about **itself** in the association request — no key, no signature, nothing to verify — and AE Titles are published in conformance statements and visible in any capture. An SCP whose only control was an AE-title list was reachable by anyone who could route to it and knew one string, while passing a check named "fail-closed peer controls". **Keep it — it is still enforced at association time and is a genuinely useful filter** (it catches a misrouted sender and pins intent). It simply has to be **paired** with `source_ip_allowlist` or mTLS off-loopback.
>
> ⚠️ **The construction gate counts controls, so the wrong spelling passes it.** Set
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
the whole point of the ⚠️ above. Without a `bind_address` (or a non-loopback `[inbound].bind_host` in
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
| `tls` / `tls_ca_file` / `tls_cert_file` / `tls_key_file` | `false` / — | **DICOM-over-TLS**: verify the peer's server cert (`tls_ca_file` pins the anchor); `tls_cert_file`/`tls_key_file` opt into **mTLS**. There is **no `tls_verify=false`** on this connector — chain and hostname are always verified. It also carries **no revocation gate** (unlike MLLP/REST/SOAP/FHIR/DICOMweb/EMAIL), so `tls=true` here is *not* refused on a stock instance — and a revoked PACS certificate is your PKI's problem, not the engine's |
| `tls_allow_expired` | `false` | **(#129, ADR 0094)** tolerate an **expired** PACS certificate with chain + hostname still verified. Combined with the missing revocation gate above, this hop can be pinned to a certificate that is **both expired and revoked** with nothing refusing, warning at posture level, or reporting it — **no posture gate, no escape variable, and `security_loosenings()` never reports it** (see the [MLLP row](#mllp--mllp)) |
| `tls_key_password` | `None` → unencrypted key | passphrase for a PKCS#8-encrypted mTLS-client `tls_key_file` (`env()`-sourced). Same fail-fast semantics as the inbound SCP (no/wrong passphrase raises at construction, never a TTY hang). |

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
| `headers` | `{}` | static extra headers (no secrets — not `env()`-resolved) |
| `timeout_seconds` | `30.0` | request timeout |
| `verify_tls` | `true` | TLS cert verification — the same posture-keyed cell as [REST](#rest--rest): `false` is **refused at construction** off loopback, and the `MEFOR_ALLOW_INSECURE_TLS` escape is **clamped inert** while `[security].enforcement = enforce` (the shipped default). **`DICOMweb()` has no `tls_allow_expired`** — it reuses the REST client but does not read that setting, so a DICOMweb hop always enforces certificate expiry |
| `capture_response` | `false` | capture the STOW-RS `dicom+json` response as a reply (ADR 0013) |

**Status classification.** A 2xx whose `dicom+json` body carries a per-instance **FailedSOPSequence**
(`00081198`) → the instance was rejected → permanent dead-letter; a 409 (all instances failed) / other 4xx /
a refused 3xx → permanent; 5xx / 408 / 429 / connection-timeout → transient retry. **PHI:** the response can
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

A fourth route exists in the engine but has **no authoring surface on a connection today**:
`tls_hop_attested` ("this hop *is* secure by means the engine cannot see" — proxy-terminated TLS, a
genuinely isolated segment) yields a silent ALLOW, but no transport factory takes it and it is not a
`connections.toml` key, so you cannot set it on an inbound or outbound. Do **not** reach for it; use
`cleartext_accepted`. (The `[logging].forward_hop_attested` sibling in `messagefoundry.toml` *is*
settable — see [CONFIGURATION.md](CONFIGURATION.md).)

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

Four facts that are easy to get wrong, stated plainly first:

- **The MLLP, raw-TCP, X12 and HTTP listeners have no accept-rate throttle.** The bound is
  `max_connections` (default 256)
  and nothing paces the accept rate. Past the cap the client's TCP connection **is** accepted by the
  asyncio server and then **immediately refused and closed at the application layer**; the
  active-client counter is never incremented for the refused peer. The peer therefore observes a
  successful connect followed by an immediate close — not a refused connect and not a backlog wait.
  A peer failing `source_ip_allowlist` is refused the same way. **The telemetry is not uniform:** the
  **MLLP, raw-TCP and HTTP** listeners emit an ADR 0021 `at_capacity` (and `peer_not_allowlisted`)
  connection_event; the **X12 and DICOM** listeners refuse identically but emit **no connection event
  at all** — `transports/x12.py` and `transports/dicom.py` contain zero `_emit_event` call sites. Nor
  is the fallback uniform: X12's `source_ip_allowlist` refusal is a logged warning
  (`transports/x12.py:310-312`), but its **`max_connections` refusal is entirely silent** — `:314-315`
  returns with no event and no log, so a partner failing at capacity leaves **no engine-side evidence
  of any kind**. Treat that gap as the thing to watch when sizing an X12 feed, not the counter.
  The slow-loris guard is the **separate**
  `receive_timeout` (default 60 s), not `max_connections`; the HTTP listener additionally answers a
  synchronous `408` when a request read exceeds it.
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
  15 s, emitted as the ODBC DSN `Connection Timeout` — a **login** timeout only), `pool_max` and
  `acquire_timeout`, and there is **no** `timeout_seconds` on this connector. A long-running
  statement is therefore unbounded; keep lookup/write statements indexed and narrow. (The *store's*
  own SQL Server / Postgres connections do apply `[store].command_timeout`, default 30 s.)
- **The store's connection pool has no acquire timeout on either server backend.** Both the SQL
  Server and Postgres stores call `pool.acquire()` with no timeout argument; the borrow is bounded
  by `[store].pool_size` (default 40) plus the warm-pool pre-open (`[store].warm_pool`, timeout
  `[store].warm_pool_timeout` default 15 s), not by an acquire deadline. The `timeout=` the Postgres
  backend hands `asyncpg.create_pool` is a pool-construction parameter carrying
  `[store].connect_timeout`; it is **not** relied on here as a bound on waiting for a free
  connection. **SQLite is the same shape at a smaller scale** — its four-connection read pool
  (`_READ_POOL_SIZE`) is borrowed with `await pool.get()`, which carries no deadline either.

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
REMOTEFILE (SFTP/FTP/FTPS) exposes **no** timeout argument — the 30 s whole-socket value is a hard-coded module fallback in `transports/remotefile.py`, not operator-configurable;
DATABASE exposes `connect_timeout` + `acquire_timeout` and no statement timeout; local FILE exposes
none (filesystem I/O is unbounded by design). The MLLP/TCP/X12/HTTP listeners expose
`receive_timeout`; the DICOM SCP instead applies `timeout_seconds` to its three pynetdicom timers. For
**synchronous** request→response feeds (REST/SOAP, X12 270/271) set a **short** `timeout_seconds`.

**Retry strategy (13.1.3).** Delivery failures retry per the connection's `RetryPolicy`. **Note the
default `retry_max_attempts` is `None` = retry forever** (with backoff: `retry_backoff_seconds` 5 s,
multiplier 2.0, capped at 300 s). Under strict FIFO a forever-retrying head blocks its lane until it
succeeds or an operator purges it. For synchronous HTTP (REST/SOAP) **set a finite
`retry_max_attempts` and a short `timeout_seconds`** to prevent cascading delays / resource
exhaustion; failures classified *permanent* (e.g. an MLLP `AR` reject) go straight to the
dead-letter path rather than retrying. **Every infrastructure hop in Table B that performs a
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
work on **three** distinct thread pools, plus `aiosqlite`'s per-connection worker thread on the SQLite
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
   - **Unbounded-by-design file I/O** — local FILE and SFTP/FTP/FTPS channel reads and writes, whose
     "timeout" posture is stated honestly per row in Table B.
   - **Inbound strict validation** — the listener runs `hl7apy` strict validate off-loop via
     `asyncio.to_thread` (`pipeline/wiring_runner.py:3259`, `:3543`), bounded by the per-inbound
     `validation.strict_timeout_s` (engine default `_STRICT_VALIDATE_TIMEOUT_SECONDS` = **5 s**,
     `wiring_runner.py:285`). The timeout frees the *listener* but cannot kill the worker — an
     orphaned validate holds its thread until it returns, bounded in turn by the 16 MiB / segment
     caps enforced before it.
   - **The store's own SQL Server I/O** — `aioodbc.create_pool()` is built with **no** `executor=`
     (`store/sqlserver.py:1953`), so every store statement is dispatched onto **this** pool via
     `loop.run_in_executor(None, …)`; on a SQL Server deployment that makes the store the pool's
     dominant consumer. Its release bound is `[store].command_timeout` (**30 s**), set as a pyodbc
     connection attribute per acquire. Postgres (`asyncpg`) is loop-native and uses no thread; SQLite
     instead runs each `aiosqlite` connection on its **own dedicated thread**, outside every pool
     listed here.
2. **Two per-stage fusing executors**, each `[pipeline].pooled_fusing_workers` wide (**default 8**),
   built only under `[pipeline].fuse_thread_hops` (**default `false`**, SQL Server + `pooled` claim mode
   only, ADR 0071 B5). Under fusion the fused stage's route/transform body runs on *these* pools, not
   the default one, so the fused-stage concurrency is that value.
3. **One dedicated single-worker `ThreadPoolExecutor` per alternate-credential File endpoint**
   (`transports/wincred.py`, `mefor-filecred`). Impersonation must never leak onto a shared pool, so
   this work is deliberately **not** on the default executor — and it carries **no engine-owned
   timeout**: a wedged share pins that endpoint's one thread indefinitely. It cannot starve the shared
   pool, which is the mitigating half.

At saturation further `to_thread` calls **queue on the executor rather than failing**. So the release
mechanism differs per class: a timeout for the bounded hops, the 5 s strict-validate backstop and
`[store].command_timeout` for the store hop, cooperative cancellation on stop for the workers, and —
for the Router/Handler and the SMB worker — nothing but a restart.

### Table A — concurrency limits & behaviour at the limit (ASVS 13.1.2 / 13.2.6)

| Service/hop | Concurrency bound (setting + default) | Behaviour when the limit is reached | Fallback / recovery |
|---|---|---|---|
| MLLP listener (inbound) | `max_connections` default 256 concurrent clients | connection accepted, then immediately refused and closed with an `at_capacity` connection_event; the counter is not incremented | the peer reconnects; a slot frees as soon as any client finishes or trips `receive_timeout` |
| MLLP destination | 1 in-flight delivery per outbound connection (`per_lane`), else the `pooled_max_processing_lanes` budget | a lane waits for a slot; the socket itself is per-delivery unless `persistent=true` | transient failure re-queues into the `RetryPolicy` path; a stale persistent connection is not reused past `idle_timeout_seconds` |
| Raw TCP listener (inbound) | `max_connections` default 256 concurrent clients | accepted then immediately refused and closed with an `at_capacity` connection_event | as MLLP |
| X12 listener (inbound) | `max_connections` default 256 concurrent clients | connection accepted, then immediately refused and closed at the application layer; the active-client counter is not incremented. **No ADR 0021 connection_event is emitted** — `transports/x12.py` emits none at all; an allow-list refusal is a logged warning only, and the at-capacity path emits **no log line either** | as MLLP |
| Raw TCP / X12 destination | as MLLP destination — one delivery per outbound lane | a lane waits for a processing slot; a fresh connection is dialled per delivery | transient failure re-queues into the retry path |
| HTTP web-service listener (inbound) | `max_connections` default 256; `max_header_bytes` 64 KiB and `max_body_bytes` 16 MiB bound one request | at capacity the connection is accepted then refused and closed (`at_capacity`); an over-declared `Content-Length` is refused before buffering; a slow read gets a synchronous `408` | the partner retries; slots free on completion or `receive_timeout` |
| File endpoint — local filesystem | one poll worker per inbound connection; one delivery lane per outbound | no connection limit exists — the bound is the poll interval `poll_seconds` (default 1.0) and `max_file_bytes` (16 MiB) | an oversize or unreadable file is skipped/errored and left for the operator; the next poll continues |
| File endpoint — UNC / SMB share | as local File, plus one dedicated impersonation worker thread per endpoint | the OS redirector queues; no engine-side cap | an SMB failure surfaces as a transient delivery/poll error and re-queues |
| SFTP (remote-file) | one session per poll or per delivery — no session pool | sessions are serialized by the lane budget; there is no server-side connection cap the engine enforces | a refused/limited server surfaces as a transient error and re-queues per `RetryPolicy` |
| FTP / FTPS (remote-file) | one session per poll or per delivery — no session pool | as SFTP | as SFTP |
| Reference-set sync (`FileRef`) | one read per set per `refresh_seconds` pass (default 3600); no concurrency knob — the OS / SMB redirector queues on a UNC path | a slow or unreachable path stretches that set's sync; the sync is isolated per reference set | the previous encrypted snapshot keeps serving reads |
| REST destination | no per-connection HTTP connection cap exists; the indirect bound is `[pipeline].pooled_max_processing_lanes` (default 256) | requests queue behind the lane budget; the backend's own 429/503 is classified transient | transient → `RetryPolicy` with backoff; permanent → dead-letter |
| SOAP destination | as REST — indirect via the lane budget | as REST | as REST |
| FHIR destination + `fhir_lookup` | as REST; `fhir_lookup` additionally runs off the event loop on the thread executor | as REST; a lookup that cannot run raises into the Handler | transient → retry; a `fhir_lookup` failure fails the message, never silently degrades |
| DICOMweb STOW-RS destination | as REST — indirect via the lane budget | as REST | as REST |
| DICOM C-STORE SCP (inbound) | `max_associations` default 10; `max_pdu_size` 16384; `max_object_bytes` 128 MiB | over the association cap pynetdicom rejects the association; an over-cap object gets a DIMSE failure **before** the durable commit | the modality re-sends; nothing is half-committed |
| DICOM C-STORE SCU / C-ECHO | one association per delivery, bounded by the lane budget | the association request fails on `connect_timeout` | out-of-resources status → retry; a hard refusal → dead-letter |
| EMAIL (SMTP) destination | one SMTP connection per send, bounded by the lane budget | the relay's own limit surfaces as an SMTP error | transient → retry; permanent → dead-letter |
| DIRECT (S/MIME over SMTP) | one SMTP connection per send, bounded by the lane budget | as EMAIL | as EMAIL |
| DATABASE destination / poll source / `db_lookup` | `pool_max` default 5 connections per connection definition | a borrow that cannot be satisfied within `acquire_timeout` (default 30 s) fails **transiently** with a PHI-free "pool exhausted or DB unresponsive" error | the row re-queues into the `RetryPolicy` path; the pool self-heals as borrows return |
| Reference-set sync (`DatabaseRef`) | `pool_max` default 5, in a **throwaway pool built per sync** | **`DatabaseRef` exposes no `acquire_timeout` and its borrow is not wrapped** — this is the one remaining unbounded connector-tier pool acquire | the sync task is isolated per reference set; a wedged sync leaves the previous snapshot serving reads |
| Internal sources — Timer / Loopback / PassThrough | n/a — they open no socket and reach no external system | n/a | n/a |
| Engine API + `/ui` + `/ws/stats` (`[api].port`) | uvicorn's own defaults (no `limit_concurrency` / `timeout_keep_alive` is passed); per-actor 429 throttles bound abuse: login 10 per IP and 60 global per 60 s, PHI reads 120 per actor per 60 s, admin writes 12 per actor per second | over a throttle the request gets `429` and an audit row; the connection stays usable | the caller backs off; the window rolls |
| Reverse proxy → engine segment (`[api].trusted_proxies`) | bounded by the proxy's own connection limits — the engine sets none on this hop | whatever the proxy does at its limit; the engine sees fewer connections | operator-owned (proxy config) |
| Store — SQLite (`[store].backend = sqlite`) | one writer connection plus a **bounded read pool of 4** read-only WAL connections (`store/store.py` `_READ_POOL_SIZE`; deliberately not a setting); no network | writes serialize behind the single writer lock; a read that finds all four borrowed **waits on the pool queue with no deadline** (`await pool.get()`), and lock contention inside SQLite waits out `PRAGMA busy_timeout` 5000 ms | the borrow is returned in `finally`; every pooled connection is closed on store close |
| Store — SQL Server (`[store].backend = sqlserver`) | `[store].pool_size` default 40, pre-warmed by `[store].warm_pool` | **no acquire timeout** — a borrow waits for a free connection; sizing plus the warm pool is the bound | a wedged pool surfaces as stalled stage workers; restart re-opens the pool and `reset_stale_inflight` recovers in-flight rows |
| Store — Postgres (`[store].backend = postgres`) | `[store].pool_size` default 40 (`asyncpg` `max_size`) | as SQL Server — the engine passes **no timeout** to `pool.acquire()`; the `timeout=` given to `asyncpg.create_pool` is a pool-construction parameter, not an engine-owned acquire deadline | as SQL Server |
| Active Directory — login binds (`[auth].ad_server`) | one `authenticate()` = **two sequential binds** plus 1–2 SUBTREE searches; concurrency is bounded by the API login rate limiter and the thread executor | at the login limiter the request gets `429`; a DC that is at capacity fails the bind | the login fails closed with `LdapError`; the user retries |
| Active Directory — session reconciler (`ad_session_recheck_seconds`) | one bind per signed-in directory user per pass, capped by `ad_session_recheck_max_users` (200); interval floored at 60 s | the remainder is deferred to later passes (least-recently-probed first), degrading to a longer effective interval rather than a bind storm | the mass-revoke breaker (`ad_session_revoke_max` 5 **and** `ad_session_revoke_max_fraction` 0.34) aborts a pass that would revoke too much |
| Kerberos / SPNEGO SSO (`kerberos_spn`) | no engine socket — one SPNEGO server step per login against the OS provider | the OS provider's own limits apply | a failed step is an audited login reject; a boot preflight degrades SSO legibly when no provider exists |
| OIDC IdP — token endpoint (`oidc_token_endpoint`) | one POST per login, bounded by the login rate limiter | the IdP's own limit surfaces as an HTTP error | the login fails closed; the user retries |
| OIDC IdP — JWKS fetch (`oidc_jwks_uri`) | one GET per cache miss, bounded by `oidc_jwks_ttl_seconds` (3600) and the amplification floor `oidc_jwks_min_refetch_seconds` (300) | a refetch inside the floor is not made; the cached key set is used | a fetch failure fails the verification closed |
| SMART token endpoint (`smart_token_url`) | one POST per token mint; the token is cached until expiry minus `smart_expiry_skew_seconds` | the delivery fails and re-queues | re-minted on the next attempt or on a `401` via `invalidate()` |
| OAuth2 token endpoint (`oauth2_token_url`) | one POST per token mint, cached the same way | the delivery fails and re-queues | re-minted on the next attempt or on a `401` |
| AI broker (`[ai].endpoint`) | one POST per assist request; bounded at the API route by the `ai:assist` RBAC gate, the fail-closed `[ai].allowed_endpoints` SSRF allow-list and the 60 s per-request timeout. **There is NO per-actor pacing on `POST /ai/chat`** — it depends on plain `require(Permission.AI_ASSIST)`, not `require_paced`/`require_step_up`, so a holder of `ai:assist` can loop assist POSTs unthrottled | the LLM's own 429/503 surfaces as an `AiBrokerError` → HTTP `502` to the caller | the assist call fails; nothing is queued or retried |
| DR backup destination (`[backup].destination`, ADR 0049) | **one writer** — leader-gated under `[cluster].enabled`, so exactly one node writes the shared destination; once per `schedule_at` pass plus any on-demand run. No engine-side cap: the OS/SMB redirector queues | a slow or full destination stretches the run; nothing is dropped and the next scheduled pass still fires | a failed or verify-failed run is logged + audited and is **never** counted as a good backup when pruning to `retention_keep` |
| Vault Transit — store DEK unwrap (`MEFOR_STORE_VAULT_ADDR`, `[store].key_provider = vault`, ADR 0019) | one HTTPS request per DEK unwrap (startup / rotation), not per message | a failure is fail-closed — the store does not open | operator fixes Vault and restarts |
| Vault Transit — bulk at-rest cipher (`MEFOR_STORE_TRANSIT_KEY`, `[store].cipher_provider = vault_transit`, ADR 0138) | **one synchronous HTTPS round trip per encrypted CELL** on every store write and read, plus one `generate_hmac` per audit row; issued **on the event loop** (`_enc`/`_dec` are sync, with no `to_thread`). No concurrency cap of its own — the effective bound is the stage/lane budget | Vault's own rate limit or a slow Transit **stalls the event loop across the whole engine**; a per-operation failure raises `CipherError` and the stage errors/dead-letters that row | the store stays open; the row is retried by the normal stage re-claim |
| Vault KV v2 (`MEFOR_SECRETS_VAULT_ADDR`) | one HTTPS request per secret resolution at config load / connector construction | fail-closed — the connection refuses to build | operator fixes Vault and reloads |
| Alerts — SMTP sink (`[alerts].email_smtp_host`) | one connection per send, serialized on **its own** background drain task behind **its own** bounded 1000-item queue | over-cap events are **dropped with a warning** rather than growing the queue | a send failure is swallowed + logged; the alert is not retried |
| Alerts — per-user security-event email (`[auth].notify_security_events`) | one connection per notification, serialized on a **second, independent** drain task with its **own** bounded 1000-item queue — so the SMTP relay sees up to **two** concurrent sessions from this engine, not one | at cap the event is **dropped with a warning**; the audited `GET /me/security-events` feed still records it | the send failure is swallowed + logged, never propagated onto the login or admin path; recovery is the pull feed |
| Alerts — webhook sink (`[alerts].webhook_url`) | one POST per event on the same single drain task and the same bounded 1000-item queue | as the SMTP sink — over-cap events are dropped with a warning | best-effort; a failure is swallowed + logged, never retried |
| Syslog forwarder (`[logging].forward_host`) | a **single** socket, synchronous send, one record at a time | a stalled collector costs at most the socket timeout per record and the record is then **dropped** | an unreachable collector at startup is skipped with a warning and the service still starts |
| SNTP clock-sync probe (`[logging].ntp_peer`) | exactly **one** datagram per process start; never on the message path | a silent peer raises `socket.timeout` | skew beyond `time_sync_max_skew_seconds` warns loudly, or refuses to start under `time_sync_fail_closed` |
| Forward / egress web proxy (`[egress].proxy_url`) | no separate bound — the proxied request occupies the destination connector's own lane | the proxy's own limit surfaces as an HTTP error on the destination request | handled by the destination's retry policy |
| Loopback ECH sidecar (`ech_sidecar`) | one loopback request per destination request; no separate bound | the sidecar's own limit surfaces as an HTTP error | handled by the destination's retry policy; misconfiguration fails closed at build |

### Table B — per-service resource strategy (ASVS 13.1.3)

| Service/hop | Timeout setting + default | Release procedure | Failure handling | Retry posture |
|---|---|---|---|---|
| MLLP listener (inbound) | `receive_timeout` 60 s bounds an idle read (slow-loris) | the client handler's outer `finally` closes the writer, with a 5 s shutdown grace | a decode/parse/validate failure NAKs synchronously and records `ERROR` before any ingress row | n/a — the sender retries |
| MLLP destination | `connect_timeout` 10 s, `timeout_seconds` 30 s (drain + ACK read) | the socket is closed per delivery, or reused and aged out via `idle_timeout_seconds` / `max_connection_age_seconds` when `persistent` | transient errors re-queue; a `NegativeAckError` (AR) dead-letters immediately | `RetryPolicy` — **default `retry_max_attempts` is unset = retry forever**; set a finite limit |
| Raw TCP listener (inbound) | `receive_timeout` 60 s | as MLLP — handler `finally` closes the socket with a shutdown grace | parse failures record `ERROR` on the ingress path | n/a |
| X12 listener (inbound) | `receive_timeout` 60 s; `max_interchange_bytes` bounds one ISA/IEA frame | as MLLP — handler `finally` closes the socket with a shutdown grace | parse failures record `ERROR` on the ingress path; an allow-list refusal is **log-only** (no connection_event) and a **capacity refusal is silent — no event and no log** | n/a |
| Raw TCP / X12 destination | `connect_timeout` 10 s, `timeout_seconds` 30 s | a fresh connection per delivery, closed in `finally` | transient vs permanent classification as MLLP | `RetryPolicy` |
| HTTP web-service listener (inbound) | `receive_timeout` 60 s bounds the **whole** request read; over budget returns `408` | handler `finally` closes the connection with a shutdown grace | an over-size body is refused before buffering | n/a |
| File endpoint — local filesystem | **none** — filesystem I/O is unbounded by design | file handles are context-managed; the source file is moved/deleted/left per `after_read` | an unreadable/oversize file is skipped or moved to `error_subdir` | `RetryPolicy` on the outbound write |
| File endpoint — UNC / SMB share | **none engine-owned** — bounded only by the OS SMB redirector | the impersonation token is reverted (`RevertToSelf`) and the worker thread is per-endpoint isolated | a share failure surfaces as a transient poll/delivery error | `RetryPolicy` |
| SFTP (remote-file) | 30 s on the **TCP connect only** — the hard-coded module fallback in `transports/remotefile.py` is passed to `paramiko.SSHClient.connect(timeout=…)`. The SSH banner and auth legs ride paramiko's own defaults (the engine sets neither `banner_timeout` nor `auth_timeout`), and the SFTP **channel read/write has no timeout at all**, so a server that stalls after connect blocks its `to_thread` worker until the engine restarts. `Sftp()` exposes no timeout argument, so none of this is operator-configurable | the `paramiko` session is closed in `finally` per poll or delivery | SSH failures map to transient | `RetryPolicy` |
| FTP / FTPS (remote-file) | 30 s **whole-socket** — the same hard-coded module fallback, handed to `ftplib.FTP_TLS(timeout=…)` / `ftplib.FTP(timeout=…)`, which sets it on the control **and** data connections. `Ftp()` exposes no timeout argument, so it is **not** operator-configurable | the `ftplib` session is closed in `finally` per poll or delivery | `ftplib.all_errors` maps to transient | `RetryPolicy` |
| Reference-set sync (`FileRef`) | **none engine-owned** — filesystem / SMB-redirector I/O, the same posture as the File connector | the file handle is context-managed and closed per pass | a load error is logged and the previous encrypted snapshot is retained | one attempt per `refresh_seconds` (default 3600) — **no inner retry** |
| REST destination | `timeout_seconds` 30 s — the **only** timeout (no separate connect timeout on the HTTP family) | the `urllib` response is context-managed and closed per request | HTTP status is classified transient vs permanent; redirects are never followed | `RetryPolicy`; **set a finite `retry_max_attempts` + a short `timeout_seconds` for synchronous feeds** |
| SOAP destination | `timeout_seconds` 30 s | as REST | as REST | as REST |
| FHIR destination + `fhir_lookup` | `timeout_seconds` 30 s on both (the lookup carries its own per-connection value), plus the same 30 s Handler-side result bridge (`pipeline/wiring_runner.py::_LOOKUP_RESULT_TIMEOUT_SECONDS`) that releases the transform worker without cancelling the in-flight request | as REST; the lookup runs on the thread executor and returns the connection immediately | a lookup failure raises into the Handler and fails the message — never a silent empty result | destination: `RetryPolicy`. `fhir_lookup`: **single-shot, no retry** |
| DICOMweb STOW-RS destination | `timeout_seconds` 30 s | as REST | STOW-RS status classified transient vs permanent | `RetryPolicy` |
| DICOM C-STORE SCP (inbound) | `timeout_seconds` 30 s applied to **all three** pynetdicom timers (ACSE, DIMSE, network) and to the off-loop commit future | the association is released by pynetdicom; the AE is shut down cooperatively on stop | an over-cap object fails the DIMSE operation before the durable commit | n/a — the modality re-sends |
| DICOM C-STORE SCU / C-ECHO | `timeout_seconds` 30 s on the three AE timers, `connect_timeout` 10 s on the association request | the association is released after each C-STORE, off the event loop | out-of-resources → transient; hard refusal → permanent | `RetryPolicy` |
| EMAIL (SMTP) destination | `timeout_seconds` 30 s passed to the `smtplib` constructor (covers connect and each command) | the SMTP session is closed per send | SMTP errors classified transient vs permanent | `RetryPolicy` |
| DIRECT (S/MIME over SMTP) | `timeout_seconds` 30 s on the `smtplib` constructor | as EMAIL; key/cert material is loaded once at construction | as EMAIL | `RetryPolicy` |
| DATABASE destination / poll source / `db_lookup` | `connect_timeout` 15 s (DSN **login** timeout only) and `acquire_timeout` 30 s on the pool borrow — **no per-statement timeout exists on this connector**. For `db_lookup` there is additionally a 30 s Handler-side **result bridge** (`pipeline/wiring_runner.py::_LOOKUP_RESULT_TIMEOUT_SECONDS`) that releases the transform worker; it does **not** cancel the statement, which completes on the loop and only then releases its connection | every acquire is paired with a `pool.release()` in `finally`; the pool is closed on connection stop | an acquire expiry raises a **transient** PHI-free `DeliveryError`; SQLSTATE drives transient vs permanent | `RetryPolicy`. `db_lookup` itself is **single-shot** — it raises into the Handler |
| Reference-set sync (`DatabaseRef`) | `connect_timeout` 15 s; **no `acquire_timeout` — the borrow is unbounded** | the connection is released and the throwaway pool closed in nested `finally` blocks | a sync error is logged and the previous snapshot keeps serving | one attempt per `refresh_seconds` (default 3600) — **no inner retry** |
| Internal sources — Timer / Loopback / PassThrough | n/a — no socket, no timeout | the worker task is cooperatively cancelled on stop | n/a | n/a |
| Engine API + `/ui` + `/ws/stats` (`[api].port`) | uvicorn defaults (the engine passes no `timeout_keep_alive`) | the ASGI lifespan calls `engine.stop()`, cancelling every worker | throttled requests get `429` + an audit row | n/a — the caller retries |
| Reverse proxy → engine segment (`[api].trusted_proxies`) | **none the engine owns** — the proxy's timeouts govern | connection lifetime is the proxy's | operator-owned | n/a |
| Store — SQLite (`[store].backend = sqlite`) | `PRAGMA busy_timeout` 5000 ms on the writer and on every read-pool connection; **the pool borrow itself carries no timeout**; no network timeout applies | connections are closed on store close | a busy database retries inside the store layer | n/a |
| Store — SQL Server (`[store].backend = sqlserver`) | `[store].connect_timeout` 15 s (DSN login) and `[store].command_timeout` 30 s applied per acquire as the pyodbc connection attribute; `[store].warm_pool_timeout` 15 s bounds the warm-up | every acquire releases back to the pool; the pool is closed on shutdown | a driver error propagates to the stage worker and the row stays claimable | stage handoffs re-run idempotently; `reset_stale_inflight` recovers on restart |
| Store — Postgres (`[store].backend = postgres`) | `[store].connect_timeout` 15 s (`create_pool(timeout=…)`) and `[store].command_timeout` 30 s as `asyncpg`'s per-statement bound | as SQL Server | as SQL Server | as SQL Server |
| Active Directory — login binds (`[auth].ad_server`) | `[auth].ad_connect_timeout` 10 s on the LDAP TCP connect and `[auth].ad_receive_timeout` 10 s on every LDAP response read — threaded into **every** `ldap3` `Server`/`Connection` construction | the service-account connection is context-managed; the user bind is unbound in a `finally`, so a **rejected** password releases it too (the common adversarial case) | fails closed with `LdapError`; the login is rejected and audited | **single-shot** — two binds, no retry loop |
| Active Directory — session reconciler (`ad_session_recheck_seconds`) | the same `ad_connect_timeout` / `ad_receive_timeout` | as the login path — context-managed connections | a pass that fails is retried on the next interval; strike state is process-local | **single-shot per pass**; `ad_session_recheck_strikes` (2) required before a revoke |
| Kerberos / SPNEGO SSO (`kerberos_spn`) | **none engine-owned** — the OS provider owns any KDC timeout | the SPNEGO context is per-request | a failed step raises `LdapError` and audits a login reject | **single-shot**, single-leg — no NTLM fallback, no multi-leg handshake |
| OIDC IdP — token endpoint (`oidc_token_endpoint`) | 10 s — `auth/oidc/flow.py`'s **own** `exchange_code(timeout=…)` default (`AuthService._oidc_exchange` passes none). The JWKS leg's 10 s is a **separate** literal, `oidc_http.DEFAULT_IDP_TIMEOUT_SECONDS`; the two coincide but are independent | the response is context-managed; the body is size-capped | a non-200 or oversize body fails the login closed | **single-shot** — one POST per login |
| OIDC IdP — JWKS fetch (`oidc_jwks_uri`) | 10 s — `oidc_http.DEFAULT_IDP_TIMEOUT_SECONDS`, the constant `jwks_fetcher` is the only consumer of | the response is context-managed; the size cap is enforced on the socket read | a fetch failure fails verification closed | **single-shot**, further damped by the refetch floor |
| SMART token endpoint (`smart_token_url`) | `smart_timeout_seconds` 30 s | the response is context-managed; the token is cached in memory | a mint failure fails the delivery | **single-shot** — re-minted only on the next attempt or a `401` |
| OAuth2 token endpoint (`oauth2_token_url`) | `oauth2_timeout_seconds` 30 s | as SMART | as SMART | **single-shot** |
| AI broker (`[ai].endpoint`) | 60 s — a **hard-coded module constant, not operator-configurable** (`[ai]` has no timeout field) | the response is context-managed; the call runs off the event loop via `to_thread` | a mis-configuration, an un-allowlisted host, or an HTTP error raises to the API route | **single-shot** — one POST per assist, no retry |
| DR backup destination (`[backup].destination`, ADR 0049) | **no engine-owned timeout** — filesystem / SMB-redirector I/O, the same posture as the File connector | handles are context-managed; the archive is fsync'd then verified before the run counts | a failed or verify-failed run is logged + audited, never counted as a good backup when pruning | **single-shot per scheduled pass** — retried only by the next daily pass |
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
| **Serial (RS‑232)** + X/Y‑Modem/Kermit + **ASTM E1381/E1394/E1318** | ~ | ❌ | ✅ | ❌ | **declined-by-design (v0.2+)** — legacy/niche lab-instrument connectivity, no feed demand ([BACKLOG.md](BACKLOG.md) #27) |
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
optional extra — `[dicom]` (`pydicom>=3.0.2,<4` + `pynetdicom>=3.0.4,<4`, pure‑Python, no numpy), `[fhir]`
(`fhir.resources` + `fhirpathpy`), `[x12]` (`pyx12`), and `[xml]` (`lxml` + `xmlschema` + `signxml`) — all
lazily imported, so an install that never touches a lane pays nothing. Still to be *evaluated*, not yet
chosen: an **NCPDP** parser (the XML/CDA question is settled — `lxml` is in tree under `[xml]`). Per the
project guardrails, each must be **verified as real and reputable, added to `pyproject.toml`, and
re‑locked** before use — no ad‑hoc installs. Each modeled lane is a substantial architectural addition,
so it follows the **plan‑first** rule (a written plan before code).
