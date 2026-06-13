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

| Code | Direction | Transport | Mirth equivalent | Built? |
|------|-----------|-----------|------------------|--------|
| `IB` | inbound | MLLP listener | MLLP/TCP Listener | ✅ |
| `OB` | outbound | MLLP sender | MLLP/TCP Sender | ✅ |
| `IBC` | inbound | MLLP listener (low/intermittent traffic) | — | ✅ * |
| `OBC` | outbound | MLLP sender (persistent link) | — | ✅ * |
| `FILE-IN` | inbound | folder poll | File Reader | ✅ |
| `FILE-OUT` | outbound | folder write | File Writer | ✅ |
| `TCP-IN` | inbound | raw TCP listener (non-MLLP framing) | TCP Listener | ⏳ planned |
| `TCP-OUT` | outbound | raw TCP sender (non-MLLP framing) | TCP Sender | ⏳ planned |
| `SFTP-IN` | inbound | SFTP poll | File Reader (SFTP scheme) | ⏳ planned |
| `SFTP-OUT` | outbound | SFTP write | File Writer (SFTP scheme) | ⏳ planned |
| `SOAP-IN` | inbound | SOAP endpoint | Web Service Listener | ⏳ planned † |
| `SOAP-OUT` | outbound | SOAP client | Web Service Sender | ✅ |
| `REST-IN` | inbound | HTTP endpoint | HTTP Listener | ⏳ planned † |
| `REST-OUT` | outbound | HTTP client | HTTP Sender | ✅ |
| `DB-IN` | inbound | DB poll | Database Reader | ✅ (SQL Server, exp.) |
| `DB-OUT` | outbound | DB write | Database Writer | ✅ |
| `FHIR-IN` / `FHIR-OUT` | in/out | FHIR endpoint/client | (FHIR connector) | ⏳ planned |
| `DICOM-IN` / `DICOM-OUT` | in/out | DICOM listener/sender | DICOM Listener/Sender | ⏳ planned |
| `JMS-IN` / `JMS-OUT` | in/out | JMS queue consumer/producer | JMS Listener/Sender | ⏳ planned |
| `MAIL-IN` | inbound | POP3/IMAP mailbox poll | Email Reader | ⏳ planned |
| `SMTP-OUT` | outbound | SMTP email send | SMTP Sender | ⏳ planned |

\* **`IBC`/`OBC`** use the *same* MLLP transport as `IB`/`OB`; the `C` is a **monitoring hint**: for
these, "waiting for connection" is the *normal, healthy* state (a low‑traffic feed or a persistent
link that idles), so the Monitor shouldn't flag them. (The Monitor health rule that honors this is not
yet implemented — the suffix documents intent today.)

† **`REST-IN`** and **`SOAP-IN`** (non-HL7 inbound *sources*). The **payload-agnostic ingress** contract
is **built** ([ADR 0004](adr/0004-payload-agnostic-ingress.md): an inbound's `content_type` selects the
HL7 path vs. a `RawMessage` route), so what these rows await is a **source connector** (an HTTP listener)
on top of it. The first source on that contract — the **`DB-IN`** poll (`DatabasePoll(...)`, below) — is
**built**; the **`REST-OUT`**, **`DB-OUT`**, and **`SOAP-OUT`** destinations are built (below).

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

> **Transforms & HL7 escaping.** Writing a **component/subcomponent** (`msg["PID-5.1"] = value`)
> stores `value` as a literal: HL7 delimiters in it (`^ ~ & |`) are **escaped** so they stay data
> (`"O^Brien"` remains one component, not two). To build *multiple* components, write the whole
> field (`msg["PID-5"] = "DOE^JANE"`) — its separators are taken as structure. A value containing a
> segment separator (CR/LF) is **rejected** (it would inject a segment downstream). Reads return the
> unescaped value, so a write→read round-trips. The message's own `MSH-2` encoding characters are
> used throughout, so custom-delimiter messages are handled correctly.

## Settings — what's supported today

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

Plus on `inbound(...)`: `ack_mode` (`original`/`enhanced`/`none`), `strict`, `hl7_version`. On
`outbound(...)`: `retry` (`RetryPolicy`).

> **Inbound bind interface (service-level).** Inbound MLLP/TCP listeners take **only a port** —
> passing a `host` is a wiring error. Every inbound binds to the service-level `[inbound].bind_host`
> (default `127.0.0.1`). Binding `0.0.0.0` exposes unauthenticated MLLP to the network, so the
> interface is a deliberate **per-environment operator decision** (DEV typically loopback, PROD a
> specific NIC or `0.0.0.0` behind a firewall) set in `messagefoundry.toml`, never authored per
> connection. See [docs/CONFIGURATION.md](CONFIGURATION.md).

> **At-least-once / duplicates:** an outbound delivery that is sent but whose ACK is lost
> (peer closes or times out after receiving) is retried, so the receiver may see a duplicate.
> This is the documented at-least-once trade-off — **outbound receivers must be idempotent.**

> **Message size caps:** beyond the MLLP frame cap, every inbound message is also rejected
> before parsing if it exceeds **16 MiB** or **10,000 segments** (`ERROR` disposition + AR NAK),
> bounding both the tolerant peek and the strict (hl7apy) validation paths.

### File — `File(...)`

| Setting | Dir | Default | Meaning |
|---------|-----|---------|---------|
| `directory` | both | — (required) | folder to poll / write into |
| `pattern` | in | `*.hl7` | filename glob to pick up |
| `poll_seconds` | in | `1.0` | poll interval |
| `min_age_seconds` | in | `0` | skip files modified within this window (partial writes) |
| `after_read` | in | `move` | `move` (→ `.processed`) or `delete` |
| `sort` | in | `name` | process order: `name` or `mtime` |
| `recursive` | in | `false` | also scan subdirectories |
| `max_file_bytes` | in | `16 MiB` | route files larger than this to the error dir instead of reading them into memory (OOM guard). `None`/`0` = unlimited. |
| `processed_subdir` / `error_subdir` | in | `.processed` / `.error` | where read/failed files go |
| `filename` | out | `{MSH-10}.hl7` | output name (supports `{HL7-path}` placeholders). Resolved values are sanitized to a **single safe filename** — path separators/unsafe chars stripped, leading dots removed, and `.`/`..`/reserved device names fall back — so a message field can never write outside the directory. |
| `overwrite` | out | `false` | overwrite vs. uniquify a name collision (collisions are resolved by an **atomic** exclusive create, so concurrent writes never clobber) |
| `encoding` | both | `utf-8` | file charset (write) |

File writes are always **atomic** (write to a temp `.part` file, then rename), so a downstream reader
never sees a partial file.

#### File handling & quarantine policy (ASVS 5.1.1)

The directory **source** is the only file-ingest path — there is no HTTP file upload/download endpoint.
Its handling of an untrusted drop directory is fixed policy:

- **Permitted type — HL7 v2 text only.** Files are selected by the `pattern` glob (default `*.hl7`), and
  every candidate is **content-sniffed** before its bytes reach the pipeline: it must begin with an HL7
  header segment (`MSH`/`FHS`/`BHS`, after an optional UTF-8 BOM / MLLP start byte / leading whitespace).
  A binary or non-HL7 file carrying a `.hl7` name is rejected on **content, not extension** (ASVS 5.2.2).
- **Maximum size.** `max_file_bytes` (default **16 MiB**, matching the MLLP frame cap). An oversize file
  is rejected by a `stat()` **before** it is read into memory (OOM / DoS guard); `None`/`0` disables it.
- **No decompression / unpacking.** The connector reads raw HL7 text only — it never opens archives or
  decompresses — so there is no zip-bomb / unpacked-size surface (ASVS 5.2.3 is N/A by construction).
- **Malicious / malformed-file behavior — quarantine, never a silent drop.** An oversize or non-HL7 file
  is **moved to the `.error` subdirectory** (preserved for the operator) and logged. A
  *textual-but-non-conformant* HL7 file still flows through and is recorded as an `ERROR`-status message
  by the parser (raw preserved in the store). A **transient** read failure (file locked / mid-write) or
  an **infrastructure** failure (store unavailable) **leaves the file in place to retry** next scan —
  never an accept-and-drop. Use `min_age_seconds` to skip files still being written.
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

### REST — `Rest(...)`

An **outbound** HTTP(S) client ([ADR 0003](adr/0003-non-hl7-transports-database-rest-soap.md)). The
Handler produces the request body (JSON, XML, an HL7-in-FHIR document — whatever the endpoint expects);
the connector delivers it. There is **no REST source yet** — a non-HL7 *inbound* awaits the
payload-agnostic ingress decided in ADR 0003.

| Setting | Default | Meaning |
|---------|---------|---------|
| `url` | — (required) | endpoint; `http`/`https` only. Use `env()` for a DEV/PROD-specific host. |
| `method` | `POST` | HTTP method |
| `content_type` | `application/json` | sets the `Content-Type` header |
| `headers` | `{}` | extra **static** headers (no secrets — these aren't `env()`-resolved) |
| `bearer_token` | — | `Authorization: Bearer …` (a **secret** — supply via `env()`) |
| `basic_user` / `basic_password` | — | HTTP Basic auth (secrets — via `env()`) |
| `timeout_seconds` | `30` | per-request timeout |
| `verify_tls` | `true` | TLS cert verification; `false` (dev only) requires `MEFOR_ALLOW_INSECURE_TLS` |
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

An **outbound** SQL connector ([ADR 0003](adr/0003-non-hl7-transports-database-rest-soap.md)) — **SQL
Server** today, via the `[sqlserver]` extra (`pip install 'messagefoundry[sqlserver]'`) + the Microsoft
ODBC Driver 18, **lazily imported** (SQLite-only installs unaffected). **Status: experimental**, like
the SQL Server *store* backend — the live round-trip is exercised only by the CI service-container job.
The **inbound** direction is the DB poll source below (`DatabasePoll(...)`).

The Handler produces a **JSON-object** body; the connector binds its keys to the `:name` parameters in
`statement` (translated to positional ODBC `?` — always parameterized, never string-built) and runs it.

| Setting | Default | Meaning |
|---------|---------|---------|
| `server` | — (required) | SQL Server host. Use `env()` for a DEV/PROD-specific host. |
| `database` | — (required) | database name |
| `statement` | — (required) | parameterized SQL / proc call with `:name` placeholders, e.g. `INSERT INTO obs (mrn, val) VALUES (:mrn, :val)` |
| `auth` | `sql` | `sql` · `integrated` (Windows) · `entra` (ActiveDirectoryDefault) |
| `username` / `password` | — | SQL-auth credentials (`password` is a **secret** — via `env()`) |
| `port` | `1433` | server port |
| `encrypt` | `true` | TLS to the DB; `false` (dev only) needs `MEFOR_ALLOW_INSECURE_TLS` |
| `trust_server_certificate` | `false` | accept an untrusted cert (dev only; needs the escape) |
| `connect_timeout` | `15` | connection timeout (s) |
| `app_name` | `messagefoundry` | ODBC `APP` name |
| `pool_max` | `5` | max pooled connections |

**Delivery semantics.** A committed statement is delivered. A **transient** DB failure (connection drop,
deadlock, timeout — SQLSTATE class `08`/`40` or `HYTxx`) → `DeliveryError`, so the lane **retries**. A
**permanent** failure (constraint / data / syntax) **and a payload that doesn't match the statement** →
`NegativeAckError` → **dead-letter** (a retry can't fix it).

**Security.** Values are bound as **parameters** (never string-interpolated into SQL); the connection
string brace-quotes every value (no connection-string injection); TLS is **on by default** and a
weakened posture is refused unless `MEFOR_ALLOW_INSECURE_TLS` is set; the outbound server is gated by the
fail-closed `[egress].allowed_db` allowlist (WP-11c). A `:name` placeholder must not appear inside a
quoted string literal in `statement` — bind dynamic strings as parameters.

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

### Database source — `DatabasePoll(...)`

The **inbound** DB poll ([ADR 0003](adr/0003-non-hl7-transports-database-rest-soap.md) §3 + the
payload-agnostic ingress of [ADR 0004](adr/0004-payload-agnostic-ingress.md)). Same connection settings
and `[sqlserver]`-extra / experimental status as the destination above; it is the File source's
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
| `auth` / `username` / `password` / `port` / `encrypt` / `trust_server_certificate` / `connect_timeout` / `app_name` / `odbc_driver` / `pool_max` | — | identical to the `Database(...)` destination above |

**Mark mechanism — your choice via `mark_statement`.** A **status column** (lead pattern:
`SELECT … WHERE status='NEW'` + `UPDATE … SET status='DONE'`), a **delete-from-queue** (`DELETE … WHERE
id=:id`), or a **high-water-mark** cursor (an `UPDATE` advancing a stored cursor) all work — the connector
just runs whatever statement you declare, bound from the row.

**Reliability — at-least-once, tolerate duplicates.** A crash (or a `mark_statement` failure) after the
handler ingested a row but before the mark commits re-emits that row next poll, so the **downstream
pipeline must tolerate duplicates**. A handler failure (e.g. the store is briefly down) leaves the row
**unmarked** so it retries — never marked-and-dropped. A poll error is **logged, not fatal** — a bad
`poll_statement` or a dropped connection never kills the poller; it retries next interval.

**Security.** TLS is **on by default** (weakening needs `MEFOR_ALLOW_INSECURE_TLS`); the connection
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
SOAP `Content-Type` (+ a `SOAPAction` header for 1.1) and POSTs it. There is **no SOAP source yet** (a
Web Service Listener awaits the payload-agnostic ingress of ADR 0003).

| Setting | Default | Meaning |
|---------|---------|---------|
| `url` | — (required) | endpoint; `http`/`https` only. Use `env()` for a DEV/PROD-specific host. |
| `soap_action` | — | the `SOAPAction` (1.1 header; 1.2 `action` content-type param) |
| `soap_version` | `1.1` | `1.1` (`text/xml`) or `1.2` (`application/soap+xml`) |
| `headers` | `{}` | extra **static** headers (no secrets — not `env()`-resolved) |
| `bearer_token` | — | `Authorization: Bearer …` (a **secret** — via `env()`) |
| `basic_user` / `basic_password` | — | HTTP Basic auth (secrets — via `env()`) |
| `timeout_seconds` | `30` | per-request timeout |
| `verify_tls` | `true` | TLS cert verification; `false` (dev only) needs `MEFOR_ALLOW_INSECURE_TLS` |
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
| **Raw TCP** client/server (non‑MLLP framing) | ✅ | ✅ | ✅ | ❌ | `TCP-IN/OUT` planned |
| **File / Directory** (local) | ✅ | ✅ | ✅ | ✅ | `FILE-IN/OUT` shipped |
| **FTP / FTPS** | ✅ | ✅ | ✅ | ❌ | File remote scheme, planned |
| **SFTP** | ✅ | ✅ | ✅ | ❌ | `SFTP-IN/OUT` planned |
| **SMB / network share** | ✅ | ✅ | ✅ | ❌ | File remote scheme, planned |
| **S3 / cloud blob** | ✅ | ~ | ✅ | ❌ | File remote scheme, planned |
| **HTTP/HTTPS** listener + sender (REST) | ✅ | ✅ | ✅ | ~ | `REST-OUT` shipped; `REST-IN` planned |
| **SOAP / Web Services** | ✅ | ✅ | ✅ | ~ | `SOAP-OUT` shipped; `SOAP-IN` planned |
| **Database** reader/writer (JDBC/ODBC) | ✅ | ✅ | ✅ | ✅ | `DB-OUT` + `DB-IN` shipped (SQL Server, exp.) |
| **SMTP** (email send) | ✅ | ✅ | ✅ | ❌ | `SMTP-OUT` planned |
| **Email reader** (POP3/IMAP) | ~ | ~ | ✅ | ❌ | `MAIL-IN` planned |
| **JMS** (Java messaging) | ✅ | ❌ | ✅ | ❌ | `JMS-IN/OUT` planned |
| **IBM MQ / MSMQ** | ~ | ❌ | ✅ | ❌ | not on roadmap |
| **Kafka / streaming** | ~ | ❌ | ✅ | ❌ | not on roadmap |
| **DICOM** (imaging) | ✅ | ~ | ✅ | ❌ | `DICOM-IN/OUT` planned |
| **Serial (RS‑232)** + X/Y‑Modem/Kermit | ~ | ❌ | ✅ | ❌ | not on roadmap (legacy/niche) |
| **FHIR** endpoint/client | ✅ | ✅ | ✅ | ❌ | `FHIR-IN/OUT` planned |
| **Internal channel‑to‑channel** | ✅ | ✅ | ✅ | ✅ | the routing graph (wired by name) — not a transport |
| Printer / command‑line / screen‑scrape | ~ | ❌ | ✅ | ❌ | not on roadmap (niche) |

**Priority of the gaps we'll close:**

- **Tier 1 — table stakes (all three have these):** raw TCP, HTTP/REST, SOAP, Database, SFTP, plus
  File remote schemes (FTP/FTPS/SMB/S3). `SFTP-*`/`SOAP-*`/`REST-*`/`DB-*` are already designed; raw
  TCP closes the MLLP‑only gap. **FHIR** belongs here too — all three now ship it.
- **Tier 2 — present in 2 of 3:** DICOM and JMS (Mirth + Rhapsody), Email (SMTP send + POP3/IMAP read).
- **Tier 3 — Rhapsody‑only, lower priority:** Kafka/streaming (worth adding for modern credibility),
  IBM MQ/MSMQ, Serial, printer/command‑line.

Each new type needs a `ConnectorType` value, a `transports/` module, and a `wiring.py` factory.

### Per‑transport feature gaps (not just new types)

- **MLLP:** TLS/SSL, custom start/end frame bytes, keep‑connection‑open/pooling, MLLP v2 (commit) ACK,
  response‑on‑same‑connection, max buffer size.
- **File:** cron/time‑of‑day polling (vs. fixed interval), file‑age sorting, batch (line‑per‑message)
  splitting, remote schemes (FTP/SMB/S3) beyond local.
- **Monitor:** honor the `IBC`/`OBC` "waiting = healthy" convention in connection health.

## Standards & formats — parity & roadmap

Formats are **orthogonal to transports**: any format can ride any connector (an X12 837 over MLLP, a
C‑CDA over a file, a FHIR bundle over HTTP). This section is the **format/standard** parity story; the
catalog above is the **transport** one.

**Where MF stands today:** **HL7 v2.x only.** [`parsing/`](../messagefoundry/parsing/) is python‑hl7
(tolerant peek, hot path) + hl7apy (opt‑in strict) — there is no XML, FHIR, X12, NCPDP, or DICOM model
anywhere in the engine. The competitors are format‑agnostic and cover the full clinical catalog.

A useful split, because it sets the cost:

- **"Free in Python" text formats** — JSON, delimited/CSV, fixed‑width, and *generic* XML are handled
  **in a Handler today** with the standard library (`json`, `csv`, `xml`/`lxml`); no engine change is
  needed to read or emit them. They're a documentation + helper‑ergonomics item, not a build.
- **"Modeled standards"** — CDA/C‑CDA, FHIR, X12/EDI, NCPDP, DICOM, and HL7 v3 each need a real
  **parse + model + validate lane** parallel to the v2 lane (a document/resource model, a field/path
  façade so transforms stay code‑first, and a standard‑specific validator). Each is its own workstream.

Legend: ✅ native · ~ partial / via generic XML/JSON · ❌ none.

| Format / standard | Mirth | Corepoint | Rhapsody | MF today | MF plan |
|-------------------|:-----:|:---------:|:--------:|:--------:|---------|
| **HL7 v2.x** | ✅ | ✅ | ✅ | ✅ | shipped (python‑hl7 + hl7apy) |
| **JSON** | ✅ | ✅ | ✅ | ~ | scriptable in Handler now; ship helper |
| **Delimited / CSV / fixed‑width** | ✅ | ✅ | ✅ | ~ | scriptable in Handler now; ship helper |
| **Generic XML** | ✅ | ✅ | ✅ | ~ | scriptable in Handler now; ship helper |
| **Raw / binary pass‑through** | ✅ | ✅ | ✅ | ✅ | stored/routed as opaque bytes today |
| **FHIR** (R4/R5, JSON + XML) | ✅ | ✅ | ✅ | ❌ | modeled lane — **Tier 1** |
| **C‑CDA / CDA / CCD** (HL7 v3 XML doc) | ✅ | ✅ | ✅ | ❌ | modeled lane — **Tier 1** |
| **X12 / EDI** (270/271, 834, 835, 837…) | ✅ | ✅ | ✅ | ❌ | modeled lane — **Tier 2** |
| **NCPDP** (SCRIPT, Telecom) | ✅ | ~ | ✅ | ❌ | modeled lane — **Tier 2** |
| **DICOM** object / SR | ✅ | ~ | ✅ | ❌ | modeled lane — **Tier 3** (pairs w/ `DICOM-*` transport) |
| **HL7 v3 messaging** (non‑CDA XML) | ✅ | ✅ | ~ | ❌ | modeled lane — **Tier 3** (low demand) |
| **IHE profiles** (XDS/PIX/PDQ) | ~ | ~ | ✅ | ❌ | transport+format combo — later |

**Roadmap priority (modeled standards):**

- **Tier 1 — FHIR and C‑CDA.** The two formats every modern RFP asks for; both are the highest‑value
  gaps after the connector catalog. FHIR also pairs with the planned `FHIR-*` and `REST-*` transports;
  C‑CDA most often arrives base64‑embedded in a v2 `MDM^T02`/`ORU` `OBX-5` (which MF already carries as
  bytes — the lane adds *understanding* it). See the CCD phasing note below.
- **Tier 2 — X12/EDI and NCPDP.** Eligibility/claims (X12) and pharmacy (NCPDP); needed for payer and
  e‑prescribing integrations, lower frequency than FHIR/CDA in a pure clinical shop.
- **Tier 3 — DICOM object/SR and HL7 v3 messaging.** DICOM pairs with the imaging transport; v3
  messaging (as distinct from CDA) sees little real‑world demand.

**C‑CDA phasing (representative of how a modeled lane lands):**
1. *Pass‑through (today):* route/store a CCD as opaque bytes — as a file, or base64 in v2 `OBX-5`.
2. *Read‑only lane:* an XML model + XPath façade + Schematron/XSD validation + an `OBX-5` base64
   extract — enough to route on and validate.
3. *Transform:* v2 ↔ C‑CDA helpers (the high‑value, high‑effort part).

**Dependency note.** A modeled lane means a new parser/validator dependency (candidates to *evaluate*,
not yet chosen: `lxml` for XML/CDA, a FHIR resource library, an X12/EDI parser, `pydicom`/`pynetdicom`
for DICOM). Per the project guardrails, each must be **verified as real and reputable, added to
`pyproject.toml`, and re‑locked** before use — no ad‑hoc installs. Each modeled lane is a substantial
architectural addition, so it follows the **plan‑first** rule (a written plan before code).
