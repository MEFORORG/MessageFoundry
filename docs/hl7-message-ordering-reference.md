# Message Ordering & Error Handling in HL7 Interface Engines

**Context document for MessageFoundry development (Claude Code reference).**

## BLUF

HL7 integration has two related but distinct reliability concerns: **in-order delivery** and **isolating bad messages**. These sit at very different maturity levels across existing engines:

- **Dead-letter / quarantine is table stakes.** Every serious engine has it, just under different names (error queue, failed queue, suspended messages, error database).
- **Per-key ordering is the harder, rarer one.** For years it was something you *built by hand* rather than configured; it has only recently begun appearing as a first-class, native feature.

The design opportunity for MessageFoundry is to make **per-key ordering a first-class Router/Connection setting with an explicit partition key**, rather than a workaround — putting it where the leading edge is now heading rather than where incumbents historically sat.

---

## Core Concepts

**In-order (FIFO) delivery.** Messages from a given source should be processed in the order produced. HL7 traffic has hard dependencies: a patient registration (ADT A01/A04) must land before orders or results that reference the encounter; an order (ORM/OMG) must precede its result (ORU); a newer update must not be overwritten by an older one arriving late. Out-of-order processing causes either hard failures (referencing an encounter that doesn't exist yet) or silent corruption (stale data overwriting newer data).

**HL7 Sequence Number Protocol (MSH-13).** The standard *does* define an in-order mechanism: the receiver tracks an expected number and accepts a message only if MSH-13 is exactly one greater than the last accepted value; 0 initializes/synchronizes the count. *In practice it is almost never implemented* — ordering is enforced architecturally instead.

**Per-key ordering.** Preserve order only *within* a single key (MRN / encounter / sending facility) while parallelizing *across* keys. This is the sweet spot between strict FIFO (safe, slow) and unordered parallelism (fast, unsafe). It is the same idiom as a partition key in modern message brokers (e.g. Kafka).

**Head-of-line blocking.** The failure mode of strict FIFO: one stuck or "poison" message blocks everything queued behind it. Mitigated by per-key ordering (narrows the blast radius) and by a quarantine path (sets the bad message aside).

**Dead-letter / quarantine.** A path to remove a failing message from the main flow — for inspection, correction, and reprocessing — without halting the queue.

---

## How the Major Engines Handle It

| Engine | Ordered-vs-parallel control | Native per-key ordering? | Dead-letter / quarantine |
|---|---|---|---|
| **InterSystems IRIS for Health** (Ensemble / HealthShare) | `Pool Size` per business host; **1 = FIFO** | **Yes — native since IRIS 2025.3** (FIFO with pool size > 1). Historically the `SessionId = key` pattern. | Messages suspended / retried; reply-code actions; failure timeout defaults to never-skip |
| **Mirth Connect** (NextGen Connect) | `Queue Threads`; **1 = ordered**, >1 not guaranteed. `Rotate Queue` mitigates head-of-line blocking | **Partial / hand-built** — thread-assignment map variable routes messages to a specific thread by a chosen value (key on MRN → per-MRN order) | Errored messages persist in DB with ERROR status; error channels / postprocessors; reprocessable |
| **Rhapsody** (Rhapsody Health, fmr. Orion/Lyniate) | Ordered routes / thread config | **No single native knob** — partition by routing on the key into separate ordered routes | **Mature** — distinct Error / Failed / Hold queues; route-level `error connector` and `no-match connector` |
| **Cloverleaf** (Infor) | Threading model *not verified here* | Build via routing | Error database for inspection / reprocessing |

### Notes per engine

**InterSystems IRIS** is the cleanest illustration of the ordered-vs-parallel lever. Pool Size 1 on every business host gives guaranteed FIFO; above 1, a message can take a faster parallel job and overtake earlier messages from the same source, so healthcare deployments default to Pool Size 1 everywhere. The long-standing per-key pattern was to set a request's `SessionId` to your partition key (lab report ID, MRN) so same-key messages serialize while the pool stays parallel across keys. *As of IRIS 2025.3 this is now a native FIFO-with-pool-size>1 option* — i.e. per-key ordering as a first-class feature.

**Mirth Connect** handles the head-of-line mitigation explicitly: with `Rotate Queue` on, a failed message rotates to the back of the queue and the next is attempted (at the cost of strict order). `Queue Threads > 1` parallelizes but drops the ordering guarantee. The relevant detail: when using multiple queue threads, a **map variable assigns messages to specific threads** — key that variable on MRN and you get per-MRN ordering with cross-patient parallelism, the same idea done manually. Its clustering add-on also offers a guaranteed-message-ordering mode (throughput cost).

**Rhapsody** leans hardest into the quarantine side. Its routes carry an error connector and a no-match connector to divert failing/unmatched messages, and operationally it exposes distinct Error, Failed, and Hold queue monitors. Per-key ordering is not a single native setting; you partition by routing on the key into separate ordered routes.

**Cloverleaf** has the equivalent quarantine concept in its error database. Its threading/ordering model was not verified in this pass — *treat the per-key story there as "build via routing" until confirmed.*

---

## Design Implications for MessageFoundry

Mapping onto the existing concepts (Connections, Routers, Handlers, durable message store):

1. **Make ordering a configurable property, defaulting to FIFO.** Per-Connection or per-Router, the safe default is in-order processing. Treat parallelism as an opt-in.

2. **Add an explicit `partition_key` to Router config.** Same key → same ordered worker/lane; different keys → processed in parallel. The key is a configurable expression over the message (e.g. PID-3 MRN, PV1 visit number, or MSH sending facility). This is the first-class version of Mirth's thread-assignment variable and InterSystems' SessionId pattern.

3. **Let the durable store be the source of truth for order.** A SQLite/aiosqlite (WAL) store with a **monotonic sequence column** and single-writer semantics naturally preserves receipt order across restarts and retries. Processing order should be *derived from the store*, not from in-memory arrival timing. Per-key parallel workers read their lane from the store; the durable sequence remains authoritative.

4. **Build a quarantine / dead-letter path as a first-class feature.** A failed message moves to a quarantine table carrying status, error detail, attempt count, and timestamps — reprocessable from the UI/CLI. Make the policy configurable per Router, e.g. *retry N times → quarantine*, with an optional *rotate* mode (skip-and-continue) for throughput-sensitive routes.

5. **Guard the partition boundary.** *Per-key parallelism is only safe as long as no single message's correct processing depends on the ordering of a different key.* The canonical hazard is an **A40 patient merge**, which legitimately spans two MRNs. Such cross-key messages must not be naively parallelized — they need either a serialization fallback or explicit handling that holds both affected keys.

---

## Open Design Questions

- **Partition key scope:** per-Router or per-Connection? What field(s) form the default key (MRN vs encounter vs sending facility), and is it a fixed field or a user-supplied expression?
- **Failure policy granularity:** is retry/rotate/quarantine configured per Router, per Handler, or globally? What are the default retry count and interval?
- **Ordering guarantee width:** how wide is the default guarantee — global FIFO, per-Connection, or per-key — and how is that surfaced/documented to the interface author?
- **Cross-key events (A40 and similar):** detect-and-serialize, or a dedicated handler? Where does that logic live relative to the Router?
- **Observability:** what does the quarantine/error console need to show (per-lane depth, oldest-in-lane age, poison-message alerts) to match the operational visibility teams expect from Rhapsody's queue monitors?

---

## Sources

Engine-specific facts above were verified against vendor documentation and community sources (versions noted where relevant):

- InterSystems IRIS for Health / HealthShare — Pool Size & FIFO docs; community post noting the native FIFO-with-pool>1 option in **IRIS 2025.3**.
- Mirth Connect (NextGen) — destination connector / queue documentation (Rotate Queue, Queue Threads, thread-assignment variable) and Advanced Clustering guide.
- Rhapsody (Rhapsody Health) — Integration Engine 7.3 release notes and Management Console / queue documentation.
- Cloverleaf (Infor) — error-database concept (threading model not independently verified in this pass).

*The HL7 Sequence Number Protocol (MSH-13) is defined in the HL7 v2.x standard.*
