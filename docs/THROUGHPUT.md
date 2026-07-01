# Understanding MessageFoundry Throughput

*A plain-language guide to what determines how many messages MessageFoundry can move — and why a
single "messages per day" number rarely tells you what you need to know.*

> **Read this first.** Every throughput figure in this document is a **theoretical maximum** measured
> in a controlled lab under ideal conditions. Your real-world throughput will almost always be **lower**,
> and it is usually set by **how fast your partner systems accept and acknowledge each message** — not by
> the engine. MessageFoundry adds only a few milliseconds of its own overhead per message; the rest of the
> time is spent waiting on round-trips to your database and your downstream systems. Size against *your*
> systems, not against a headline number.

---

## Executive summary

- **The engine is nearly transparent.** In our reference lab, MessageFoundry adds on the order of
  **~16 milliseconds** of its own processing per message. For an ordered (strictly in-sequence) feed that
  works out to roughly **60 messages/second end-to-end** and **~450 messages/second at the point of
  receipt** — but those are *ceilings under ideal conditions*, not promises for your environment.

- **Your partner systems are the biggest factor.** For ordered delivery, each message is sent, the engine
  **waits for the partner to accept and acknowledge it**, and only then does the next one go. The partner's
  round-trip time lands *directly* in the critical path. A partner that takes 50 ms to acknowledge caps a
  single ordered stream at roughly **15 messages/second** — no matter how fast the engine or database is.

- **"Messages per day" is a weak unit.** Healthcare traffic is **bursty**. In the production ADT feeds
  we've profiled, the **busiest hour runs about 2.7× the all-day average rate**. You have to size for the
  *peak hour*, not the daily average — so a raw "X million/day" figure, on its own, tells you very little.

- **Scale by fanning out, not by one giant pipe.** A strictly-ordered interface is a single serial lane
  with a bounded rate — that's the physics of guaranteed ordering, not a product limitation. Real capacity
  comes from running **many interfaces** (split feeds at the source: by hospital, facility, service line).
  One node's message store easily absorbs the combined load of dozens of interfaces.

- **Four questions to ask of *any* throughput claim** — ours or a competitor's:
  **(1)** How big are the messages? **(2)** Is delivery strictly ordered or parallel?
  **(3)** How fast does the receiving system acknowledge? **(4)** What's the *peak-hour* rate behind that
  daily average? Without those four, a msg/s or msg/day number is marketing, not engineering.

---

## 1. How a message flows (and why there are two different "speeds")

A message moves through MessageFoundry in stages, each of which is written durably to the message store
before the next begins (that's what guarantees nothing is lost):

```
   sender ──▶ [ receive + persist ] ──▶ [ route ] ──▶ [ transform ] ──▶ [ deliver ] ──▶ partner
                     │                                                        │
                 ACK to sender                                         partner ACK
              (fast — "intake")                                    (paced by the partner)
```

This gives you **two distinct throughput numbers**, and they are often very far apart:

| Rate | What it measures | Typical relationship |
|---|---|---|
| **Intake rate** (ACK-on-receipt) | How fast the engine can accept a message, store it durably, and acknowledge the *sender*. The sender never waits for downstream delivery. | **Higher** — ~450/s in our lab. Protects upstream senders from downstream slowness. |
| **Delivery rate** (end-to-end) | How fast the engine can get a message all the way to the *partner* and confirm it landed. | **Lower** — ~60/s in our lab. Paced by everything downstream, especially the partner. |

The gap between them is not waste — it's the buffer. MessageFoundry accepts and safely stores messages
faster than it delivers them, so a momentary slowdown at a partner doesn't push back on the sender. The
backlog drains as the partner catches up.

**Takeaway:** when someone quotes a throughput number, ask *which* rate they mean. Intake numbers look
impressive but say nothing about how fast messages actually reach their destination.

---

## 2. The single biggest factor: your partner systems and round-trip times

This is the point most capacity conversations miss.

**Ordered delivery is inherently serial.** When you require messages to arrive in the exact order they were
received (the default, and a hard requirement for most clinical feeds), the engine can only have **one
message in flight per destination at a time**:

1. Send message *N* to the partner.
2. **Wait** for the partner to receive it, process it (often persist it to *its own* database), and send
   back an acknowledgement.
3. Only then send message *N+1*.

That waiting time is not the engine's — it belongs to the **network round-trip and the partner's own
processing**. And because the stream is serial, it lands squarely in the critical path.

### The round-trips that make up a message's journey

Every message pays for several round-trips, and each one adds latency:

- **Sender ↔ engine** — the intake acknowledgement. Fast, and it doesn't block delivery.
- **Engine ↔ message store** — each durable stage handoff is a commit. If the store is on another server,
  every commit is a network round-trip. (See §4.)
- **Engine ↔ partner** — the delivery send *and the partner's acknowledgement*. **This is usually the
  dominant term**, and MessageFoundry does not control it.
- **Engine ↔ enrichment source** *(optional)* — if a handler does a live lookup (e.g. a provider or
  eligibility check), that adds another round-trip during transformation. (See §5.)

### What this does to throughput

For an ordered stream, throughput is approximately:

> **messages/second ≈ 1000 ÷ ( engine overhead + partner round-trip )**, in milliseconds

The engine overhead is small and roughly fixed (~16 ms in our lab). The **partner round-trip is yours**,
and it dominates as soon as it's more than a few milliseconds:

| Partner acknowledges in… | Approx. ordered throughput | "Uniform" msgs/day* | Realistic msgs/day (peak-aware)† |
|---|---|---|---|
| ~0 ms (lab ideal) | ~60 /s | ~5.2 M | ~1.9 M |
| 10 ms | ~38 /s | ~3.3 M | ~1.2 M |
| 25 ms | ~24 /s | ~2.1 M | ~0.8 M |
| 50 ms | ~15 /s | ~1.3 M | ~0.5 M |
| 100 ms | ~9 /s | ~0.8 M | ~0.3 M |
| 250 ms | ~4 /s | ~0.35 M | ~0.13 M |

<sub>\* "Uniform" assumes traffic is perfectly flat around the clock — it never is (see §6).
† "Peak-aware" divides by a 2.7× burst factor, which is the realistic planning number. Illustrative
first-order model anchored to the measured ~16 ms engine floor; your numbers depend on your systems.</sub>

The lesson is stark: a partner that takes a quarter-second to acknowledge each message will hold a single
ordered stream to a few messages per second, and **no amount of engine or database speed changes that.**
The bottleneck has moved outside MessageFoundry entirely.

### What you can do about a slow partner

- **Relax ordering where it's safe.** If a feed tolerates out-of-order delivery, unordered mode lets the
  engine keep many messages in flight at once, hiding the partner's round-trip behind concurrency (see §3).
- **Open multiple connections to the partner.** Each destination connection is its own independent stream,
  so *N* connections give you *N* parallel ordered lanes (if the partner accepts concurrent connections).
- **Fan out at the source.** Split one hot feed into several interfaces (see §7) so the aggregate isn't
  gated by a single serial lane.
- **Ask your partner about their acknowledgement latency.** It is often the cheapest thing to improve, and
  it's the term that matters most.

---

## 3. Ordering: the throughput-vs-order trade-off

Ordering guarantees and raw throughput pull in opposite directions. MessageFoundry lets you choose per
feed:

| Mode | Guarantee | Throughput | Use when |
|---|---|---|---|
| **Strict FIFO** *(default)* | Messages delivered in exactly the order received. | Bounded — one message in flight per destination (serial). | Order matters: ADT streams, anything where a later message corrects an earlier one. |
| **Unordered** | No ordering guarantee. | Higher — many messages in flight at once; the partner round-trip is hidden by concurrency. | Order doesn't matter: independent results, logging, feeds keyed only by their own content. |

Strict ordering being serial is not unique to MessageFoundry — it is a property of *any* system that
guarantees order over a single stream. This is exactly why integration engines let you opt out of ordering
when a feed can tolerate it: it's the most direct throughput lever available for a single interface.

---

## 4. The message store (durability has a cost, and location matters)

Every stage handoff is committed durably to the store before the next stage runs — that's what makes
delivery at-least-once and crash-safe. So the store's commit latency is part of every message's journey.

| Choice | Effect on throughput |
|---|---|
| **SQLite (embedded, default)** | Runs *in-process* with no network hop — the fastest per-commit path. Its ceiling is single-writer serialization, which is the floor case in our testing, not a problem for most single-node deployments. |
| **SQL Server / PostgreSQL (server database)** | Chosen for concurrency, high availability, and enterprise operations — **not** for raw single-stream speed. Every commit is now a **network round-trip** to the database server, which *adds* latency to each handoff. |
| **Store location — local vs. across the network** | This matters more than the database brand. A commit to a co-located, fast local disk is dramatically quicker than a commit that crosses the network to a remote database server. In our testing a local NVMe store committed on the order of **~65× faster** than a round-trip to a database on another box. |
| **Disk speed (NVMe vs. shared SAN)** | The store forces data to disk on commit for durability; faster storage lowers that per-commit cost. |

**One store serves many interfaces.** A single node's store has enormous headroom — in our lab a local
store sustained on the order of **tens of thousands of commits per second**, far more than any one ordered
interface can generate. This is *why* the scaling story is "add interfaces," not "make one interface
faster": the shared store is nowhere near the wall.

---

## 5. Message and transformation factors

- **Message size.** A small ADT message and a large message carrying an embedded document are not the same
  unit of work. Bigger messages cost more to parse, store, encrypt, and transmit.
- **Parsing and validation.** Fast, tolerant field inspection on the routing path is cheap. Full strict
  validation is deliberately opt-in per feed because it is the slow path — turn it on where you need
  conformance, not everywhere.
- **Transformation complexity.** How much work your handler does per message directly affects the rate.
  Heavy transformation is one of the largest hardware-independent reducers of throughput.
- **Live enrichment lookups.** A handler may do a sanctioned read-only lookup (e.g. a provider or
  eligibility check against a database or FHIR endpoint). Each lookup is another round-trip that adds to a
  message's time in the pipeline — powerful, but use it deliberately.
- **Fan-out.** If one inbound message is delivered to *N* destinations, that's *N* deliveries to commit and
  *N* partners to wait on. Each destination is its own independent lane.

---

## 6. Why "messages per day" is a misleading unit

**Healthcare message traffic is bursty — it is nothing like a flat, around-the-clock stream.** It follows
the operational rhythm of the facilities behind it, and that shape matters far more than the daily total.

### The shape of real traffic

- **Within a day:** volume is light overnight, ramps up sharply in the morning as registration, admissions,
  rounds, lab draws, and shift changes begin, peaks during the busy clinical hours, and tapers into the
  evening. Emergency-department and registration surges create short, sharp spikes on top of that curve.
- **Across a week:** weekdays run **several times heavier** than weekends, driven by elective admissions,
  scheduled procedures, and clinic activity.
- **Across a year:** seasonal load (e.g. respiratory-illness season) shifts the baseline further.

### The number that actually matters: the peak hour

A system doesn't experience the daily *average* — it experiences the **busiest hour**. If you size for the
average, you will be underwater exactly when volume is highest: queues back up, and end-to-end latency
climbs right when timeliness matters most.

**In the production ADT feeds we've profiled, the busiest hour runs about 2.7× the all-day average rate.**
So a feed that averages out to some tidy daily figure is actually asking for **nearly three times that
average rate** during its peak — and *that* is the rate your interface has to sustain.

### Same interface, very different "daily capacity"

Because you must size to the peak, the realistic daily capacity of an interface is well below the naive
"sustained rate × 86,400 seconds" figure:

| | Naive (assumes flat traffic) | Realistic (peak = 2.7× average) |
|---|---|---|
| One ordered interface at 60 msg/s | ~5.2 M messages/day | **~1.9 M messages/day** |

Nothing about the engine changed between those two columns — only the assumption about traffic shape. The
naive number is off by nearly 3×.

**This is why a bare "handles X million messages/day" claim is close to meaningless.** Two feeds with the
*same* daily total but different burst profiles need very different capacity. Always ask for the
**peak-hour rate**, the **message size**, and the **ordering guarantee** behind any daily figure — those,
not the daily total, tell you whether it fits your environment.

---

## 7. Putting it together: how to size a deployment

There is no single throughput number — there's a short calculation using *your* inputs:

1. **Start from the per-interface ceiling** for your ordering mode (our lab reference: ~60 msg/s ordered,
   with an instant partner).
2. **Apply your partner's real acknowledgement time** (§2). This is usually the biggest reduction.
3. **Apply your traffic's burst factor** (§6) — divide by ~2.7 for ADT-shaped traffic (or measure your own
   feed's peak-hour ÷ daily-average ratio).
4. **Fan out to enough interfaces** to cover your aggregate peak, splitting feeds at the source.

### A worked (illustrative) example

Suppose a partner acknowledges in ~25 ms and you have ADT-shaped traffic:

- Ordered throughput per interface ≈ 1000 ÷ (16 + 25) ≈ **~24 msg/s**.
- Peak-aware daily capacity ≈ 24 × 86,400 ÷ 2.7 ≈ **~0.8 M messages/day per interface**.
- To carry, say, a 5-million-message/day aggregate, you'd fan out to roughly **6–7 interfaces** — each
  comfortably within one node's shared-store headroom.

Your inputs will differ; the point is the *method*. Plug in your partner latency and your peak factor, then
count interfaces.

### Fan-out is the scaling story

A mega health system cannot push all of its ADT through one interface, and it doesn't need to. It splits
the feed at the source — by hospital, facility, region, or service line — across **multiple interfaces**.
Aggregate capacity is the sum of the interfaces; the shared message store on a single node has ample
headroom for the combined load, so you scale out by adding interfaces rather than trying to make one pipe
infinitely fast.

---

## 8. Reference lab measurements (and their caveats)

These are the figures referenced above, stated with full conditions so you can judge how they map to your
environment. **They are theoretical maxima under controlled conditions using synthetic data — not
guarantees, and not measured against any live clinical system.**

| Measurement | Value | Conditions |
|---|---|---|
| End-to-end delivery, one ordered interface | **~60 msg/s** | Single strictly-ordered MLLP interface, synthetic ADT, pass-through (no heavy transform), server database over a LAN, default settings, **instant-acknowledging partner**. |
| Intake (ACK-on-receipt) | **~450 msg/s** | Same setup; measures accept-and-persist, not end-to-end delivery. |
| Single-node store commit ceiling | **~tens of thousands of commits/s** | Local NVMe store; the shared store is far from the bottleneck for realistic interface counts. |
| Engine's own per-message overhead | **~16 ms** | Derived from the ordered end-to-end rate with an instant partner; this is the portion MessageFoundry contributes. |

**Why these are conservative and why your mileage will vary:**

- **Ordered, single interface.** The default strict-FIFO mode is serial by design. Unordered feeds and
  multiple interfaces both go faster.
- **Instant partner.** The lab partner acknowledges immediately. **Real partners don't** — and as §2 shows,
  their round-trip time is usually the dominant factor. This is the single largest reason your end-to-end
  number will differ from the lab number.
- **No independent industry benchmark exists.** There is no trustworthy public per-node throughput number
  for the major integration engines either — every published msg/s figure is hardware- and
  workload-dependent. Treat *all* such numbers (including these) as starting points for your own
  measurement, not as guarantees.

---

## Takeaways

1. MessageFoundry adds only a few milliseconds per message; **your partner systems and round-trip times set
   the real throughput.**
2. There are **two** rates — fast intake and slower end-to-end delivery. Know which one a number refers to.
3. **Strict ordering is serial** and therefore bounded; relax ordering, add connections, or fan out when you
   need more.
4. Traffic is **bursty** — size to the **peak hour (≈ 2.7× the average)**, not the daily total. "Messages
   per day" alone tells you little.
5. **Scale by fanning out** to multiple interfaces; one node's store has ample headroom.
6. Interrogate every throughput claim with four questions: **message size, ordering, partner
   acknowledgement time, and peak-hour rate.**
