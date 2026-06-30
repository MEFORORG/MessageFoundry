# Positioning & Competitive Landscape

How MessageFoundry is positioned relative to the established healthcare integration engines, and the
deliberate choices that differentiate it. This is product positioning, not a feature-by-feature
competitive teardown — it states what MessageFoundry *is* and *is not* trying to be.

## One-line positioning

**An open-source, Python-native, code-first healthcare integration engine** — a modern alternative to
engines like **Mirth Connect** and **Corepoint**, built for teams that want their interface logic to be
real, version-controlled code rather than clicks in a proprietary GUI, without a per-engine license.

## The landscape

The mature commercial engines fall into two broad authoring models:

- **Low-code / visual** — Corepoint (low/no-code), Rhapsody (visual + scripting), Qvera (visual
  mapping). Powerful, but the logic lives inside the vendor's editor and runtime.
- **Embedded-scripting** — Mirth Connect (JavaScript), Cloverleaf (Tcl), InterSystems IRIS/Ensemble
  (ObjectScript). Closer to code, but each is tied to a vendor language and runtime.

These are proven, fast, native-core products. MessageFoundry does **not** compete with them on raw
per-core throughput — a compiled native engine will out-run an interpreted one core-for-core, and we
don't pretend otherwise. We compete on **economics, ecosystem, and the authoring model**, and we scale
to enterprise volume through architecture (durable staged pipeline + horizontal scaling) rather than
per-core speed.

## What differentiates MessageFoundry

- **Open-source (AGPL) + commercial dual-license — no per-engine license fee.** The engine is yours to
  read, run, fork, and audit. The commercial license exists to fund maintenance, not to gate the
  software.
- **Code-first in Python.** Routers and Handlers are ordinary, pure Python functions
  (`@router` / `@handler`) — testable, diff-able, reviewable, and version-controlled. The Python
  ecosystem (parsing, crypto, data, web) is available to a transform without a vendor SDK. Guided
  tooling (wizards, a VS Code extension) exists for connection *configuration*, but interface *logic*
  is always code.
- **Payload-agnostic ingress.** HL7 v2 is the default and first-class, but the same pipeline carries
  JSON, XML/SOAP, X12, FHIR, DICOM (headers/SR), and arbitrary binary — without forcing everything
  through an HL7 object model.
- **Reliable by default, no extra broker.** A transactional staged queue on the database gives
  at-least-once delivery, retries, replay, and dead-lettering out of the box — the durability story is
  built in, not bolted on.
- **On-prem and PHI-first.** Localhost-bound API with required auth + RBAC, a user-attributed audit log,
  encryption-at-rest for message bodies, and PHI log redaction are built in. No PHI leaves the local
  environment without explicit, reviewed configuration.
- **Fork-to-customize direction.** The roadmap is a read-only component SDK that users fork to
  customize, rather than a closed runtime they configure around.

## Who it's for

MessageFoundry targets the full range from a **single community hospital** up to the **enterprise tier**
(large IDNs / consolidated systems). Smaller and mid-size estates run comfortably on a single process
today; enterprise volume is served through the engine's horizontal-scaling and concurrency roadmap on a
remote production database. The durable, code-first core is the same at every size.

## What it deliberately is *not*

- **Not a visual / drag-drop transformer.** Code-first authoring *is* the differentiator — a guided
  editor that drifts toward declarative *logic* authoring is an anti-goal (see
  [BACKLOG.md](BACKLOG.md) #26).
- **Not a broker-coupled architecture.** The staged database queue *is* the durability layer; we don't
  require Kafka/JMS to be reliable.
- **Not chasing native per-core benchmark wins.** The honest trade is interpreted-language flexibility +
  open-source economics over raw single-core speed; scale comes from architecture.

---

*See also: [ARCHITECTURE.md](ARCHITECTURE.md) (the engine model), [CONNECTIONS.md](CONNECTIONS.md) (the
connector vocabulary), and the project's reliability and PHI invariants in the root `CLAUDE.md`.*
