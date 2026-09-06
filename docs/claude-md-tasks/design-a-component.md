# mefor-design-a-component

> Split out of [CLAUDE.md](../../CLAUDE.md) on 2026-09-05. Prohibitions that bind
> before this task starts stay in that file, which loads automatically. Read it first.


**How it's built.** Connections/Routers/Handlers are authored code-first against the
`messagefoundry` surface (`inbound`/`outbound`/`@router`/`@handler`/`Send`/`MLLP`/`File`/`Message`)
and registered into a `Registry` by the loader ([config/wiring.py](../../messagefoundry/config/wiring.py)).
The engine runs the graph via `RegistryRunner`
([pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)). There is no declarative
channel config or "channel" runner — don't build a "channel"/"route" *element* (an object, runner,
or config surface that bundles the graph).

**Connections may also be data.** *Routers/Handlers (logic) stay code-first*, but a Connection's
*transport config* (type + settings + the inbound's `router` binding + delivery knobs) may live in an
optional **`connections.toml`** in the config dir, edited by hand and by a VS Code GUI ([ADR
0007](../../docs/adr/0007-gui-manageable-connections-toml.md)). The loader desugars each TOML entry through
the **same** `inbound()`/`outbound()` factories into identical `Registry` entries, so it is a flat
endpoint list — **not** a graph-bundling "channel" element. "Code-first" is a default for *logic*, not
an identity rule binding transport config.

---


> **Governing standard:** *modular, loosely-coupled architecture with contract-defined boundaries
> (information hiding)* — so components can be built in parallel, by people or AI agents, without
> conflicts. The points below are how it's enforced in code; see
> [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) §"Architectural standard" for the rationale
> (Parnas information hiding, cohesion/coupling, contract-first, Conway's Law).
- **AI coding assistance is centrally governed** by an environment-clamped policy on an
  **OFF→PHI-safe** spectrum (`mode` × `data_scope`, bounded per `dev`/`staging`/`prod`), RBAC-gated
  by `ai:assist`. The MVP assistant only ever sends **code** (`code_only`) — never message bodies;
  `phi` scope is future (engine broker over a BAA). Full model: [`docs/AI.md`](../../docs/AI.md).
- Don't build **visual / template-driven authoring** (drag-drop transformer, declarative
  field-mapping) — **declined-by-design (v0.2+)**: code-first Routers/Handlers *are* the
  differentiator (BACKLOG #26 — closed, so it lives in
  [`docs/archive/backlog/BACKLOG-CLOSED.md`](../../docs/archive/backlog/BACKLOG-CLOSED.md), not in the
  live ledger). *Narrow carve-out (2026-07-10, #26 amendment; widened to Routers 2026-08-05 per
  [ADR 0076](../../docs/adr/0076-typed-action-vocabulary-action-list-lens.md) Amendment D, BACKLOG
  #232):* a **structured Steps view** over real Python Handlers **and Routers** via a typed action
  vocabulary (BACKLOG #222 — closed, same archive; the router `route` row kind is #232, still open
  in [`docs/BACKLOG.md`](../../docs/BACKLOG.md), ADR-gated) is permitted — the
  carve-out was granted because the `.py` stays the **only artifact and the only execution path**,
  and that property holds identically for a `@router` (a byte-splice Steps view over a real
  `@router` projects destination selection from reviewable Python; it introduces no declarative
  artifact and no second execution path), so naming Routers does not cross the #26 line;
  declarative logic execution, declarative field-mapping, and drag-drop canvas logic authoring
  remain declined.
- Don't build **Serial (RS-232) / ASTM E1381/E1394/E1318** lab-instrument connectivity —
  **declined-by-design (v0.2+)**: no real feed demand, outside the HL7/FHIR/X12/DICOM scope
  (BACKLOG #27 — closed, so it lives in
  [`docs/archive/backlog/BACKLOG-CLOSED.md`](../../docs/archive/backlog/BACKLOG-CLOSED.md), not in the
  live ledger; the connector-parity row is [`docs/CONNECTIONS.md`](../../docs/CONNECTIONS.md)).
- Don't adopt **ISO/IEC 5055:2021 / OMG ASCQM** as a quality **measure** — **declined-by-design
  (2026-08-07)**, three reasons each independently sufficient: no free or open-source
  5055-conformant **Python** analyser exists (the conformant ecosystem is C/C++/Java/C#/COBOL-
  weighted), there is no contract counterparty for the clause the standard exists to support (it is
  written into development and outsourcing contracts; this is OSS on PyPI), and a weakness-**count**
  score collides with the anti-metric rule in
  [`docs/Code_Quality_Standards.md`](../../docs/Code_Quality_Standards.md) §4.1. **The catalogue is a
  different question and was adopted:** the ASCQM 1.1 weakness list is free from OMG, one bounded
  pass over it ran under **#1073**, and its findings are **#1089–#1093**. Re-running that pass is
  legitimate; adopting the score is not. *(#1073 is closed, so it lives in
  [`docs/archive/backlog/BACKLOG-CLOSED.md`](../../docs/archive/backlog/BACKLOG-CLOSED.md) once archived,
  not in [`docs/BACKLOG.md`](../../docs/BACKLOG.md) — a marker here has to outlive its item by
  construction, so it must not cite only the live file.)*
