# Step B — write amplification (staged pipeline, ADR 0001)

ADR 0001 made the **measured** write amplification of the staged pipeline the decision gate for the
full router/transform split. Step A introduced the `ingress` boundary and recorded its +1-commit cost;
Step B takes the split — adding the `routed` stage between routing and transform — and this note
records the realized 3-stage cost.

## The three-stage flow

A received message now flows `ingress → routed → outbound`, each boundary a single committed
transaction (claim → produce-next-stage rows → complete/consume this stage):

| | INSERTs | DELETEs | commits | persistent queue rows |
|---|---|---|---|---|
| Pre-staging (`enqueue_message`) | 1 message + N outbound + 1 event | 0 | 1 | N |
| Step A — `enqueue_ingress` (ACK boundary) | 1 message + 1 ingress + 1 `received` event | 0 | 1 | (1 ingress, transient) |
| Step A — `handoff` (combined route+transform) | N outbound + 1 `routed` event | 1 ingress | 1 | N |
| **Step B — `enqueue_ingress`** (ACK boundary) | 1 message + 1 ingress + 1 `received` event | 0 | 1 | (1 ingress, transient) |
| **Step B — `route_handoff`** (router stage) | H routed + 1 `routed` event | 1 ingress | 1 | (H routed, transient) |
| **Step B — `transform_handoff`** (transform stage, ×H) | (per handler) Mₕ outbound + 1 `transformed` event | 1 routed | 1 (each) | Mₕ |

For the common **single-handler** message (H = 1, delivering to N destinations), Step B is **three
transactions** (`enqueue_ingress` + `route_handoff` + `transform_handoff`):

- **3 commits/message** — up from Step A's 2, and the pre-staging baseline of 1 (≈3× the inline model,
  as ADR 0001 Q5 predicted).
- **+1 transient queue-row class** — the `routed` row, INSERTed at `route_handoff` and DELETEd at
  `transform_handoff` (on top of Step A's transient `ingress` row).
- **+1 `transformed` event** per handler — the disposition is logged as it flows
  (`received` → `routed` → `transformed`).
- **Persistent footprint is unchanged at N outbound rows.** Both the `ingress` and the `routed` rows
  are *consumed* (deleted) at their handoff, so the raw body is never kept twice at rest beyond the
  brief route→transform window — the same PHI-at-rest posture as Step A's ingress row (`docs/PHI.md`).

### Multi-handler fan-out

When the router selects **H** handlers, `route_handoff` produces H routed rows in one transaction and
each handler then transforms in **its own** `transform_handoff` transaction, so the cost is **2 + H
transactions/message** (ingress + route + one transform per handler). The per-handler transaction is
the price of independent transform isolation/retry: a slow or failing handler's transform no longer
blocks routing — nor the other handlers' transforms.

## Why it's worth it

Step A bought **ACK-on-receipt** (the listener no longer blocks on routing/transform/delivery). Step B
adds **router-vs-transform isolation**: routing is its own durable, FIFO, retry/alert-policied stage,
so a slow or wedged transform can no longer stall routing, and each handler's transform is
independently observable, retryable, and replayable (a dead `routed` row recovers via per-message
replay, like a dead ingress row). At-least-once is preserved by the per-stage transactional handoff;
the extra re-run boundary is safe because routers and transforms are pure.

The modest +1-commit/message (single-handler) is acceptable at typical HL7 volumes (not high-
frequency). The multi-writer **SQL Server backend remains the scale path** for high volumes, gated on
BACKLOG #1 (`supports_ingest_stage = False` — the engine refuses to run the staged pipeline on it).

## Regression guard

`tests/test_staged_pipeline.py::test_write_amplification_persistent_row_footprint` drives the full
three-stage flow and pins the persistent footprint (exactly N outbound rows — no leftover `ingress` or
`routed` row, so the raw is never duplicated at rest) and the event trail
(`received` → `routed` → `transformed`), so an accidental change that keeps a consumed stage row
around — doubling raw PHI at rest — fails the suite.
