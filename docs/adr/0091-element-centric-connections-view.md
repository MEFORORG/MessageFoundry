# 0091 — Element-centric Connections view over an authoritative static wiring graph

**Status:** Accepted (2026-07-11) — owner authorized the D1+D2 build same-day ("start D1 and D2"); D1+D2 built; **D3 v1 built 2026-07-12** (owner go — see the resolved go gate below).
**Deciders:** owner (ratifies) + IDE/DX working group
**Related:** [ADR 0076](0076-typed-action-vocabulary-action-list-lens.md) (the static `lens parse` AST discipline this extends), [ADR 0007](0007-gui-manageable-connections-toml.md) (connection transport config as data — the gear/edit affordances the redesigned view keeps), [ADR 0031](0031-startup-connection-fault-isolation.md) (degraded `failed` connections the view should surface), [ADR 0035](0035-ide-extension-workspace-trust-and-scope.md) (the exec gate every refresh honors), [ADR 0052](0052-enterprise-scale-target.md) (the ~1,500-connection target that bounds any whole-graph render), BACKLOG #152/#176 (the reverse-reachability index, merged PR #919), CLAUDE.md §1 (*"The configuration is a **graph** … all wired by name"*, *no grouping unit*) and §12 (*don't build a "channel"/"route" element*; #26 — no visual/drag-drop authoring).
**Code references** are `origin/main` at authoring (`ce923c3`); cited by module + symbol, line numbers omitted deliberately — locate at implementation time.

---

## Context

### The owner's element model (2026-07-11 directive)

The owner restated the intended model as four completely separate items, wired by name:

- **Inbound connection** — drains to exactly **one** router; **uniquely owns a port** on the engine; the system checks for and prevents port conflicts.
- **Router** (Python) — sends to as many handlers as needed; **one router may be the sink for multiple inbound connections**.
- **Handler** (Python) — may **receive from multiple routers**; may send to **any number of outbound connections**.
- **Outbound connection** — may **receive from any number of handlers**.

The goal: keep the wire-by-name nature simple, supporting one-to-one and one-to-many (and many-to-one) setups, with the items broken out so interface construction stays simple for the developer.

**The engine already enforces every clause of this.** Verified against `origin/main`:

- One router per inbound: `InboundConnection.router` is a single required `str` (`config/wiring.py`); an unresolved name fails the **required** `validate` gate (`Registry.validate` / `validate_config`).
- Port ownership is protected in layers: static duplicate-port detection (`Registry.port_collisions`, listener types, overlapping hosts); an env-resolved pre-flight that also reserves the engine API's own port and raises `PortConflictError` **before anything binds** (`inbound_binding_conflicts`, run by `build_check_registry`); a per-connection guard before each OS bind (`_guard_port_conflict`); and an external-process bind failure classified and isolated as a degraded `failed` connection per ADR 0031 — never a crash.
- N-inbounds→1-router, N-routers→1-handler, N-handlers→1-outbound: all legal; no cardinality or ownership constraint exists anywhere. A `Send` to an unknown outbound fails closed at the transform stage (`transform_one`) and dead-letters — count-and-log intact.

So this ADR changes **no engine semantics**. The defects are in the layer that *presents* the model and the layer that *derives* it for tooling.

### Defect 1 — the CONNECTIONS tree invented a hierarchy the architecture doesn't have

The IDE's CONNECTIONS view (`ide/src/graphTree.ts`) nests the router under its inbound and handlers under the router, with outbounds interleaved alphabetically among the inbounds at the root. Consequences, all observed in the current code:

1. **Implied containment/ownership.** The nesting reads as "this inbound *contains* this router" — the exact bundled-channel reading CLAUDE.md §1 retires. There is no design doc behind the nesting; the view grew organically (its only design note is its own file-header comment).
2. **Silent duplication of shared nodes.** A router named by two inbounds is materialized once per inbound; a handler returned by two routers likewise; an outbound appears at the root *and* under every sending handler. No dedup, no "shared" marker anywhere.
3. **Fan-in is invisible.** Standing on a handler there is no way to see which routers feed it; standing on an outbound, no way to see which handlers send to it — precisely the many-to-one relationships the owner's model calls out. (The reverse-reference index from #919 already computes this; nothing renders it.)
4. **Context actions exist only on connection roots** (`viewItem == meforConnection`); router/handler rows get none.

### Defect 2 — the edge data feeding the view is best-effort and triplicated

The tree consumes `messagefoundry graph --json` (`__main__.py:_graph`), which **imports/executes** the config and then derives router→handler and handler→outbound edges by scanning each function's **compiled string constants** (`_referenced`/`_string_consts`) — by its own comment, *"best-effort … misses computed names."* A `Send` target held in a module-level constant, or any computed name, silently drops the edge — so a chain **truncates with no indication anything is missing**. (This, not the view design, is why a real feed's handler showed no outbound in the owner's session — the tree *does* nest Send targets when the scan finds them.)

Meanwhile the repo carries **three inconsistent extractors** of the same edges: the `graph` CLI's bytecode scan, `config/reachability.py`'s own heuristic scan (feeding only the advisory dead-config check), and the ADR 0076 lens's AST parse of literal `Send(...)` targets (`lens.py:_send_outbounds`) — the most precise of the three, but handlers-only (routers are explicitly out of lens scope) and consumed only by the action-list editor, never by the tree.

There is also **no static validation of `Send` targets**: a typo'd literal `Send("OB_Wrong", …)` passes `messagefoundry check` unless a fixture happens to exercise that handler, surfacing only at runtime as a post-ACK dead-letter.

### External evidence (deep-research pass, adversarially verified 2026-07-11)

A fan-out research pass (19 sources, 25 claims verified 3-0 unless noted) converged on the same verdict:

- **Rendering a multi-parent DAG as a strict tree is a documented UX failure.** NN/g's polyhierarchy work names it (a child with multiple parents cannot be represented in a single-parent tree without duplication); **Apache Airflow retired its Tree view for exactly this** — *"a tree diagram cannot properly represent a graph … users being confused seeing multiple leaves representing the same task"* (apache/airflow#18675).
- **The closest healthcare-engine precedent does what this ADR proposes.** Rhapsody presents communication points (endpoints) as first-class standalone components in flat sections, **referenced by routes rather than nested under them**, one name consistent across workspace/route/monitoring surfaces; its monitoring UI is two parallel flat sections (routes; communication points) with per-element state + counts. The owner's first-hand Corepoint description matches: connections (in/out) and action-list logic units are separate element lists wired by reference — there is no "route" object there either.
- **By-name cross-references are the standard mitigation.** Node-RED's link nodes replace drawn/nested wiring across views with an explicitly many-to-many named reference.
- **VS Code UX guidelines** (verified live 2026-07-11): tree views are the endorsed sidebar surface "from simple flat lists to deeply nested trees"; *"avoid deep nesting unless necessary"* (a soft strike against the current 4-level chain); webviews *"only … if you absolutely need them"*, with sidebar webview views explicitly to be limited — a graph canvas is sanctioned only as an **on-demand editor-area panel** (Nx Console is the shipped precedent: a read-only project-graph webview launched on demand, focusable on one element).
- **Read-only graph views over code are the established code-first pattern** (Dagster global asset lineage, Airflow graph view, Nx project graph, Terraform `graph` → DOT); drag-drop canvases belong to canvas-as-source-of-truth tools (NiFi, Rhapsody's route editor) and scale via the containment/grouping element this project **declines by design**. Scale caveat: Dagster's global lineage is documented degrading near ~200 nodes — read against the ADR 0052 ~1,500-connection target, any canvas must be focus/filter-first, never whole-estate-by-default.
- **An end-to-end "by-flow" reading is a recognized complementary perspective** (Node-RED: *"easy to read an individual flow from start to finish"*) — a complement to, not a replacement for, the element view (medium confidence; single-vendor authoring guidance).

## Decision

Rebuild the CONNECTIONS surface as an **element-centric view over one authoritative static wiring graph**, in three parts. The four element kinds become the display's first-class citizens — matching both the engine's actual model and the owner's directive — and every edge shown is either real or explicitly marked unresolvable.

### D1 — One authoritative static wiring graph (engine)

Replace the three parallel edge derivations with a **single extractor** producing one graph contract, emitted by `messagefoundry graph --json` (shape v2, additive):

- **AST-first extraction** (ADR 0076 static discipline — stdlib `ast`, never import/execute for edge purposes): extend lens-grade parsing to **routers** (literal handler names in `return` statements) alongside the existing `_send_outbounds` handler parsing; retain the compiled-constants scan as a **fallback tier** for shapes AST misses.
- **Edge provenance** on every edge: `literal` (AST-proven) / `heuristic` (string-constant scan) / `dynamic` (a return/Send whose target could not be statically resolved — emitted as an explicit dangling marker, never silently omitted).
- **Forward and reverse adjacency** in one payload (inbound→router, router→handlers, handler→outbounds, plus each element's referrers), so no consumer recomputes fan-in. `config/reachability.py` and the `graph` CLI converge on this one derivation (dead-config/#152 impact analysis become consumers, not siblings).
- **A new advisory check** (`send-target`, `required=False`, mirroring the existing advisory pattern): a **literal** `Send`/router-return naming no known outbound/pass-through/handler prints a nudge with handler + target name. Advisory only — dynamic names are legitimate; the runtime fail-closed path (ADR 0001 dead-letter) remains the authority.

### D2 — The CONNECTIONS view: four element sections, cross-referenced by name (IDE)

The sidebar tree becomes four flat sections — **INBOUND CONNECTIONS · ROUTERS · HANDLERS · OUTBOUND CONNECTIONS** — in pipeline order. Rules:

- **Every element appears exactly once**, under its kind. Expanding an element shows **reference children**, grouped by direction: an inbound shows `→ routes to <router>` (and its port + transport in the description — the uniquely-owned resource made visible); a router shows `⇦ fed by (N)` inbounds and `→ sends to (N)` handlers; a handler shows `⇦ fed by (N)` routers and `→ sends to (N)` outbounds; an outbound shows `⇦ receives from (N)` handlers.
- **Reference children navigate** — activating one reveals the target element in its own section (the Node-RED link-node / "find all references" pattern) — while the element row itself keeps today's open-source-location command.
- **Dynamic edges render explicitly** — `→ (dynamic — not statically resolvable)` — never a silently shorter list.
- **A by-flow perspective is retained as a secondary toggle** on the existing view-toolbar (where group-by-type/partner already lives): the today-style inbound→router→handler→outbound chain, completed to the outbound leaf and with every shared node badged (`shared ×N`) so duplication reads as *reference*, not identity. Element view is the default; flow view is the complementary end-to-end reading.
- Existing affordances carry over: filter/group, gear → `connections.toml` form vs open-source (ADR 0007), edit/clone, ADR 0031 degraded-`failed` badging, the ADR 0035 exec gate, and `graph.refresh()` triggers. Context actions extend to router/handler rows (open source; open action-list lens for handlers).

### D3 — Wiring Map panel (deferred; explicitly out of this ADR's build)

A **read-only** graph canvas of the estate as an **on-demand editor-area webview** (Nx Console pattern), rendering the natural 4-layer DAG with real edges, node→source navigation, and **focus/filter as a first-class requirement** (open focused on one element/feed/partner; whole-estate render is never the default, per the Dagster ~200-node degradation vs the ADR 0052 target). Strictly a projection of D1's graph — **no drag-drop authoring, no editing** — so BACKLOG #26's declined-by-design (visual authoring) is untouched: the `.py` stays the only artifact and execution path. Ships only after D1+D2 prove the graph contract; gated by its own go decision.

**What this must not break:** no grouping element is introduced — the sections are *element lists keyed by kind*, not bundles; nothing here creates an object/runner/config surface that wires a path (CLAUDE.md §12). The lens stays static and single-module. `graph --json` v2 is additive so existing consumers (name completion, chat context) keep working. Engine runtime behavior is untouched.

## Acceptance Criteria

> EARS form; each links (`→`) to the test that verifies it (built with D1+D2, 2026-07-11).

- **AC-1** — THE SYSTEM SHALL emit, from `messagefoundry graph --json`, every inbound/router/handler/outbound **exactly once**, with forward **and** reverse adjacency and a provenance tag (`declared`/`literal`/`heuristic`) on every edge.
  → `tests/test_graph_static.py::test_elements_once_with_forward_and_reverse_edges` · `::test_graph_cli_v2_shape_and_backward_compat`
- **AC-2** — WHEN a handler (or router) references a **literal** name that resolves to no known outbound/pass-through (or handler), `messagefoundry check` SHALL print an advisory `send-target` result and SHALL NOT fail the gate.
  → `tests/test_graph_static.py::test_send_target_advisory_flags_dangling_literals_never_blocks`
- **AC-3** — WHEN an edge target cannot be statically resolved, THE SYSTEM SHALL mark the element `dynamic` and the views SHALL render an explicit dynamic marker — never a silently truncated chain.
  → `tests/test_graph_static.py::test_computed_targets_mark_dynamic_never_silently_empty` · `ide/src/test/suite/graph-model.test.ts` ("dynamic elements render an explicit marker")
- **AC-4** — WHILE the element perspective is active, THE SYSTEM SHALL render each element under exactly one section exactly once, and activating a reference child SHALL reveal the target element.
  → `ide/src/test/suite/graph-model.test.ts` ("four sections, every element exactly once"; "cross-reference rows point at their target element")
- **AC-5** — WHEN a router is named by N inbounds (or a handler by N routers, or an outbound by N handlers), THE SYSTEM SHALL list all N under the element's `fed by`/`receives from` group — fan-in is always visible.
  → `tests/test_graph_static.py::test_elements_once_with_forward_and_reverse_edges` · `ide/src/test/suite/graph-model.test.ts` ("fan-in is visible")
- **AC-6** — WHILE the flow perspective is active, THE SYSTEM SHALL badge every node that appears under more than one parent (`shared ×N`) and SHALL complete each chain to its outbound leaves (or a dynamic marker).
  → `ide/src/test/suite/graph-model.test.ts` ("the chain is completed to the outbound leaves, shared nodes badged")
- **AC-7** — WHERE existing consumers read the graph JSON (completion, chat), THE SYSTEM SHALL keep the v1 fields intact (v2 is additive), and the IDE SHALL still render a v1 payload (older CLI) by normalizing it client-side.
  → `tests/test_graph_static.py::test_graph_cli_v2_shape_and_backward_compat` · `ide/src/test/suite/graph-model.test.ts` ("v1 payload normalization")

## Options considered

1. **Element-centric four-section view over one authoritative graph, flow perspective as secondary toggle, canvas deferred** (D1+D2, D3 gated) — **CHOSEN.** Renders the owner's model literally; fan-in visible; duplication eliminated in the primary view and labeled in the secondary; strongest external precedent (Rhapsody flat sections, Corepoint's own shape, Airflow's tree retirement, NN/g).
2. **A: keep the nested chain, complete + badge it** — Rejected *as primary*: reproduces the documented duplication pitfall (the Airflow retirement case) and sits at the "avoid deep nesting" boundary; retained as the secondary flow perspective where an end-to-end reading is the point.
3. **C: co-equal dual toggle** — Folded into 1: no shipped precedent of co-equal by-flow/by-element toggles in one tree surfaced; evidence supports element-primary + flow-complementary.
4. **D: webview DAG canvas as the primary surface** — Rejected: VS Code guidelines make sidebar webviews a last resort; scale risk at the ADR 0052 target; deferred to an on-demand, read-only, focus-first panel (D3).
5. **Fix only the data layer, keep today's nesting** — Rejected: reliable edges make the duplication and fan-in blindness *worse* (more shared subtrees rendered, still no reverse view).
6. **Status quo** — Rejected: the view teaches a containment model the architecture deliberately does not have, and silently truncated chains misrepresent real estates (observed on a live feed 2026-07-11).

## Consequences

**Positive** — The display finally matches the engine's (and the owner's) model: four first-class element kinds, wired by name, fan-in and fan-out both visible, nothing silently missing. One graph derivation feeds the tree, completion, dead-config/#152 impact analysis, and any future surface (web console graph, D3 canvas). The `send-target` advisory catches dangling literal Sends at check time instead of runtime dead-letter. Inbound rows surface their uniquely-owned port.

**Negative / risks** — An end-to-end trace in the element view takes three expansions instead of one (mitigated by the flow toggle and reference navigation). Static extraction remains static: computed names render as `dynamic` — honest but not complete (the runtime fail-closed path stays the authority). Two renderers over one model is more IDE code than one. D3's usability at estate scale is flagged, not proven; it stays gated.

**Out of scope** — Any authoring canvas or drag-drop wiring (declined-by-design, #26); any channel/route grouping element (§12); engine HTTP API graph endpoints (a possible follow-on for the web console — not needed by the IDE, which shells the CLI); renaming the Connection/Router/Handler vocabulary; the PySide6/web consoles' own displays.

## Resolved on acceptance (2026-07-11, with the D1+D2 build)

- [x] **View naming:** the view keeps its "Connections" name — the section headers (Inbound Connections / Routers / Handlers / Outbound Connections) make the four kinds explicit without churning the container identity users already know.
- [x] **Graph v2 schema:** a new `config/graph.py` is the single extractor (`build_wiring_graph` → `WiringGraph`: provenanced `WiringEdge`s, `dynamic` element set, `dangling` literal refs); the `graph` CLI and `config/reachability.py` both consume it. JSON v2 = top-level `version: 2`, per-element `edges` (`{target, target_kind, provenance}`), `fed_by`, `receives_from`, `dynamic` — v1 fields untouched.
- [x] **Lens scope:** a sibling AST walker inside `config/graph.py` (returns + `Send` targets + single-assignment module constants); `lens.py`'s ADR 0076 handlers-only charter is untouched.
- [x] **Backlog lanes:** none needed — the owner authorized the build same-day and D1+D2 landed with the ADR flip.

## Deferred follow-ups (all closed 2026-07-12)

- [x] **Live decorations** — shipped 2026-07-12 (owner authorized 2026-07-12). Opt-in (`messagefoundry.liveStatus.enabled`, default off; `intervalSeconds` ≥ 5) poll of the engine's `GET /connections` (`Permission.MONITORING_READ` — the lowest read tier, same as the Console dashboard; no new engine route or permission) feeding status + message counts as description suffixes on inbound/outbound rows (`ide/src/liveStatus.ts` poller, pure `liveStatusModel.ts` row aggregation, `graphModel.ts` suffix rendering, `GraphProvider.setRuntime`). Destination rows (one per inbound→outbound edge) aggregate per outbound: counts sum, worst-severity status wins. Auth is **passive**: the poll reuses the SecretStorage session Stage → Promote signed in with (`auth.peekToken` — never prompts from a timer) behind the SEC-005 host gate; 401 clears the dead session, 401/403/unreachable all degrade silently to undecorated rows (a dev engine embedded `allow_no_auth` serves it tokenless). Counts + status words only — never message content. *Residual gap, honest by design:* router/handler rows stay undecorated — the engine keys its stage metrics by connection, so no per-router/per-handler runtime counter exists to show.
- [x] **Refresh** — shipped 2026-07-12: a config-dir `FileSystemWatcher` (`**/*.py`, `connections.toml`, `codesets/**/*.csv`; `ide/src/configWatcher.ts`) and the save handler both funnel into one debounced (750 ms, `configRefresh.ts` `RefreshCoalescer`) validate + graph + code-sets refresh, so an external edit (git pull, another tool) refreshes without double-firing against the save path; exec-gated (ADR 0035) exactly like the save handler. A `configDir` resolving outside the workspace folder is not watched (graceful: manual refresh still works); the watcher rebuilds when the setting changes.
- [x] **D3 go gate:** resolved — **owner go 2026-07-12**. v1 scope: a **focus-first** (always opened focused on one element — tree selection, context menu, or QuickPick), **hop-bounded** (1–3, default 2, BFS both directions), **node-capped** (150, farthest hop dropped deterministically, truncation surfaced), strictly **read-only** editor-area webview (`ide/src/wiringMap.ts` over the pure `ide/src/wiringMapModel.ts`); dynamic elements render a synthetic "?" stub, edges carry their D1 provenance (solid = declared/literal, dashed = heuristic). A **whole-estate render is deliberately absent** (the Dagster ~200-node degradation vs the ADR 0052 target) — an unfocused build is legal only under the node cap. No drag-drop, no editing (#26 untouched).

## References

- Owner directive + screenshot session, 2026-07-11 (the four-element spec quoted in Context; the truncated `IB_400_EKG…` chain).
- Research pass (2026-07-11, adversarially verified): NN/g polyhierarchy (nngroup.com/articles/polyhierarchy); Airflow Tree-view retirement (apache/airflow#18675, airflow.apache.org UI docs); Rhapsody Administration Manual (flat routes/communication-points sections); Node-RED flow-structure docs (link nodes); VS Code UX guidelines — views + webviews (code.visualstudio.com/api/ux-guidelines, verified live 2026-07-11); Nx explore-graph docs + Nx Console marketplace listing; Dagster webserver docs (global asset lineage; ~200-node degradation from its tracker); Terraform `graph` CLI docs; NiFi user guide (relationships/connections; Process Groups = the declined grouping element).
- Code: `ide/src/graphTree.ts` (current provider), `ide/src/extension.ts` (view creation/refresh), `messagefoundry/__main__.py` `_graph`/`_referenced`/`_string_consts` (current derivation), `messagefoundry/lens.py` `_send_outbounds` (AST Send extraction), `messagefoundry/config/reachability.py` (#919 reverse index), `messagefoundry/config/wiring.py` (`InboundConnection.router`, `Registry.validate`, `port_collisions`, `inbound_binding_conflicts`), `messagefoundry/pipeline/dryrun.py` `transform_one` (fail-closed Send resolution).
