# Handoff — BACKLOG #232: Steps view for routers (2026-08-05)

> **Status going in.** The ADR gate is **discharged**: [ADR 0076](../adr/0076-typed-action-vocabulary-action-list-lens.md)
> **Amendment D** (owner-ratified 2026-08-05) widens the grammar with a `route` row kind, and
> [`CLAUDE.md`](../../CLAUDE.md) §12's carve-out now names Routers. **No feature code was written** —
> this lane was design-only. What remains is a straight build against a settled contract, not a
> decision. Everything below lets a session build it without re-deriving the design work.
>
> **This is a NOT-DEPLOYED beta with zero production instances.** #232 is a **low-severity capability
> gap** — no correctness or security risk, and no prior router Steps contract to preserve, so there is
> no migration or compatibility shim to build. Where this doc says a router "would" render or an older
> IDE "would" break, that conditional is deliberate.

## What #232 wants, and why it is not "point the lens at routers"

`lens parse` emits rows per `@handler` only — ADR 0076 §3 put routers "out of v1 scope" — so a
`@router` gets **no Steps view at all**: no "View as Steps" CodeLens on the def, no rows. An analyst who
can read a Handler as steps drops back to raw Python exactly where **destination selection and fan-out**
are decided.

A router does not mutate `msg`; it **selects destinations**. The shipped shape is a guard-and-return of
handler names ([`samples/config/IB_DEMO_ORU_router.py:22-27`](../../samples/config/IB_DEMO_ORU_router.py)):

```python
@router("demo_oru_router")
def route_demo_oru(msg):
    if msg["MSH-9.1"] != "ORU":
        return []
    return ["demo_oru_relay"]
```

The reason the v1 grammar excluded this is a **grammar gap, not a veto**: the v1 vocabulary is a
field-mutation roster (`copy_field`/`set_field`/…) over the mutable `Message` API, and it had **no row
kind** for a routing return. Amendment D §D.2 records the full finding (the #26 carve-out's "Handlers"
wording is INCIDENTAL; nothing that put routers out of v1 is a live blocker). Read Amendment D
(§D.1–§D.8) before building — it is the settled contract this handoff implements.

## The four build components

1. **A `route` row kind** (DECIDED, over overloading `send`). `send` rows carry outbound-connection
   names and belong to the outbound delivery stage; `route` rows carry **handler** names and belong to
   the routed stage. Different namespace, different pipeline stage — overloading `send` would fuse the
   two. Contract (Amendment D §D.3):
   `{ kind: "route", handlers: [..], unrouted?: true, line_start, line_end, nesting }`. `handlers`
   follows `send`'s literal-or-empty rule; `unrouted: true` is the additive discriminator for a
   routed-nowhere return, mapping to the store disposition **UNROUTED** (logged, never dropped).
2. **`return []` disambiguation by the enclosing decorator** (DECIDED — see "The `return []` resolution"
   below).
3. **A router-specific Add-palette group** — routing-relevant items only (route-to-handler, a guard, a
   comment). No transform verbs, no lookups (Amendment D §D.6: a router stays pure destination-selection;
   `db_lookup`/`fhir_lookup` raise outside a live Handler).
4. **Coverage-partition + byte-stable-splice parity** — a `@router` body must tile into
   `route`/`control`/`note`/`code` rows that exactly partition the def body, and a `route` edit must be a
   byte-stable row-scoped splice, exactly as the handler path already guarantees.

## Files the build will touch

Line numbers drift — anchors below were verified on this branch; locate exactly at build time. The build
touches **at least** the following:

- **[`messagefoundry/lens.py`](../../messagefoundry/lens.py)** — the parser.
  - Add a `_router_name(node)` keyed on `_callee_name(dec.func) == "router"`, mirroring `_handler_name`
    (`:343-360`).
  - In `parse_source`, stop the router `continue` at **`:306`** (`continue  # not a @handler (router or
    plain def) — out of v1 scope`) and emit a router entry discriminated by role (e.g. a `role` field, or
    a `router`/`handler` discriminator) so a consumer can tell a router projection from a handler one.
  - Thread the def's **role** from `parse_source` through `_partition_suite` (`:470`) → `_emit_stmt`
    (`:537`) → `_classify_simple` (`:667`) so a router `return []` classifies as a `route`/`unrouted`
    row while a handler `return []` stays **byte-identical** to today's `send`/`filtered` row
    (`:678-686`).
  - Keep the coverage-partition invariant (`_partition_suite` already tiles gaps/blanks/comments); a
    router body just recognizes `route` instead of `send` on its returns.
- **[`ide/src/editorToolbar.ts`](../../ide/src/editorToolbar.ts)** — the CodeLens/toolbar gate.
  - `hasHandler` at **`:64`** gates the "View as Steps" affordance on a `@handler`; extend it to routers
    (add a `hasRouter`, or generalize to "has a Steps-renderable element").
  - The per-element CodeLens gate `if (el.kind === "handler")` at **`:88`** adds "View as Steps" for
    handlers only; add the same lens for `el.kind === "router"`.
  - The `messagefoundry.activeFileHasHandler` context key at **`:131-132`** drives the editor-title
    button; add/relax it so a router-only file also offers the button.
- **[`ide/src/stepsView.ts`](../../ide/src/stepsView.ts)**, **[`ide/src/stepsModel.ts`](../../ide/src/stepsModel.ts)**,
  and **[`ide/media/stepsWebview.js`](../../ide/media/stepsWebview.js)** — render the `route` kind and the
  router Add-palette group. The kind MUST be threaded through **both** the TS model and the CSP-isolated
  webview (which cannot import from `src/`) — this is the same dual-implementation discipline Amendment A
  §A.7 records for `note`; a kind added to one alone renders a blank, titleless row in the other.
- **[`scripts/quality/lens_coverage.py`](../../scripts/quality/lens_coverage.py)** — router coverage
  stats. Out of scope for the first build increment, but the coverage scan may be extended to count
  router rows so the router recognition rate is measurable the way the handler rate is.

## The `return []` resolution (DECIDED)

The enclosing decorator disambiguates. Verified against the engine's own return normalizer
`_handler_names` ([`messagefoundry/pipeline/dryrun.py:98-101`](../../messagefoundry/pipeline/dryrun.py),
`list[str] | str | None`; `[]` == routed nowhere):

| in a `@router` | `route` row |
|---|---|
| `return []` / `return ()` / `return None` / a bare `return` | `handlers: []`, `unrouted: true` (message logged **UNROUTED**, never dropped) |
| `return ["a", "b"]` / `return ("a",)` (string-literal names) | `handlers: ["a", "b"]` |
| `return "a"` (bare string literal) | `handlers: ["a"]` |
| a non-literal element (`return [pick(msg)]`, `return names`) | `handlers: []`, **no** `unrouted` (dynamic; mirrors `send`'s empty-on-non-literal) |

In a `@handler`, `return []` is **unchanged**: it stays the `send` row with `filtered: true`
(`lens.py:678-686`). The role branch is the only thing that makes a router return classify as `route`, so
AC-R3 (assert the handler leg first) is the guard that the branch never regresses the handler path.

## ADRs to amend at build time

- **ADR 0076 — done here** (Amendment D). No further 0076 amendment is expected for the row kind.
- **ADR 0089 (recognition-first) and ADR 0108 (send fan-out)** — on current analysis these are
  **leveraged, not widened**: neither names routers, and the router path reuses their recognition and
  partition machinery rather than changing their contracts. The builder should **re-confirm** this the
  moment the router body needs a construct those ADRs own (e.g. an accumulator-style routing idiom), and
  amend if so — but nothing found in this lane requires it.

## Red-by-design tripwires — do not "fix" them early

[`ide/src/test/suite/editor-toolbar.test.ts:62`](../../ide/src/test/suite/editor-toolbar.test.ts) asserts:

```ts
assert.strictEqual(hasHandler('@router("IB")\ndef route(msg): ...'), false);
```

This is **correct today** (a router-only file cannot open as Steps) and **inverts when the build lands**
(a router file will open as Steps, so `hasHandler` — or its router-aware successor — must report the file
as Steps-renderable). It is a deliberate tripwire, **not a flake and not a regression**. When you build:
update this assertion as part of the change, and do not touch it before then. A builder who "fixes" it
early, or who reads its future inversion as a regression, has misread it.

**At least two further published assertions invert the same way.** They are recorded here so the builder
updates them deliberately and does not read their post-build failure as a regression. Each is a **correct
statement about the shipped code today** — the build is not done, so none is a false present-tense claim;
the build is what inverts them:

- **`tests/test_lens_parse.py:435` — `test_routers_are_out_of_scope`.** Its body ends
  `assert [c["handler"] for c in contracts] == ["h"]  # router excluded`. Once a `@router` gets a
  projection, that list would gain the router and both the assertion and the test's intent must be
  rewritten — update it in the same change that adds the `route` row.
- **`docs/testing/master-test-plan/13-steps-editor.md` — STEPS-52, STEPS-46, and the `:39` "already
  covered" row.** STEPS-52 (`:149`, **P1**) is literally "Routers have no Steps view, at the provider
  level too"; STEPS-46 (`:143`) says the "View as Steps" CodeLens "appears only on a `@handler`"; the
  `:39` evidence row records "routers out of scope (`:435`)". Amendment D §D.1 supersedes that scope, so
  all three describe the **pre-build** state and would need reconciling when the build lands. **Editing
  the master test plan is out of this lane's scope** — it is flagged here (and surfaced to the owner) so
  the builder reconciles it deliberately rather than being surprised when STEPS-52 has to become "routers
  **do** have a Steps view".

These are forward-reconciliation notes, not defects: every one is true of the code as shipped, and the
build is what inverts them — the same relationship the `editor-toolbar.test.ts:62` tripwire has.

## Contract-version skew (must be handled, not discovered)

Mirror Amendment A §A.7. `parse_source` emits no schema version and the extension shells whatever
`messagefoundry` is on `PATH`. An older IDE receiving `kind: "route"` hits the default-less title switch
and renders a **blank, titleless row**. **Gate `route` emission behind a flag or a contract version**, and
thread the kind through both `ide/src/stepsModel.ts` and `ide/media/stepsWebview.js`. `route` is additive
for handlers (a `route` kind appears only for a `@router`), so the flag/contract gate is the whole
compatibility story.

## Corrected anchors (the item's own citations drifted)

- The lens router skip is at **`lens.py:306`** — the #232 item body says `:305` (off-by-one). `:344-347`
  in the item points inside `_handler_name`, whose full span is `:343-360`.
- The sample router is [`samples/config/IB_DEMO_ORU_router.py:22-27`](../../samples/config/IB_DEMO_ORU_router.py).
- **Citation trap (§3 vs §4).** The #232 item, its BACKLOG banner, and its ranked-table row all say the
  `route` kind "widens the ADR 0076 §3 grammar". Per ADR 0076 §2 the *grammar* rule points at **§4**
  (recognition grammar + degradation ladder); **§3** is the row **enum**. The `route` kind touches §3's
  enum **and** §4's grammar — cite it that way (Amendment D does). The BACKLOG banner is corrected in this
  lane; the **ranked-table row (`docs/BACKLOG.md:234`) is off-limits to this lane and is flagged to the
  owner** to correct separately.

## Gates

All docs edits in this lane; the build's gates are the project quartet plus the doc guards:

```
python -m ruff check .
python -m ruff format --check .
python -m mypy messagefoundry
python -m pytest -q                 # name BOTH testpaths if you touch messagefoundry_webconsole/
python scripts/docs/backlog_status_check.py
```

When the build lands, follow the project's falsify-every-new-test rule: for each new router test (the
coverage-partition property, the route-return classification, the handler-vs-router byte-stability guard,
the router-palette scope, the contract-version-skew guard), break the thing on purpose, watch the new
test go red, then restore — and report the falsification you actually ran.

## Open questions (settle with the owner before or during the build)

1. **Amendment D acceptance status.** Recorded as ACCEPTED (owner-ratified, build handed off), parallel to
   Amendment A, with a **counted** Acceptance-Criteria block. Confirm it should be counted (not PROPOSED
   under a distinct heading like Amendments B/C).
2. **Router-body recognition scope.** Recommendation: recognize routing constructs only — `route` returns,
   control rows, `note`, `code` — and offer only routing-relevant Add-palette items. A router must stay
   pure destination-selection. Confirm.
3. **`unrouted` label.** Recommendation: an additive `unrouted: true` on the route row (distinct from the
   handler `send`'s `filtered: true`), matching the store disposition UNROUTED. Confirm the flag/wording.
4. **The stale ranked-table row.** `docs/BACKLOG.md:234` says the `route` kind "widens the ADR 0076 §3
   grammar" and reads better as "§3 enum + §4 grammar". It is off-limits to this lane (never touch the
   ranked table). Owner to decide whether to correct it outside this lane.
