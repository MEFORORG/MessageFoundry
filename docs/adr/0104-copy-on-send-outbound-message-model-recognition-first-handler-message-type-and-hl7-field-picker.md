# ADR 0104 — Copy-on-Send outbound message model, recognition-first handler message-type, and HL7 field picker

**Status:** Proposed (2026-07-12) — draft for owner ratification. Build is **gated on Acceptance**.
**Deciders:** owner + IDE/DX + engine working group
**Related:** ADR **0076** (typed action vocabulary + Steps lens — the `.py`-only-artifact discipline this inherits), ADR **0089** (recognition-first lens over native `Message` idioms — the Steps surface the picker edits), ADR **0084** (`accepts=` router-stage seam — the enforcement seam Q2 reuses), ADR **0004** (payload-agnostic ingress / `RawMessage` — why Q2 is HL7-only), ADR **0057** (inline Step-A fast-path — the second execution path Q1/Q2 must hold on), ADR **0087** (subprocess sandbox — the pickle boundary `Send.message` must survive), ADR **0072** (traced dry-run — live values beside Steps rows), ADR **0005 / 0081** (`SetState` / `SetMeta` — the declarative-op precedent), ADR **0010 / 0043** (`db_lookup` / `fhir_lookup` — raise in the router phase), CLAUDE.md **§2** (reliability/purity), **§8** (HL7 conventions), **§12** (the #26 bright line), BACKLOG **#26** (declined visual/declarative authoring; the Steps-over-`.py` carve-out). Backing evaluation + competitor comparison: [`docs/research/message-model-eval.md`](../research/message-model-eval.md).
**Code references** are `origin/main @ a79e14b`; line numbers drift — locate exactly at implementation time.

---

## 1. Context — the forcing problem

The owner's ask: *"our code should support a copy of the inbound message and an outbound message. The developer should not edit the inbound message … make it easier to follow even though we let people do full coding."* Plus an **HL7 field picker** for the Set-Field `path`, and whether **Handlers should declare their message type**. Three linked questions, one design surface:

1. **Q1 — message model.** Today [`parsing/message.py`](../../messagefoundry/parsing/message.py) has **no `Message.copy()`**. A Handler mutates `msg` in place then `Send("OUT", msg)`; `Send.message` holds a reference to the mutated object and `send.message.encode()` runs **once at handoff** ([`pipeline/dryrun.py`](../../messagefoundry/pipeline/dryrun.py) `transform_one`). Cross-handler isolation already exists (the routed stage carries the raw string and each handler re-parses its own `Message`); the stored ingress raw is never mutated. So "inbound immutability" is today a **mental-model** gap, not a data-corruption bug — **but** within a single handler there is no supported way to emit two *different* per-destination variants, and nothing makes the inbound read-only.
2. **Q2 — handler message-type declaration.** `Message.message_type`/`message_code`/`trigger_event` peek MSH-9 at runtime. Should a Handler *declare* the type it handles, and what would that buy?
3. **Q3 — HL7 field picker.** The Set-Field `path` (`PID-3.1`) is free-text in the Steps lens (ADR 0076/0089).

**Invariants in play (quoted verbatim from [CLAUDE.md](../../CLAUDE.md)):**

> "At-least-once now relies on a re-run re-deriving identical output, so **routers and transforms must be pure** (message in → message out, no external side effects); outbound connections must still be **idempotent**." (§2)

> "**every received message is persisted before the ACK** … nothing is accepted-and-dropped." (§2, count-and-log)

> "Don't build **visual / template-driven authoring** … code-first Routers/Handlers *are* the differentiator … a **structured Steps view** over real Python Handlers … is permitted — plain `.py` stays the only artifact and execution path." (§12, #26 carve-out)

**Estate reality (ADR 0089 §1, an AST scan of the migrated production estate):** **0** uses of the ADR 0076 typed vocabulary against **1,283** native `msg.set(...)` sites. Any new model that *requires adoption* to work will not work; any model that *forces a rewrite* of that estate is a non-starter.

**Competitor grounding** (full comparison + independent fact-check in the backing memo): every engine with a good field picker scopes it from a **declared or sampled structure** and keeps the path **free-text-degradable** (Corepoint typed `(handle, path)` rows; Mirth's example-template-scoped tree; Iguana's VMD; Rhapsody's message-definition-by-name with graceful degradation); every engine that generates code from a visual model carries an **unclosed round-trip seam**. Iguana and Rhapsody make the read-only-source + writable-copy pattern their default. **Caveat (verified):** their per-destination edit *safety* comes from **schema-bound** addressing MessageFoundry does not have — we borrow the *ergonomic pattern*, not a claim that a schemaless positional copy makes per-destination edits semantically safe.

This ADR was produced by a multi-agent evaluation whose recommendations were **majority-refuted and revised** by an adversarial panel (Q1 5/5, Q2 4/5, Q3 5/5) plus an independent competitor fact-check and a completeness critic; the load-bearing codebase claims were then re-verified against the tree. See §9 of the backing memo.

## 2. Decision

Record **all three** in this one ADR (one design surface), extending ADR 0076/0089, sibling to ADR 0084. Everything is **additive and opt-in where it matters**; every existing handler keeps working; the AGPL / Python / code-first / payload-agnostic differentiator is preserved. Build in sequence **Q1 → Q2 → Q3**.

### 2.1 Q1 — copy-on-Send outbound snapshot (structural clone), inbound read-only advisory

**`Send(to, message)` captures a defensive *structural* snapshot of a `Message` payload at construction time** (implemented copy-on-write to bound cost). Ship **`Message.copy()`** alongside as an ergonomic explicit clone. **Both are a structural clone of the parsed model — never `Message.parse(self.encode())`.** Inbound read-only stays **advisory** (documented; an opt-in `msg.readonly()` view for teams wanting a CI guarantee — never a default). **Reject** the distinct `OutboundMessage` type, the `def handle(inbound, outbound)` signature, the `msg.out` property, any hard input-mutation error, and **any object-identity fan-out lint as the load-bearing correctness guard.**

Why copy-on-Send rather than an opt-in `copy()` the estate must remember to call: the estate's dominant `set(); Send(); set(); Send()` idiom simply **becomes correct with zero handler edits**, including the helper- and loop-laundered forms a static lint provably cannot classify. The one signal that distinguishes a *divergence bug* from the *correct same-content archive+downstream idiom* is **whether the object was mutated between the two Sends** — which is exactly what snapshot-at-construction captures.

```python
# same-content fan-out (archive + downstream): both snapshots post-normalize → identical bytes
@handler("archive")
def handle(msg):
    msg["MSH-3"] = "FOUNDRY"
    return [Send("OB_ARCHIVE", msg), Send("OB_EHR", msg)]

# divergent fan-out: the classic "bug" now delivers per-destination, no copy() call needed
@handler("fanout")
def handle(msg):
    msg.set("MSH-5", "SYS_A"); a = Send("OB_A", msg)   # snapshot #1: SYS_A
    msg.set("MSH-5", "SYS_B"); b = Send("OB_B", msg)   # snapshot #2: SYS_B
    return [a, b]

# copy() stays available as readability sugar (structural clone, not re-parse):
class Message:
    def copy(self) -> "Message":
        """Independent mutable structural clone of current in-memory state —
        no encode→parse round-trip, no backend switch."""
```

**Why structural clone, not `parse(encode())` (verified correction).** `Message.parse` re-runs `normalize()` + a parse and **always uses the default (built-in) backend** ([`parsing/message.py`](../../messagefoundry/parsing/message.py) `parse` → `_backend.use_builtin()`); a `copy()` of an inbound that was parsed via the **python-hl7 fallback** would therefore silently **switch backends** mid-handler. A structural clone (`copy.deepcopy` of the built-in dict model; a clone of the `hl7.Message` for the fallback) snapshots current in-memory state directly, keeps the source's own backend, and removes any dependency on encode↔parse round-trip fidelity. (The earlier draft asserted `Message.parse` calls `.strip()` and loses terminal whitespace — that specific mechanism is **not** accurate: `normalize()` only collapses line endings. The backend-switch reason is real and independently sufficient; the ADR does **not** rely on the `.strip()` claim.)

**Non-HL7 (`RawMessage`) correction.** `RawMessage.raw` is a **writable** attribute and one `RawMessage` is **shared across sibling handlers**. copy-on-Send snapshots the `RawMessage` at construction (closing the within-handler duplicate-delivery case), but the **cross-handler** leak (a handler doing `rm.raw = transform(rm.raw)` corrupts siblings) is *not* fixed by snapshotting at Send. → **Now:** document the safe idiom (build N strings, `Send(to, str)`) and warn that mutating `.raw` before a Send is a sibling-leak foot-gun. → **Scan-gated fast-follow:** freeze `RawMessage.raw`. Do **not** ship the "already immutable" framing.

### 2.2 Q2 — recognition-first descriptive type; enforcement on the `accepts=` seam

**The handled HL7 message type is DESCRIPTIVE and RECOGNITION-FIRST** — inferred by the lens/`check` from the guards handlers already write (`if msg.message_code != "ADT": return []`) and from any existing `accepts=` — so the picker/lint light up across the estate with **zero new ceremony** and the declaration cannot drift from the guard (there *is* only the guard). An explicit **`message_type=` kwarg** on `@handler` is a **documentation escape hatch**, inert to the engine.

**Enforcement is NOT a new engine-interpreted flag.** It is an author-written, AST-visible predicate on the existing ADR 0084 seam:

```python
@handler("adt_to_epic", accepts=message_type_of("ADT^A01"))   # opt-in enforcement
```

`message_type_of("ADT^A01")` returns a **pure** predicate compiled to `message_code == "ADT" and trigger_event == "A01"` — **component-wise**, reading MSH-9.1/9.2 through the message's own MSH-2 separators and unescaping (never a whole-field caret-literal compare). Code-only (`"ADT"`), exact, list, and wildcard forms expand accordingly. It **fails loud** (raises → `ERROR`/dead-letter, deterministic on the same input, re-run-stable) on any message lacking MSH-9 (`RawMessage`, BHS/FHS batch) — never a silent decline. It inherits ADR 0084's ratified **FILTERED → UNROUTED** disposition shift, so it is always a deliberate author choice, never a default. HL7-only and optional throughout; **required is a non-starter** (`RawMessage` has no MSH-9 — contradicts payload-agnostic ingress, ADR 0004).

### 2.3 Q3 — extend the shipping autocomplete first; a thin, gated Steps picker

**Step 1 (do first):** the segment→field→component path drill-down **already ships** in [`ide/src/completion.ts`](../../ide/src/completion.ts) over the bundled [`ide/media/hl7schema.json`](../../ide/media/hl7schema.json), inside the `msg["…"]`/`.field("…")`/`.set("…")` surface the estate actually uses. **Extend that inline autocomplete** with message-type ranking (Q2) and `occurrence=`/`repetition=` snippet hints. Zero mode switch, no partial-projection failure mode, no new artifact — the ergonomic win with the least risk.

**Step 2 (gated):** a Steps-view picker for the Set-Field `path`, gated on **(a)** ADR 0089 Accepted **and (b)** a measured, nonzero, sustained adoption signal for the recognition lens itself (its base rate mirrors the 0/1,283 vocabulary result). Scope, thin and honest:

- **Path arg only.** A segment→field→component quick-pick over `hl7schema.json` that **always degrades to free-text** (Z-segments, site-custom fields, cross-version paths stay typeable); the picker never blocks a path. **Offered paths gated behind a dual-backend round-trip proof** (`parse → set(path, sentinel) → encode()` byte-identical on built-in *and* python-hl7); unproven depths degrade to free-text with an explicit "unverified round-trip" marker.
- **Occurrence/repetition — READ-ONLY display in the MVP** (matching [`messagefoundry/lens.py`](../../messagefoundry/lens.py) Phase A). Editing them re-points *which* segment instance / field repetition a write hits (a silent `msg.set` semantics change); that is a separately-ratified, test-gated phase.
- **Message-type scoping via a corrected resolver.** Trigger ≠ structure: `ADT^A04/A08/A13` all map to structure `ADT_A01`, and hl7apy `MESSAGES` is keyed by **structure** — a naive `"ADT^A08"` lookup misses. Emit a **trigger→structure resolver** centralizing the map MessageFoundry **already hand-maintains** in [`generators/adt.py`](../../messagefoundry/generators/adt.py) (`TRIGGER_TO_STRUCTURE`), key the table by structure id, **pin a version** (inbound strict `version`/MSH-12), make the **real synthetic sample authoritative** and the abstract structure the ranking fallback, **always union in Z-segments**, and make a scope **miss visibly distinct** from a Z-segment fallback. Scoping **ranks, never removes** — an "All segments" escape is always present.
- **No false-complete rows.** Computed (`msg.set(f"PID-{i}", v)`), conditional, helper-wrapped, and loop-`occurrence` writes are **not** rows — they are surfaced as an explicit **"unmodeled code present"** marker. The Steps view may never imply it shows every field write.
- **Projection over real `.py`.** The picker edits the path literal of a **native** `msg.set(...)` via the ADR 0089 byte-space per-argument splice — `.py` stays the only artifact/execution path; no stored model, no codegen, no canvas. A `message_type=` scope hint is **not** the `accepts=` precedent (it is read only by the IDE, never executed) — justified on its own inert terms.

## 3. The five spec blockers (close on paper before any build)

1. **MSH-9 component matching.** Whole-field equality returns False for 100% of conformant 3-component `ADT^A01^ADT_A01` traffic and hardcodes `^` → match `message_code`+`trigger_event` via MSH-2 (§2.2).
2. **Batch / non-MSH leading segment.** A BHS/FHS-led `Message` has no MSH-9; `field("MSH-9")` reads BHS-9. `message_type_of` must **raise**. State the **transport-dependent split contract**: **File-source ingress splits batches** (via [`parsing/split.py`](../../messagefoundry/parsing/split.py) `split_batch`, wired in [`transports/file.py`](../../messagefoundry/transports/file.py) — the "Tier 2.2" batch split; **not** ADR 0082, which is *outbound* batch aggregation), so each split message carries its own MSH-9 and matches normally; **MLLP does not split** (no batch handling in [`transports/mllp.py`](../../messagefoundry/transports/mllp.py)), so a batch over MLLP arrives as one `Message` and surfaces as a loud ERROR against an HL7-type-enforced handler.
3. **Fail loud on non-HL7.** A synthesized `getattr(m,"message_type",None)` returns `None` on `RawMessage` → silent UNROUTED, whereas the hand-written guard raises. `message_type_of` raises on any message lacking MSH-9 (§2.2); `check` warns when a `message_type`-bearing handler is bound to a non-`hl7v2` inbound.
4. **Structural-clone snapshot.** copy-on-Send/`copy()` must be a structural clone satisfying dual-backend `snapshot.encode() == source.encode()` over the escaping / repetition / custom-separator / Z-segment corpus — including a `set()` trailing-whitespace terminal field, an appended trailing-whitespace segment, and a **python-hl7 fallback-produced source** (§2.1).
5. **Execution-path matrix.** The snapshot invariant and the enforcement predicate must hold on **both** the split path (`dryrun.py` `transform_one`) **and** the fused inline fast-path (ADR 0057), and across the **subprocess sandbox** pickle boundary (ADR 0087) — see §4.

## 4. Purity / re-run, fan-out, and the execution-path matrix

**Purity / re-run.** A structural clone is a pure function of in-memory state (itself a pure parse of the immutable stored raw); it touches no clock/RNG/network and never mutates the ingress raw. Because it is a structural clone (not re-parse), `copy()`'s re-run purity **no longer depends** on encode↔parse round-trip stability. `message_type_of` is deterministic on the same input (raises identically on a non-HL7 body), so it is re-run-stable. Nothing here weakens at-least-once, FIFO, or count-and-log.

**The one honest behavior change.** copy-on-Send moves the delivery snapshot from **handoff-time** to **Send-construction-time**. For single-Send handlers and fan-out constructed at `return` with no interleaved post-construction mutation, bytes are **identical**. The only regression surface is a handler that constructs a `Send`, then mutates the *same* `Message` before returning, *relying on* the late mutation reaching that already-constructed Send (today's last-write-collapse-to-all-destinations). That reliance is almost always the bug this fixes, but it is a behavior change → **gated on an AST estate scan** for "construct Send, then mutate its referenced Message before return" before the default flips, and a **throughput benchmark** (copy-on-write keeps the common no-post-mutation path zero-copy).

**Sandbox (ADR 0087).** Under `[sandbox].mode=subprocess` the Handler runs in a child and returns `Send`s over a length-prefixed pickle pipe; `send.message.encode()` runs in the **parent**. Every `Send.message` (and the snapshot) must remain **picklable** — an invariant the build must assert. Cost note: today `[Send("A",msg),Send("B",msg)]` sharing one object pickle-memoizes to **one** serialized message; **N independent snapshots serialize N** — copy-on-write bounds this to divergent-fan-out cases, and the throughput benchmark must measure it (the 45M/day path is latency/CPU-sensitive). This cost is also why the distinct `OutboundMessage` type is rejected: its true ripple is not just "grows the `Send.message` union" — it also touches `_partition` narrowing, the `isinstance(send.message, str) else .encode()` branch, the pickle boundary, and mypy-strict narrowing at every Send/transform site. copy-on-Send incurs none of that.

**Inline fast-path (ADR 0057).** The fused path runs `route_only` + a single handler's `transform_one` inline in the router worker and materializes deliveries there, gated on M-single/M-deliver/no-state/no-passthrough. The snapshot invariant must be asserted on **both** paths. A single handler declined by Q2's `accepts=` predicate yields `names=[]` → the M-single fallback → the split path → UNROUTED; the build walks that sequence.

**PT / loopback (ADR 0013).** A `Send` to a PT inbound re-enters as fresh ingress and is re-parsed by that inbound's own Router — `Send` is not one delivery kind. A passthrough Send carries the raw for re-ingress (snapshotted like any other); a looped-back copy's `message_type` is re-peeked downstream (so any Q2 declaration there must match the **re-ingressed** body); ADR 0057 bars passthrough from the fused path, so PT + fan-out always takes the split path.

## 5. Acceptance Criteria

> Behavioural, EARS form; each links (`→`) to the test/fixture that will verify it. **Proposed — no code yet;** the `→` refs are the tests the build lane SHALL add (they will not resolve until then), following the ADR 0089 pattern.

- **AC-1** — WHEN a Handler constructs `Send(to, msg)` and then mutates `msg` before constructing a second `Send`, THE SYSTEM SHALL deliver to the first destination the message state **as of the first Send's construction** (per-destination divergence), on both the split and inline (ADR 0057) execution paths.
  → `tests/test_copy_on_send.py::test_divergent_fanout_snapshots_per_send`
- **AC-2** — THE SYSTEM SHALL produce, for `Message.copy()` and the copy-on-Send snapshot, an output whose `encode()` is byte-identical to the source's `encode()` on **both** the built-in and python-hl7 backends, including a trailing-whitespace terminal field, an appended trailing-whitespace segment, custom MSH separators, repetitions, and a fallback-produced source.
  → `tests/test_message_copy.py::test_structural_clone_encode_parity_both_backends`
- **AC-3** — THE SYSTEM SHALL implement `copy()`/the snapshot as a structural clone of the parsed model, NOT via `Message.parse(self.encode())`, and SHALL preserve the source's parser backend (no built-in↔python-hl7 switch on clone).
  → `tests/test_message_copy.py::test_clone_preserves_backend`
- **AC-4** — WHEN a fan-out `Send.message` is marshalled across the subprocess-sandbox pipe (ADR 0087), THE SYSTEM SHALL pickle and re-encode it in the parent without error.
  → `tests/test_sandbox_fanout.py::test_send_message_picklable_across_pipe`
- **AC-5** — THE SYSTEM SHALL match `message_type_of(spec)` component-wise on `message_code` + `trigger_event` read through the message's own MSH-2, matching a 3-component `ADT^A01^ADT_A01` and a message whose MSH-2 uses a non-standard component separator.
  → `tests/test_message_type_of.py::test_component_wise_match_three_component_and_custom_sep`
- **AC-6** — IF a message enforced by `accepts=message_type_of(...)` lacks an MSH-9 (a `RawMessage` or a BHS/FHS-led batch), THEN THE SYSTEM SHALL raise → record `ERROR`/dead-letter (never silently decline to UNROUTED, never accept-and-drop).
  → `tests/test_message_type_of.py::test_fail_loud_on_non_hl7_and_batch`
- **AC-7** — THE SYSTEM SHALL infer a Handler's handled message type from its native guard / existing `accepts=` (recognition-first) with no `message_type=` kwarg present, and expose it to the lens/`check`.
  → `tests/test_lens_type_inference.py::test_infers_handled_type_from_guard`
- **AC-8** — WHERE the Steps picker offers a path, THE SYSTEM SHALL have proven that path round-trips byte-identically on both backends; an unproven path SHALL degrade to free-text marked "unverified round-trip", and the picker SHALL never block a free-text path (Z-segments/site-custom always typeable).
  → `ide/src/test/completion.picker.test.ts::offered_paths_roundtrip_or_degrade`
- **AC-9** — THE SYSTEM SHALL resolve message-type scoping through a version-pinned trigger→structure resolver (`ADT^A08 → ADT_A01`), union in Z-segments and any segment present in the authoritative sample, rank-not-remove (an "All segments" escape always present), and render a scope miss visibly distinct from a Z-segment fallback.
  → `ide/src/test/completion.scoping.test.ts::trigger_to_structure_and_zseg_union`
- **AC-10** — THE SYSTEM SHALL mark unmodeled writes (computed/conditional/helper-wrapped/loop-`occurrence`) as "unmodeled code present" and SHALL NOT render them as editable rows (no false-completeness).
  → `messagefoundry/tests/test_lens_false_completeness.py::test_unmodeled_writes_marked`
- **AC-11** — THE SYSTEM SHALL leave existing handlers byte-for-byte unchanged in routing, disposition, and the runtime MSH-9 peek when they pass nothing new (`@handler("x")` / `@handler("x", accepts=…)`), and SHALL require no edit to the native `msg.set`/`Send(msg)` estate.
  → `tests/test_backcompat_estate.py::test_native_estate_unchanged`

## 6. Options considered

**Q1.** 1. **copy-on-Send structural snapshot + `copy()` sugar** — **CHOSEN** (fixes the whole estate with zero edits; the only signal separating divergence from same-content is mutation-between-Sends, which the snapshot captures). 2. *Opt-in `copy()` + static aliasing lint* — Rejected: 0/1,283 adoption predicts ~nil use; the lint provably false-fires on the correct archive+downstream idiom and misses helper/loop-laundered aliasing. 3. *Distinct `OutboundMessage` type* — Rejected: rewrites the estate, and ripples through `_partition`, the `.encode()` branch, the pickle boundary, and mypy-strict narrowing. 4. *`def handle(inbound, outbound)` / hard read-only inbound* — Rejected: breaks all 1,283 in-place-mutate sites; strict immutability is an ergonomics choice, not verified parity table-stakes. 5. *`parse(encode())` clone* — Rejected: silent backend switch on a fallback-parsed source.

**Q2.** 1. **Recognition-first descriptive type + `accepts=message_type_of(...)` enforcement** — **CHOSEN.** 2. *Engine-interpreted `@handler(message_type=…, enforce=True)`* — Rejected: compiling a decorator string into routing behavior is a second declarative execution surface (ADR 0076 bright line); whole-field matching silently UNROUTES 3-component types. 3. *Required declaration* — Rejected: `RawMessage` has no MSH-9 (ADR 0004).

**Q3.** 1. **Extend the shipping inline autocomplete first; gated thin Steps picker** — **CHOSEN.** 2. *Build the Steps picker now* — Rejected: the drill-down already ships in `completion.ts`; the Steps picker's adoption base rate is presently zero. 3. *Editable occurrence/repetition spinners in the MVP* — Rejected/deferred: editing them silently re-points which segment instance a write hits. 4. *hl7apy `MESSAGES` lookup keyed by trigger* — Rejected: it is keyed by **structure**; needs the trigger→structure resolver.

## 7. Consequences

**Positive.** Fan-out becomes correct for the whole native estate with **zero handler edits**; per-destination variants need no `copy()` discipline. The Steps view's linear "a Set-Field between two Sends affects only the later destination" mental model becomes **actually true** (closing a PHI-masking foot-gun). Type scoping + path lint light up on the estate with no new ceremony. `.py` stays the only artifact/execution path; #26 untouched.

**Negative / risks.** copy-on-Send is a real (if narrow) delivery-**timing** change — scan- and benchmark-gated. Snapshotting adds CPU + (under the subprocess sandbox) pipe-marshalling cost at fan-out; copy-on-write bounds it but it must be measured at the 45M/day target. Static declared/inferred type can diverge from runtime MSH-9 (a router legitimately feeding ADT **and** ORU to one handler) → the path lint stays **advisory** (rank-never-hide, All-segments always present). hl7apy 2.5.1 vs feeds spanning 2.3–2.7 and vs an inbound's declared strict `version`/MSH-12 → the catalog is marked a pinned superset, not a per-feed schema. `copy()` re-parses nothing and never re-validates via hl7apy → a copy of a strict-validated inbound is not re-validated (stated, not silently assumed).

**Out of scope.** Hard-enforced read-only inbound (opt-in `msg.readonly()` view only); freezing `RawMessage.raw` + a non-HL7 builder (scan-gated fast-follow); editable occurrence/repetition in the picker; multi-version schema tables scoped by MSH-12; value-side (HL7-table) pickers for coded fields; any `derive`/`copy_message` typed-vocabulary row (declined — a copy-on-Send `Send` and an author `copy()` stay unrendered native calls; the Steps carve-out never grows to express object lifecycle or fan-out topology).

## 8. To resolve on acceptance

- [ ] **Match grammar** — confirm the one-line spec for `message_type_of` / declaration: code-only (`"ADT"`), exact (`"ADT^A01"`), list, wildcard-as-sugar — so picker, resolver, and predicate agree (component-wise throughout).
- [ ] **Snapshot implementation** — copy-on-write vs unconditional structural snapshot: decide against the throughput benchmark; confirm the default-flip trigger for copy-on-Send after the estate scan.
- [ ] **Picker MVP breadth** — recognition-inferred type + generic catalog only first, or include sample-MSH-9 scoping (lean: defer sample scoping for a smaller, PHI-free MVP).
- [ ] **Non-HL7 fan-out** — string-building + `Send(to, str)` now (recommended) vs freezing `RawMessage.raw` / a builder later.
- [ ] **Value-side assist** — HL7-table values for coded fields (PID-8 etc.) is out of Q3's path-picker scope; schedule as a separate sibling item if wanted.
- [ ] **BACKLOG number** — allocate a BACKLOG item for the build (`pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind backlog -Title "…"`) and link it here before flipping to Accepted.
- [ ] **Confirm the two verified corrections** are honored in the build: no reliance on a `Message.parse` `.strip()` mechanism (§2.1); inbound batch split is `parsing/split.py`+`file.py`, not ADR 0082 (§3).
