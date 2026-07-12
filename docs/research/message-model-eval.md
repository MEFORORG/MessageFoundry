<!--
Backing evaluation for ADR 0104 (docs/adr/0104-…). Produced by a multi-agent design + competitor
research workflow whose recommendations were majority-refuted and revised by an adversarial panel
(Q1 5/5, Q2 4/5, Q3 5/5), an independent competitor fact-check, and a completeness critic — see §9.

Two post-memo verification corrections (the ADR is authoritative where it differs from this memo):
  1. §4 asserts `copy() = Message.parse(self.encode())` corrupts terminal whitespace via a `.strip()`.
     VERIFIED INACCURATE: parsing/peek.py `normalize()` only collapses line endings; it does not strip
     the body. The BACKEND-SWITCH failure (Message.parse always uses the default backend, so a copy of a
     python-hl7-fallback-parsed message switches backends) IS real and independently justifies the
     structural-clone-over-reparse recommendation. Do not rely on the `.strip()` mechanism.
  2. §5/§6 cite "ADR 0082" for BHS/FHS batch. ADR 0082 is OUTBOUND batch aggregation; INBOUND batch
     splitting is a File-source feature (parsing/split.py + transports/file.py "Tier 2.2"), and MLLP does
     not split. ADR 0104 §3 carries the corrected citation.
-->

# Decision Memo — Message model, Handler type declaration, and the HL7 field picker (revised, post-validation)

**To:** MessageFoundry owner
**Re:** Three linked design questions (Q1 outbound-copy / Q2 Handler message-type / Q3 field picker), pre-ADR
**Status of this memo:** synthesis + recommendation, revised after an independent competitor fact-check, a five-skeptic refutation panel per question, and a completeness critic. No ADR or code written yet. See §9 **Validation notes** for exactly what was challenged and how this revision responded.

---

## 1. TL;DR

- **Q1 — CHANGED. Make fan-out correct *structurally* via copy-on-Send, not via an opt-in `copy()` the estate won't adopt.** The panel refuted the original (opt-in `copy()` + advisory lint) 5/5, and it was right: (a) `copy() = Message.parse(self.encode())` was *proven* to corrupt terminal whitespace and to switch parser backends; (b) the "same object → ≥2 Sends" lint fires on the *correct* same-content archive+downstream idiom and misses helper/loop-laundered aliasing; (c) `RawMessage` is **not** immutable; (d) 0/1,283 adoption of the last opt-in vocabulary predicts opt-in `copy()` gets used ~never. Revised recommendation: **`Send(to, msg)` captures a defensive structural snapshot of a `Message` at construction** (copy-on-write to control cost). This closes the fan-out hole for the whole native estate with zero handler edits and makes divergent-vs-same-content fan-out resolve by snapshot *timing* — the one signal that actually distinguishes them. Keep `copy()` as ergonomic sugar (also a structural clone, not re-parse). Inbound read-only stays **advisory**. This is a delivery-timing change, so it is **gated on an estate scan + a throughput benchmark** (see §4).
- **Q2 — CHANGED. Descriptive type becomes recognition-first; enforcement stops being an engine-interpreted flag.** The panel refuted 4/5. Fixes folded in: (a) *recognition-first* — the lens/`check` **infer** the handled type from the guards handlers already write (`if msg.message_code != "ADT": return []`) and from existing `accepts=`, so the picker/lint light up on the estate with **zero new ceremony**; an explicit `message_type=` kwarg is a documentation escape hatch, not the primary path. (b) Enforcement is **not** a new `enforce=True` string the engine compiles — it is an author-written, AST-visible helper on the existing `accepts=` seam: `accepts=message_type_of("ADT^A01")`, staying inside ADR 0076's ".py is the only artifact and execution path." (c) Matching is **component-wise** (`message_code` + `trigger_event`, read via MSH-2, never hardcoding `^`) — fixing the 3-component `ADT^A01^ADT_A01` and custom-separator blockers. (d) The helper **fails loud** (ERROR) on a message with no MSH-9 (`RawMessage`, BHS/FHS batch) instead of silently declining to `UNROUTED`.
- **Q3 — CHANGED. Extend the autocomplete that already ships before building a heavier picker; make the picker humbler and honestly gated.** The panel refuted 5/5. Fixes: the primary win (segment→field→component path completion) **already ships** in `ide/src/completion.ts` inside the `msg["…"]`/`.set("…")` surface authors actually use — so **extend that inline autocomplete** (message-type ranking, occurrence/repetition snippet hints) as step one. A Steps-view picker is gated on **ADR 0089 Acceptance *and* a measured, nonzero adoption signal for the recognition lens itself**; ships path-arg splice **only**; keeps occurrence/repetition **read-only display** (matching lens.py Phase A — editing them re-points which segment instance a write hits and is a separate, test-gated phase); never renders a **false-complete** row list (computed/conditional/helper-wrapped/loop writes are marked "unmodeled code present"); and scopes via a **version-pinned trigger→structure resolver** with the real synthetic sample authoritative and Z-segments always unioned in.
- **Blockers to pin in the ADR spec before any build (expanded from one to five):** ① MSH-9 component matching (was the sole original blocker); ② batch / non-MSH leading segment (BHS/FHS) behavior + the transport-dependent split contract; ③ fail-loud on non-HL7 for the enforcement helper; ④ the copy-on-Send **snapshot must be a structural clone** and must satisfy dual-backend `snapshot.encode() == source.encode()`; ⑤ the subprocess-sandbox picklability + marshalling profile and the inline-fast-path (ADR 0057) invariant, on **both** the split and fused execution paths.
- **Net:** all three remain additive, opt-in where it matters, and preserve the **AGPL / Python / code-first / payload-agnostic** differentiator. Every existing handler keeps working (Q1's one behavior-timing change is scan-gated and only ever moves buggy last-write-collapse toward correctness). Recommend one **Proposed** ADR extending ADR 0076/0089, sibling to ADR 0084, sequenced so Q1 lands first.

---

## 2. The three linked questions and how they connect

1. **Q1 — Message model.** Should the inbound `Message` be read-only, with handlers editing an explicit outbound copy? Which API shape, and is immutability enforced or advisory?
2. **Q2 — Handler message-type declaration.** Should a Handler declare the HL7 message type it handles instead of relying solely on the runtime MSH-9 peek? Optional/required; descriptive/execution-affecting?
3. **Q3 — HL7 field picker.** Should the Steps-view Set-Field `path` param become a structured picker? Where does metadata come from, how is it scoped, how does it degrade, and how does it stay a projection over real `.py`?

**They are one design surface.** **Q2 scopes Q3** (a known message type ranks/scopes the picker and lints paths). **Q1 is the frame the picker edits within** — and after this revision the coupling is tighter and *helps*: copy-on-Send makes the Steps view's linear "a Set-Field between two Sends affects only the later destination" mental model **actually true**, closing the PHI-masking foot-gun the Q3 panel raised (§6). Decide together; build in sequence (Q1 → Q2 → Q3).

---

## 3. Competitor comparison

Confidence markers reflect the independent fact-check. **‡ = low-confidence / attributed opinion** (single third-party source or an inference the vendor never states). **† = directional** (verbatim-verified primary evidence, but from a dated or single document). Unmarked cells are verbatim-verified against resolving primary sources.

| Engine | Inbound vs outbound model | Field-mapping UX | Message-type declaration | Code escape hatch | Lesson for MEFOR |
|---|---|---|---|---|---|
| **Corepoint** (Rhapsody/Lyniate)† — core mechanics from a single 2016-era vendor blog; admin docs paywalled | Typed action rows operate on a named "message handle" + an "HL7 path". **‡** Multiple *distinct* source/destination message objects is an **inference**, not vendor-stated; **‡** read-only source handle is **unverified** (neither confirmed nor denied). | Typed action rows with `(handle, HL7-path)` operands; structure/segment-aware editor, path pre-population, literal-vs-path source toggle. Not drag-drop, not free-text-only. `ItemCopy` is first-party confirmed; **‡** `ItemSplit` is third-party-only; `ItemReplace`/`ItemFormatDate` are unconfirmed. | Structure/version **declared per interface** → scopes conformance validation (verified). **‡** A per-transform trigger-event declaration is **unverified**. | **‡** "No raw scripting escape hatch" traces to **one third-party comparison site**, not vendor docs — treat as attributed opinion. | Validates typed `(handle, path)` addressing + a structure-scoped editor. Keep `.py` the only artifact. Read-only-inbound and no-scripting are **not** established parity table-stakes here. |
| **Mirth** (NextGen Connect) — verified, but msg/tmp specifics come from community Discussion #4849 (tonygermano), not official product docs | Two **mutable** objects: `msg` (inbound, always present) + `tmp` (outbound, **only if an outbound template is set**, seeded from that template; **Mirth does not auto-transfer** msg→tmp). Separation is convention; nothing enforces immutability. | Tree drag-drop generates a step over a free-text path; **Mapper / Message Builder / JavaScript** are real step types with free-text targets (also External Script / XSLT / Iterator). A JavaScript step is one-way. All steps compile to one JS function. | Per-direction **format/datatype** only (defaults HL7 v2.x); **no** "this channel handles ADT^A01"; picker scoped by the pasted **example template**. Strict parser is a HL7 v2.x **data-type-properties** toggle (optional). | **Yes (JavaScript)** — central. **‡** Asymmetric round-trip (form steps re-render; a JS step never does) is a sound **inference** from the architecture, not a documented Mirth statement. | Free-text path filled from a tree works. Decouple format-declaration from strict validation. Instant codegen inherits the one-way door — MEFOR's static-lens-over-`.py` avoids it. Don't build a Message Builder. |
| **Iguana** (iNTERFACEWARE) — read-only-inbound quote is verbatim on a resolving official page | `hl7.parse{}` returns a **read-only** node tree — "unchanged copy of the original" (verbatim) — plus the matched rule name; `hl7.message{}` is a **separate writable** tree; `Out:mapTree(Msg)` then override. Read-only inbound **by design**. | **Code (Lua) only**; read-only overlays = VMD autocomplete + live per-line value annotations (verbatim). No visual mapper. | **Yes (VMD)** — Identity inspects **MSH-9.1 + trigger** to classify to a named def; drives repeats/structure, filter/route. **‡** That autocomplete is *scoped by the VMD grammar* is plausible but **not documented** — present as inference. | N/A — code **is** the artifact; visual surfaces are read-only projections. | Read-only inbound is proven and valued. A distinct writable copy solves per-destination variants. **Caveat (§4):** Iguana's copy is **schema-bound** (fields addressed against a message *definition*) — that is what makes per-destination edits *safe*, a property MEFOR's schemaless positional copy does **not** inherit. |
| **Rhapsody** (Orion / Rhapsody Health)† — primary evidence is the **Rhapsody Reference Guide, PDF metadata ~2006** (the "2.4"/"Administration Manual" label is only the host's filename; **corrected** from the original memo) | `ROMessage` (read-only source) + `Message` (mutable copy via `output.append(template)`, which **copies the template and returns the copy**); `MessageCollection`. Read-only input **enforced by type** (verbatim: elements "cannot be altered in any way"). | JS free-text `setField("SEG/Field")` validated against the route's message definition, **+** a separate visual Symphonia Mapper (`.mdf`). **‡** ".mdf is a compiled binary" and "the two do not round-trip" are architectural **inferences**, not stated. **‡** "Input tree/Output tree drag-drop" and "modern 6.x is browser-based" are **unverified** (6.x rests on vendor marketing; authoring remains a desktop IDE). | **Yes** — message-definition file (`.s3d`/`.xsd`/`.mdf`) associated **by name** with a route; "Restricting by Message Type"; **graceful degradation** when absent (verbatim). | **Yes (JS filter)**. **‡** The JS engine being "Rhino" is **unverified** — the source never names it; **dropped**. | Validates read-only-inbound + explicit output copy; `append()`-returns-a-copy is the fan-out primitive shape MEFOR lacked. Optional statically-analyzable declared type with graceful degradation. Plain `.py` beats a binary/opaque mapping artifact for AGPL/diff/review. |

**Convergence (qualified):** every engine with a good field picker scopes it from a **declared or sampled structure** and keeps the path **free-text-degradable**; every engine that generates code from a visual model has an unclosed **round-trip seam**. Both point MEFOR toward "structured projection over free-text `.py`." **But** the panel's category-error warning is accepted: the competitors' *safety* for per-destination field edits comes from **schema-bound** addressing MEFOR does not have. This memo therefore borrows their credibility for the *ergonomic pattern* (read-only source + explicit writable copy; declared type scopes the picker) and **not** for a claim that a schemaless positional copy makes per-destination edits semantically safe (§4, §6).

---

## 4. Recommendation Q1 — inbound-immutable / outbound-copy

**Decision (revised): make within-handler fan-out correct *structurally* — `Send(to, message)` captures a defensive snapshot of a `Message` payload at construction (copy-on-Send, implemented copy-on-write). Ship `copy()` as an ergonomic clone alongside. Implement both as a structural clone of the parsed model — never `Message.parse(self.encode())`. Keep inbound read-only ADVISORY. Reject the distinct `OutboundMessage` type, `def handle(inbound, outbound)`, `msg.out`, and any hard input-mutation error. Do NOT ship an object-identity fan-out lint as the load-bearing guard.**

### Why the original shape was refuted (5/5) and what changed

1. **The proven corruption.** `copy() = Message.parse(self.encode())` was reproduced failing on **both** backends: `Message.parse` calls `.strip()` on the whole message, so a terminal-field trailing-whitespace value (common in free-text NTE/OBX-5, trailing Z-segments) survives `msg.encode()` but is **lost** after `copy()`. Re-parse also always uses the **default** backend, so a `copy()` of an inbound that was parsed via the python-hl7 fallback silently **switches backends** mid-handler. → **Fix: structural clone** (`copy.deepcopy` of the built-in dict model; a clone of the `hl7.Message` for the fallback), which is a true snapshot of current in-memory state, removes the encode↔parse round-trip dependency entirely, avoids `.strip()`, keeps the source's own backend, and is cheaper.

2. **The lint could not be the guardrail.** "Same mutated `Message` object referenced by ≥2 Sends" cannot statically distinguish the **rare divergence bug** from the **dominant correct idiom** (normalize once, deliver identical bytes to archive + downstream). It false-fires on correct production handlers *and* misses the bug when `msg` is laundered through a helper param or a loop — exactly the decomposition CLAUDE.md §4 encourages. A *runtime* guard on object identity has the same fatal ambiguity (it would dead-letter correct same-content fan-out). The only signal that separates the two is **whether the object was mutated between the two Sends** — which is precisely what snapshot-at-construction captures. → **Fix: drop the lint as the safety mechanism; make correctness structural.**

3. **`RawMessage` is not immutable.** `RawMessage.raw` is a writable attribute and one `RawMessage` is **shared across sibling handlers**, so the non-HL7 path has *both* a within-handler duplicate-delivery foot-gun *and* a cross-handler leak. The original "already immutable, so non-HL7 is safe" premise was false. → **Fix in §"Non-HL7" below.**

4. **Adoption reality.** The ADR 0089 scan found **0** uses of the shipped typed vocabulary against **1,283** native `msg.set` sites. An opt-in `copy()` beside a still-mutable inbound is another opt-in affordance; predicting non-zero adoption contradicts the only measurement we have. Copy-on-Send needs **zero adoption** — the estate's dominant `set(); Send(); set(); Send()` idiom simply becomes correct.

### How copy-on-Send resolves the fan-out cases (structurally, no discipline)

```python
# SAME-CONTENT fan-out (archive + downstream) — still correct, cost-controlled by COW
@handler("archive")
def handle(msg):
    msg["MSH-3"] = "FOUNDRY"
    return [Send("OB_ARCHIVE", msg), Send("OB_EHR", msg)]
    # both snapshots taken post-normalize -> identical bytes. Correct.

# DIVERGENT fan-out — the classic "bug" now delivers per-destination, no copy() call
@handler("fanout")
def handle(msg):
    msg.set("MSH-5", "SYS_A"); a = Send("OB_A", msg)   # snapshot #1: SYS_A
    msg.set("MSH-5", "SYS_B"); b = Send("OB_B", msg)   # snapshot #2: SYS_B
    return [a, b]                                       # diverge correctly

# HELPER-LAUNDERED and LOOP forms — also correct, because each Send snapshots at ITS construction
def _emit(m, dest, sysid): m.set("MSH-5", sysid); return Send(dest, m)
@handler("fanout2")
def handle(msg):
    return [_emit(msg, "OB_A", "SYS_A"), _emit(msg, "OB_B", "SYS_B")]  # A=SYS_A, B=SYS_B

# copy() remains available as readability sugar (structural clone, not re-parse):
class Message:
    def copy(self) -> "Message":
        """Independent, mutable structural clone of current in-memory state.
        Clones the parsed model directly — no encode->parse round-trip, no .strip(),
        no backend switch."""
        ...
```

The helper and loop cases are exactly the ones the static lint **provably could not** catch; copy-on-Send catches them for free because the snapshot is taken at the moment each `Send` is constructed.

### Enforced or advisory? — **ADVISORY, unchanged.**

Hard read-only inbound (two-arg signature, new returnable type, mutation error) breaks all 1,283 native mutate-in-place sites and fails "existing handlers MUST keep working." Corepoint's read-only-inbound is **unverified**, and Mirth's is convention-only, so strict immutability is an **ergonomics choice, not parity table-stakes** (fact-check confirmed). Keep an opt-in `msg.readonly()` view for teams wanting a test/CI guarantee — never a default.

### The one honest behavior change (and its gate)

Copy-on-Send moves the delivery snapshot from **handoff-time** to **Send-construction-time**. For the overwhelming majority — single-Send handlers, and fan-out constructed at `return` with no interleaved post-construction mutation — bytes are **identical**. The only regression surface is a handler that constructs a `Send` and then mutates the *same* `Message` before returning, *relying on* the late mutation reaching that already-constructed Send (today's last-write-collapse). That reliance is almost always the bug this fixes, but it is still a behavior change. → **Gate: an AST estate scan for "construct Send, then mutate its referenced Message before return" before flipping the default;** if any exist, adjudicate individually. Copy-on-write keeps the common no-post-mutation path zero-copy.

### Back-compat & typing

`Message` stays mutable; `def handle(msg)` unchanged; **the `Send.message` union is unchanged** (`Message | RawMessage | str`) — copy-on-Send stores the same types. No estate or `samples/config` edits. This is a decisive point against the rejected `OutboundMessage` type, whose true ripple (per the completeness critic) is **not** just "grows the union": it also touches `_partition` narrowing (wiring.py), the `isinstance(send.message, str)` else-`.encode()` branch (dryrun.py ~L415), the **subprocess-sandbox pickle boundary**, and mypy-strict narrowing at every Send/transform site. Copy-on-Send incurs **none** of that ripple.

### Sandbox marshalling (critical gap, folded in)

Under `[sandbox].mode=subprocess` (Accepted/built, ADR 0087), the Handler runs in a child process and returns `Send`s over a length-prefixed pickle pipe; `send.message.encode()` runs in the **parent**. So every `Send.message` must remain **picklable** — an invariant the ADR must state for `Message` and for the snapshot. Cost note: today `[Send("A",msg),Send("B",msg)]` sharing one object pickle-memoizes to **one** serialized message; **N independent snapshots serialize N**. Copy-on-write bounds this to divergent-fan-out cases, but the ADR must record it and the throughput benchmark must measure it (the 45M/day path is latency/CPU-sensitive).

### Inline fast-path (critical gap, folded in)

ADR 0057 (Proposed) fuses `route_only` + a single handler's `transform_one` inline in the router worker and materializes `[(d.to, d.payload) …]` there, gated on M-single/M-deliver/no-state/no-passthrough. The copy-on-Send snapshot invariant **must be asserted on both the split path (dryrun.py ~L415) and the fused inline path**, or "fan-out is correct" is unproven for the path a throughput-tuned deployment actually runs. (This is also where a declined single handler under Q2's `accepts=` predicate yields `names=[]` → M-single fallback → the split path → UNROUTED; walk that sequence in the ADR.)

### PT / loopback (important gap, folded in)

A `Send` to a PT inbound (ADR 0013) re-enters as fresh ingress and is re-parsed by that inbound's own Router — `Send` is **not one delivery kind**. The ADR must state that a passthrough Send carries the raw for re-ingress (copy-on-Send snapshots it like any other), that a looped-back copy's `message_type` is re-peeked by the downstream handler (so any Q2 declaration there must match the **re-ingressed** body), and that ADR 0057 bars passthrough from the fused path (PT + fan-out always takes the split path).

### Purity / re-run

The structural clone is a pure function of in-memory state (itself a pure parse of the immutable stored raw); it touches no clock/RNG/network and never mutates the ingress raw. Because it is a structural clone (not re-parse), copy()'s re-run purity **no longer depends** on encode↔parse round-trip stability. Required regression tests: `snapshot.encode() == source.encode()` on **both** backends over the escaping / repetition / custom-separator / Z-segment corpus, **including** (a) a `set()` trailing-whitespace value in the terminal field and (b) an appended trailing whitespace segment — the exact cases that failed under the rejected re-parse implementation — plus a source produced by the python-hl7 **fallback**.

### Non-HL7 fan-out (correction, folded in)

`RawMessage.raw` is writable and shared across siblings. copy-on-Send snapshots the `RawMessage` at construction too (a `RawMessage` snapshot captures the current `.raw` string), closing the **within-handler** duplicate-delivery case. The **cross-handler** leak — a handler doing `rm.raw = transform(rm.raw)` corrupts siblings that share the object — is *not* fixed by snapshotting at Send (the mutation happens earlier). → **Recommend now:** document the safe non-HL7 idiom (build N strings, `Send(to, str)`), warn that mutating `.raw` before a Send is a sibling-leak foot-gun. → **Fast-follow:** freeze `RawMessage.raw` (frozen/`__setattr__` guard), gated on an estate scan (freezing is itself a behavior change for any handler mutating `.raw`). Do **not** ship the "already immutable" framing.

### Domain honesty (skeptic-5, accepted)

copy-on-Send and `copy()` fix **object independence**, not the **semantic safety** of per-destination positional field edits. MEFOR exposes MSH-9.1/9.2 but **no MSH-9.3 structure**, and all paths are free-text positional over a tolerant parse; a per-destination `set("PID-3", …, repetition=2)` is a positional guess against a repeating identifier list whose slot meaning is carried in PID-3.4 (assigning authority) that MEFOR does not model. The fan-out primitive does not make that edit *safe*; the Q3 picker must not imply it does (§6). The "market validates the primitive" claim is therefore **qualified**, not dropped: competitors validate the read-only-source + writable-copy *pattern*; their edit *safety* comes from schema-binding MEFOR lacks.

---

## 5. Recommendation Q2 — Handler message-type declaration

**Decision (revised): the handled type is DESCRIPTIVE and RECOGNITION-FIRST — inferred from the guards handlers already write, with an optional `message_type=` kwarg only as a documentation escape hatch. Enforcement is NOT a new engine-interpreted flag; it is an author-written, AST-visible predicate on the existing `accepts=` seam (ADR 0084), matched COMPONENT-WISE and failing LOUD on non-HL7 / batch. HL7-only, optional, additive throughout.**

**Required is a non-starter** (unchanged): `RawMessage` has no MSH-9, requiring it rewrites the estate and contradicts payload-agnostic ingress (ADR 0004).

### Why the original (4/5) was refuted and the two structural changes

- **Adoption (recognition-first, not declaration-first).** A descriptive kwarg has **zero write-time payoff** and the estate ignored the last zero-payoff-at-runtime affordance entirely (0/1,283). → **Fix:** apply ADR 0089's recognition principle to *type*. The lens/`check` **infer** the handled type from what handlers already write — the native `if msg.message_code/msg.message_type != "…": return []` guard and any existing `accepts=` — so picker scoping and path validation light up across the estate with no new ceremony, and the declaration can't drift from the guard because **there is only the guard**. `message_type=` remains available for handlers where no guard is statically recoverable or for pure self-description.
- **ADR 0076 bright line (enforcement).** Compiling a decorator *string* (`message_type="ADT^*", enforce=True`) into routing behavior is engine-side interpretation of metadata — a second, declarative execution surface, however thin. An `accepts=` **lambda/helper call** is author-written code *in the .py*, AST-recognizable, on the one execution path. → **Fix:** expose enforcement only as `accepts=message_type_of("ADT^A01")`. No `enforce=` flag, no engine codegen from a string.

### The tiers, restated

```python
# Tier 1 (descriptive, recognition-first, default) — inferred, zero runtime effect:
@handler("adt_to_epic")
def handle(msg):
    if msg.message_code != "ADT" or msg.trigger_event != "A01":
        return []                       # recognized by the lens as "handles ADT^A01"
    ...
# optional explicit escape hatch (documentation only, no runtime effect):
@handler("adt_to_epic", message_type="ADT^A01")

# Tier 2 (opt-in enforcement) — author-written, AST-visible, on the existing accepts= seam:
@handler("adt_to_epic", accepts=message_type_of("ADT^A01"))
```

`message_type_of("ADT^A01")` returns a **pure** predicate compiled to `message_code == "ADT" and trigger_event == "A01"` (code-only form → `message_code == "ADT"`; wildcard/list expand accordingly). Both `message_code` and `trigger_event` read MSH-9.1/9.2 through the message's own MSH-2 separators and unescape — **never** a whole-field caret-literal compare. It **inherits ADR 0084's ratified FILTERED→UNROUTED disposition shift**, so it must be a deliberate author choice, never a default.

### 🚫 Blocker ① (unchanged, now fully specified): component matching

Whole-field MSH-9 equality (`getattr(m,"message_type",None) == "ADT^A01"`) returns **False for 100%** of conformant 3-component `ADT^A01^ADT_A01` traffic (Epic/Cerner routinely populate MSH-9.3, required in v2.4+) → silent **UNROUTED** after AA, and it hardcodes `^`, breaking on custom component separators. **Fix (spec, before build):** match on parsed components as above; add a load-time/`check` test with a 3-component MSH-9 **and** a message whose MSH-2 uses a non-standard component separator. Do not codify the estate's whole-field hand-written guards into the framework predicate.

### 🚫 Blocker ② (new, from the completeness critic): batch / non-MSH leading segment

A BHS/FHS-led batch `Message` (ADR 0082) has no MSH-9; `field("MSH-9")` reads BHS-9 (empty/garbage). Component matching **does not** fix this. **Fix (spec):** `message_type_of` must **raise** (→ loud ERROR/dead-letter, per Blocker ③) when the leading segment is not MSH, never silently decline. State the **transport-dependent split contract**: File-source ingress splits batches (each split message carries its own MSH-9 and matches normally); MLLP does **not** split, so a batch over MLLP arrives as one `Message` and correctly surfaces as a loud ERROR against an HL7-type-enforced handler. The Q3 picker's structure catalog also has no BHS/FHS entry — scoping degrades to the generic catalog with a *visible* "batch envelope — no structure scope" marker (§6).

### 🚫 Blocker ③ (new): fail loud on non-HL7

The synthesized `getattr(m,"message_type",None)` returns `None` on a `RawMessage` → predicate `False` → declines **100%** → silent **UNROUTED**, whereas the hand-written `msg.message_type` guard **raises AttributeError** → loud ERROR/AlertSink. Enforcement must not convert a visible wiring fault into a silent black hole. **Fix (spec):** `message_type_of` raises on any message lacking MSH-9 (`RawMessage`, batch), producing an ERROR disposition — deterministic on the same input, so re-run-stable. `check` additionally warns when a `message_type`-bearing handler is named by a router bound to a non-hl7v2 inbound.

### mypy-strict cost (important gap, folded in)

`m.message_code`/`m.trigger_event` exist only on `Message`, not `RawMessage`; the sketch's `getattr(m,"message_type",None)` is exactly the untyped escape hatch strict mode discourages. The `message_type_of` helper must carry a proper `isinstance`/`content_type` narrowing so the predicate type-checks cleanly under strict, and the ADR should state that `copy()`/`message_type` add **no further `Any` leakage** beyond the already-`Any` `Message._m`.

### Back-compat

Strictly additive. `@handler("x")` and `@handler("x", accepts=…)` unaffected. The 1,283 native sites pass nothing new → routing, disposition, and the runtime MSH-9 peek are byte-for-byte identical. Existing hand-rolled guards keep working and are **not** auto-migrated. Under recognition-first they simply become the *source* the lens reads — the picker gets scoped, the code is untouched.

---

## 6. Recommendation Q3 — HL7 field picker

**Decision (revised): extend the inline autocomplete that already ships first; build a Steps-view picker only when ADR 0089 is Accepted AND the recognition lens shows measured use — and keep it a thin, honest projection.**

The panel refuted 5/5, and two facts reframe the work: the field-path drill-down **already ships** (`ide/src/completion.ts`, bundled `hl7schema.json`, no per-keystroke Python) inside the `msg["…"]`/`.field("…")`/`.set("…")` surface the estate actually uses; and a separate Steps-view picker is another structured affordance layered on the same lens whose adoption base rate is presently zero.

### Step 1 — extend the surface that already exists (do this first)

Add message-type ranking and `occurrence=`/`repetition=` snippet hints to the **inline** `completion.ts` autocomplete. This reaches fluent authors with **zero mode switch**, no read-only/partial-projection failure mode, and no new artifact. For path discovery this is faster than opening a lens and navigating dropdowns — the ergonomics win with the least risk.

### Step 2 — the Steps-view picker, gated and thin (only after Step 1 + evidence)

**Gates:** (a) ADR 0089 **Accepted**; (b) a **measured, nonzero, sustained** adoption signal for the recognition lens itself (instrument real edits before expanding it) — because its base rate mirrors the 0/1,283 vocabulary result.

**Scope, as corrected by the panel:**

1. **Picker-as-control (path arg only).** Render the Set-Field `path` param as a segment→field→component quick-pick over `hl7schema.json`. **Always degrades to free-text**; Z-segments, site-custom fields, cross-version paths stay typeable. Conformance stays the separate `validation.strict` tier; the picker never blocks a path. **Gate offered paths behind a dual-backend round-trip proof** (`parse → set(path, sentinel) → encode()` byte-identical on built-in *and* python-hl7); depths that aren't proven equal (deep `.C.S`, some repetitions) degrade to free-text with an explicit "unverified round-trip" marking rather than being presented as authoritative picks.

2. **Occurrence / repetition — READ-ONLY display in the MVP.** These are **not** editable spinners. ADR 0089 Phase A freezes these kwargs read-only precisely because editing them re-points **which segment instance / field repetition** a write hits (a silent `msg.set` semantics change — `occurrence=2` targets the 2nd OBX; flattening `occurrence=i` from a loop to a literal re-points a loop-driven write). Render them exactly as lens.py already does: bound, read-only. **Editing** occurrence/repetition is a **separately-ratified phase** with its own adversarial byte-stability matrix **and** a semantics-change guard. Likewise, drilling a repeating field from `PID-3` to `PID-3.1` changes which bytes are touched (component read/write hits the first repetition only) — surface that as a distinct write target, not a free refinement.

3. **Message-type scoping — corrected resolver, sample-authoritative.** Trigger event ≠ message structure: `ADT^A04/A08/A13` all map to structure `ADT_A01`, and hl7apy `MESSAGES` is keyed by **structure** — so a naive lookup of `"ADT^A08"` **misses** and silently falls back to the generic catalog for ~56% of ADT triggers, indistinguishable from a legitimate Z-segment fallback. **Fix:** (i) emit a **trigger→structure resolver** (`ADT^A08 → ADT_A01`), centralizing the map MEFOR **already hand-maintains** in `generators/adt.py` rather than duplicating it; (ii) key the segment-structure table by **structure id** and resolve every scope lookup through it; (iii) **pin a version** (from the inbound's strict `version` or MSH-12) — a structure catalog without a version is unsound across 2.3–2.7; (iv) make the **real synthetic sample the authoritative** scope source and the abstract structure the ranking fallback, and **always union in** Z-segments and any segment present in the sample, so the picker never *hides* the site-local/non-conformant fields authors most need; (v) label the list as the **structure family** (e.g. "ADT_A01 family"), and make a scope **miss visibly distinct** in the UI from the Z-segment/non-conformant fallback so a silent no-op is impossible. Scoping **ranks, never removes** — an "All segments" escape is always present.

### Degradation

The migrated estate has zero declarations today, so recognition-inferred type (from guards) plus sample-based scoping is the **default**, and the generic catalog is the floor. The picker is fully useful with no explicit declaration at all — exactly as Mirth ships a useful picker with only a pasted example.

### Fan-out synergy (skeptic-3 concern, resolved by Q1)

The panel's PHI-masking foot-gun — a Set-Field row rendered *between* two Send rows implies "affects only the later destination" while today's deferred encode delivers the final state to **both** — is **resolved by copy-on-Send**: snapshot-at-construction makes that linear, sequential per-destination mental model **actually true**. The Steps view must still: (a) not present the ordering as misleading for legacy handlers if copy-on-Send is not yet enabled on that engine; and (b) **disambiguate receiver variables** (`msg` vs a re-parsed `msg2`) in row labels so the per-destination re-parse workaround projects faithfully.

### False-completeness guard

Recognition renders only literal `msg.set` idioms as rows; computed paths (`msg.set(f"PID-{i}", v)`), conditional writes, helper-wrapped writes, and loop-`occurrence` writes are **not** rows. A Steps view that looks authoritative while hiding those is a hazard. **Requirement:** unmodeled writes are surfaced as an explicit **"unmodeled code present"** marker; the Steps view may never imply it shows every field write.

### How it stays a projection over real `.py`

The picker edits the path literal of a **native** `msg.set(...)` via the ADR 0089 byte-space per-argument splice — `.py` stays the only artifact and execution path; no stored model, no codegen, no canvas. It refuses Mirth's Message Builder and Rhapsody's binary mapper. **Correction:** a `message_type=` scope hint is **not** the `accepts=` precedent — `accepts=` is *executed* by `route_only`; a design-time scope hint is read only by the IDE. It must be justified on its own terms (inert to the engine, always degrades to "All segments"), never presented as executed logic; this is why Q2 makes the *inferred guard* (real executable code) the authoritative type source and the kwarg a mere hint.

---

## 7. Risks & open questions the owner should weigh

**Blockers to resolve in the ADR spec before any build (five, up from one):**
- **① MSH-9 whole-field match silently UNROUTES 3-component / custom-separator types** → component-wise `message_code`+`trigger_event`, reading MSH-2 (§5).
- **② Batch / non-MSH leading segment (BHS/FHS)** → `message_type_of` raises; state the transport-dependent split contract; picker shows a "batch envelope" scope marker (§5/§6).
- **③ Enforcement on non-HL7 silently UNROUTES** → fail loud (ERROR), never silent decline (§5).
- **④ copy-on-Send / copy() snapshot must be a structural clone** satisfying dual-backend `snapshot.encode() == source.encode()` (incl. terminal whitespace, appended trailing segment, fallback-produced source) (§4).
- **⑤ Sandbox picklability + marshalling and the inline fast-path invariant** must hold on **both** split and fused paths (§4).

**Rated concern (back-compat) — fixable before build:**
- **Enforcement bright-line** → author-written `accepts=message_type_of(...)`, not an engine-interpreted `enforce=` string (§5).
- **Picker "ship now" overstated** → the inline autocomplete extension ships first; the Steps picker is gated on 0089 Acceptance *and* measured lens adoption (§6).
- **Picker splice can corrupt native calls** → path-arg splice only; occurrence/repetition read-only; per-shape byte-stability matrix; unproven shapes stay read-only/free-text (§6).
- **Recognize-vs-generate line** → explicitly **decline** adding any `derive`/`copy_message` row to the ADR 0076 vocabulary or a "derive per-destination copies" grouping to the lens. A copy-on-Send `Send` and an author `copy()` stay **unrendered native calls**; the Steps-view carve-out never grows to express object lifecycle or fan-out topology (§4/§8).

**Rated major (fan-out) — corrected and folded in:**
- **`RawMessage` is NOT immutable** and is shared across siblings → corrected framing; safe non-HL7 idiom documented; snapshot at Send; freeze `.raw` as a scan-gated fast-follow (§4).
- **Object-identity fan-out lint cannot be the guardrail** → removed; correctness is structural via copy-on-Send (§4).

**Rated minor — document, don't block:**
- Copy-on-Send is a **delivery-timing change** → estate scan for "construct Send, then mutate before return"; benchmark the copy-on-write cost against the 45M/day path (§4).
- `copy()` re-parses via the tolerant backend, **never** hl7apy → a copy of a strict-validated inbound is **not** re-validated; state it so operators don't assume the outbound copy inherits the strict guarantee (§4).
- Static declared/inferred type can diverge from runtime MSH-9 (a router legitimately feeding ADT **and** ORU to one handler) → path lint stays **advisory**, "rank never hide, All-segments always present"; add a softer router→handler cross-check warning (§5/§6).
- Static-validation false positives on non-conformant real HL7 (Z-segments, site-local fields) → advisory only, never fail-closed; Z-segments always allowed and always unioned into a scoped list.
- hl7apy 2.5.1 vs feeds spanning 2.3–2.7, **and** vs an inbound's operator-declared strict `version`/MSH-12 → mark the catalog visibly as a pinned superset, not a per-feed schema; align (or explicitly note the non-alignment of) the catalog with the declared strict version so the authoring surface doesn't suggest a field the engine's own validator disagrees with.
- PT/loopback (ADR 0013): `Send` is not one delivery kind; a looped copy's type is re-peeked downstream; PT + fan-out takes the split path (§4).

**Open questions for the owner to rule on:**
- Declaration/match grammar: code-only (`"ADT"`), exact (`"ADT^A01"`), list, wildcard-as-sugar — confirm the one-line spec so picker, resolver, and predicate agree (component-wise throughout).
- Copy-on-Send implementation: copy-on-write vs unconditional snapshot — decide against the throughput benchmark.
- Does the MVP include sample-MSH-9 scoping, or recognition-inferred + generic-catalog only first? (Lean defer sample scoping — smaller, PHI-free MVP.)
- Non-HL7 fan-out: string-building + `Send(to, str)` now (recommended) vs freezing `RawMessage.raw` / a builder later.
- Value-side assist (HL7 table values for coded fields like PID-8) is **out of Q3's path-picker scope** — decide as a separate sibling item.

---

## 8. Recommended decision & phasing

Record all three in **one ADR, status Proposed, extending ADR 0076/0089, sibling to ADR 0084** — one design surface. Sequence so value lands early and the five blockers are closed on paper first.

**Put in the Proposed ADR:**
1. **Q1** — **copy-on-Send** structural snapshot at `Send` construction (copy-on-write), `copy()` as sugar, **both as a structural clone (not `parse(encode())`)**; inbound read-only **advisory**; **no load-bearing fan-out lint**; corrected `RawMessage` framing + safe non-HL7 idiom; the dual-backend clone-encode test; the estate scan gate for the delivery-timing change; the **sandbox picklability/marshalling** note and the **fast-path (0057) invariant on both paths**.
2. **Q2** — **recognition-first** descriptive type (inferred from existing guards/`accepts=`), optional `message_type=` escape hatch; **component-wise matching** written into the spec; enforcement as author-written `accepts=message_type_of(...)` (no engine-interpreted flag); **fail-loud on non-HL7/batch**; the batch/BHS-FHS + transport-split contract; the mypy-strict-clean predicate typing.
3. **Q3** — **extend inline autocomplete first**; the Steps picker as a **gated, thin projection**: path-arg splice only, occurrence/repetition **read-only**, dual-backend round-trip gate on offered paths, **no false-complete rows**, scoping via a **version-pinned trigger→structure resolver** (centralizing `generators/adt.py`) with **sample-authoritative** ranking and Z-segments always unioned; the single ratified kwarg name **`message_type=`**.

**Defer (name explicitly so they don't creep in):**
- Hard-enforced read-only inbound (`msg.readonly()` view / CI flag) — opt-in only, never default.
- Freezing `RawMessage.raw` and a non-HL7 builder — scan-gated fast-follow.
- Editable occurrence/repetition in the picker — separately-ratified, test-gated phase.
- Multi-version schema tables scoped by MSH-12; value-side (code-table) pickers.
- Any `derive`/`copy_message` typed-vocabulary row — **declined**; if ever revisited, recognition-only over an author-written `copy()`, never a generator.

**Suggested build order:**
- **Phase A (independent of the lens):** Q1 copy-on-Send (COW) + `copy()` sugar + structural-clone impl + estate scan + benchmark + dual-backend clone-encode test + `RawMessage` framing/idiom, with the fast-path (0057) invariant asserted. Closes the real fan-out gap for the whole estate; ships without ADR 0089.
- **Phase B (metadata + declaration):** Q2 recognition-first inference in the lens/`check` + the trigger→structure resolver + version pinning; `accepts=message_type_of()` (component-wise, fail-loud) as the opt-in enforcement, gated on its matching tests.
- **Phase C (gated on ADR 0089 Acceptance + measured lens adoption):** Q3 Step 1 inline-autocomplete extension first; then, if the adoption signal is real, the Steps picker path-arg control + read-only occurrence/repetition + scoping.

**Frame the BACKLOG item** as an extension of the ADR 0076/0089 lens line and a sibling to ADR 0084, explicitly inside the #26 carve-out: structured Steps view over real `.py`, no declarative logic execution, `.py` the only artifact and execution path. Every adopt-me surface has a useful zero-declaration default; the package is additive over the native estate; the **AGPL / Python / code-first / payload-agnostic** differentiator is preserved throughout.

**Bottom line:** the direction survives, but only after material changes the panel forced — fan-out correctness moved from an unadopted opt-in `copy()` to structural **copy-on-Send** (structural clone, not re-parse); enforcement moved from an engine-interpreted flag to an author-written **`accepts=` helper** with component-wise matching that **fails loud**; and the picker demoted to **extend-what-ships-first**, gated on real adoption, with a corrected trigger→structure resolver. Resolve the five spec blockers pre-code, correct the competitor claims per §3/§9, and the set is safe to build.

---

## 9. Validation notes

### 9.1 Competitor fact-check reliability and corrections applied

| Competitor | Reliability | Load-bearing corrections applied to this memo |
|---|---|---|
| **Corepoint** | Medium | "No scripting escape hatch" and "easiest to administer" are **single-third-party (mirth.support) attributed opinion**, not vendor-confirmed → annotated ‡. Multiple distinct source/dest objects and read-only source handle are **inference/unverified** → annotated ‡. `ItemSplit` third-party-only; `ItemReplace`/`ItemFormatDate` unconfirmed. Per-transform trigger-event unverified. Mechanics from a single 2016-era blog → row marked †. Dead `lyniate.com` URL dropped; Health Catalyst patent kept out (it is a non-Corepoint contrast). |
| **Mirth** | High | msg/tmp specifics **attributed to community Discussion #4849**, not official docs. "Code Template" is **not** a transformer step type (removed from any step-type framing). Strict parser is a **data-type-properties** toggle, not per-connector. Asymmetric round-trip labeled **inference** ‡. |
| **Iguana** | High | Read-only-inbound quote is verbatim, safe to assert. "Autocomplete scoped by VMD grammar" softened to **inference** ‡. Added the **schema-bound-copy** caveat (their edit safety ≠ MEFOR's schemaless positional copy). |
| **Rhapsody** | High (primary), but sourcing corrected | Source re-labeled **Rhapsody Reference Guide, ~2006** (not "Administration Manual ~2013"; "2.4" is only the host filename) and row marked †. ROMessage-read-only and `append()`-returns-copy verbatim-safe. "Rhino" JS engine **dropped** (unverified). ".mdf compiled binary / no round-trip" and "6.x browser-based / Input-Output-tree drag-drop" annotated **inference/unverified** ‡. |

### 9.2 Recommendations vs the refutation panels

| Rec | Refuted | Disposition |
|---|---|---|
| **Q1** | **5 / 5** | **Changed.** Accepted: structural-clone (fixes proven whitespace/backend corruption); **copy-on-Send** replaces opt-in `copy()`+lint (fixes adoption, helper/loop aliasing, same-content false-positives); `RawMessage`-not-immutable corrected. **Rebutted:** the *runtime* object-identity guard (skeptic 5b) — it would dead-letter the correct same-content fan-out; copy-on-Send achieves the safety goal without the ambiguity. **Conceded (deferred):** schemaless positional per-destination edits are not made *semantically* safe (skeptic 5) — scoped honestly; the "market validates" claim qualified. |
| **Q2** | **4 / 5** | **Changed.** Accepted: component-wise matching (3-component + custom-separator blockers); fail-loud on non-HL7/batch; enforcement moved off the engine-interpreted flag onto an author-written `accepts=` helper (bright-line); **recognition-first** inference (adoption + drift). The one non-refuting lens (purity) is satisfied a fortiori. |
| **Q3** | **5 / 5** | **Changed.** Accepted: extend the already-shipping inline autocomplete first; gate the Steps picker on 0089 Acceptance **and** measured lens adoption; occurrence/repetition **read-only**; dual-backend round-trip gate on offered paths; false-completeness marker; trigger→structure resolver + version pin + sample-authoritative + Z-union + visible miss. **Resolved by Q1:** the PHI-masking interleaving hazard (copy-on-Send makes the linear model true). |

### 9.3 Completeness gaps

| Gap | Severity | Response |
|---|---|---|
| Subprocess-sandbox pickle marshalling (copy-on-Send multiplies serialized messages; picklability invariant; OutboundMessage pipe cost) | Critical | **Accepted** — §4: stated invariant + cost, COW mitigation, benchmark gate; scored against the OutboundMessage rejection. |
| Inline fast-path (ADR 0057) is a second execution path | Critical | **Accepted** — §4/§5: invariants asserted on **both** split and fused paths; enforce/`accepts=` → M-single → UNROUTED sequence walked. |
| Batch BHS/FHS breaks `message_type`; transport-dependent split | Important | **Accepted** — §5 Blocker ②: fail-loud + split contract; §6 batch scope marker. |
| PT/loopback re-ingress (ADR 0013) | Important | **Accepted** — §4: `Send` is not one delivery kind; downstream re-peek; split-path-only for PT+fan-out. |
| OutboundMessage ripple + mypy-strict cost (getattr escape hatch) | Important | **Accepted** — §4 (rejection scored beyond union size; copy-on-Send avoids the ripple) + §5 (typed, `isinstance`-narrowed predicate). |
| copy() backend-switch on fallback re-parse | Nice-to-have | **Resolved** — structural clone keeps the source's backend; covered by the fallback-source test (§4). |
| Strict validation vs copy()/picker | Nice-to-have | **Accepted/deferred** — §4/§7: copy() does not re-validate (stated); align catalog with declared strict version or note non-alignment. |

### 9.4 What remains uncertain (be transparent)

- **Copy-on-Send is a real, if narrow, behavior change.** It is gated on an estate scan and a throughput benchmark; the residual risk is a handler that *intentionally* relies on today's last-write-collapse-to-all-destinations. We assess that as almost always the bug this fixes, but it is not provably zero until the scan runs.
- **Throughput cost of snapshotting** at 45M/day scale is unmeasured; the copy-on-write design is intended to keep the single-Send/no-post-mutation common case zero-copy, but this must be benchmarked before the default flips.
- **Structural clone of the python-hl7 fallback object** must be verified to deep-clone cleanly (no shared internal state); the dual-backend `snapshot.encode() == source.encode()` test is the acceptance bar.
- **Q3 adoption is explicitly unproven.** We are declining to build the heavy picker on faith; the inline-autocomplete extension is the low-risk first move, and the Steps picker waits on a measured signal that may not materialize — in which case the correct outcome is to *not* build it.
- **Competitor "read-only inbound as parity" is weaker than it first reads:** only Iguana and Rhapsody's read-only-inbound are verbatim-verified; Corepoint's is unverified and Mirth's is convention-only. The memo treats strict inbound immutability as an ergonomics choice, consistent with that evidence.