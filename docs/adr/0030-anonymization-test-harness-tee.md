# ADR 0030 — Anonymizer / de-identification for the test harness + tee (`messagefoundry.anon`)

- **Status:** **Accepted (2026-06-20) — ratified on the owner's go; built and shipped (PR #440).** The forks below
  (module home, rules model, surrogate strategy, leak-gate reconciliation) were ratified before the build.
- **Built (this ADR):** **shipped (PR #440)** — the pure-stdlib `messagefoundry.anon` package (`hl7.py`/`keying.py`/`rules.py`/`surrogates.py`/`leak.py`, vendored byte-identical to `tee/anon/`) plus the tee `anonymize-captures` subcommand. It layers on already-shipped substrate: the pure HL7 model
  [`parsing/message.py`](../../messagefoundry/parsing/message.py) (`Message.set`/`encode`, MSH-derived
  `_encoding_chars`, repetition handling) and [`parsing/peek.py`](../../messagefoundry/parsing/peek.py)
  (tolerant python-hl7 peek); the surrogate pools + datatype encoders in
  [`generators/_hl7data.py`](../../messagefoundry/generators/_hl7data.py) (`FAMILY_NAMES`, `STREETS`,
  `cx()`/`xpn()`/`xad()`/`xcn()`, NANP-reserved fictional phones); the seeded-determinism pattern in
  [`generators/_core.py`](../../messagefoundry/generators/_core.py) (`random.Random(f"{seed}|…")`); the
  vendored standalone HL7 reader [`tee/hl7_fields.py`](../../tee/hl7_fields.py); the tee capture/export
  path ([`tee/store.py`](../../tee/store.py) `RelayStore.captures`, [`tee/__main__.py`](../../tee/__main__.py));
  the harness capture sink ([`harness/reconcile/capture.py`](../../harness/reconcile/capture.py)) and
  file-replay loader ([`harness/reconcile/compare.py`](../../harness/reconcile/compare.py),
  [`harness/load/corpus.py`](../../harness/load/corpus.py)); and the publish leak-gate
  [`scripts/publish/scan_forbidden.py`](../../scripts/publish/scan_forbidden.py) (`FORBIDDEN`).
- **Decision in one line:** ship a **pure-stdlib, dependency-free `anon` package** that turns real,
  messy HL7 v2 into structurally-faithful **PHI-free** datasets via a **two-layer rule model — a
  declarative field-*selection* map (data) over a code registry of pure surrogate *functions* (logic)** —
  with **deterministic keyed surrogates**; the engine **owns** it beside `parsing/` and the tee **vendors a
  byte-identical copy** (mirroring [`tee/hl7_fields.py`](../../tee/hl7_fields.py)), every output proven clean
  by `scan_forbidden` before it can be committed. *(On landing this would be the first built slice of the
  de-id capability PHI.md §9 / CLAUDE.md §9 still call planned-not-built — see §8; the docs only flip on
  code landing, never on ADR acceptance.)*
- **Related:** [ADR 0004](0004-payload-agnostic-ingress.md) (payload-agnostic ingress — the
  `content_type` seam this anonymizer dispatches on); [ADR 0012](0012-x12-edi-codec.md) (the vendor-a-pure-
  codec precedent the tee already follows); [ADR 0010](0010-handler-callable-db-lookup.md) (the one
  sanctioned non-pure input — contrast: the anonymizer is strictly pure); BACKLOG #36 (this item), #14
  (the tee parity relay), #26 (visual/declarative *logic* authoring — declined; this is *not* that);
  [PHI.md](../PHI.md) §9 (de-identification `[ROADMAP]` — on landing this *would be* the first concrete
  slice that flips it) / §7 (redaction is *not* de-id); [CLAUDE.md](../../CLAUDE.md) §9 (de-id planned-not-
  built, centralize the rules) / §8 (read separators from MSH, never string-slice, parse defensively) / §4
  (`parsing/` is the one pure carve-out lib; this ADR extends that carve-out to `anon/` on acceptance —
  dependency direction one-way) / §12 (don't drift to declarative *logic*).

## Context

The highest-value test inputs MessageFoundry can have are **real-world HL7 shapes** — messy, non-
conformant, vendor-quirky messages from an actual feed. Those are precisely the inputs we **cannot
commit**: they carry PHI. The synthetic generators ([`generators/`](../../messagefoundry/generators/),
mirroring Synthea) produce conformant messages but not the off-spec shapes that break parsers. BACKLOG
#36 asks for an **anonymizer** that converts captured real messages into **structurally-faithful, PHI-free**
fixtures safe to commit/share/replay — consumed by both the standalone **tee** relay
([`tee/`](../../tee/), #14) and the PySide6 **test harness** ([`harness/`](../../harness/)).

This is the **first concrete consumer** of the de-identification capability that
[CLAUDE.md](../../CLAUDE.md) §9 and [PHI.md](../PHI.md) §9 call **"planned, not built"** — with the
standing rule *"centralize the rules — don't inline ad-hoc de-id logic. Don't reference a framework that
doesn't exist."* That rule binds this ADR: while it is **Proposed** nothing is built, and the PHI.md/CLAUDE.md
flips below are gated on **code landing**, never on acceptance. De-id is also a **distinct** capability: it is
**not** the store cipher and **not** the `safe_exc()`/`redact()` log chokepoint, which PHI.md §7 states
verbatim is *"conservative redaction, **not** de-identification."* This ADR must not conflate them.

The constraint that shapes everything is a **dependency-split asymmetry**:
- The **harness** freely imports the engine (`messagefoundry.parsing`, `.generators`, …) — it already
  imports engine packages directly, so a new `messagefoundry.anon` is an ordinary import for it.
- The **tee** is **deliberately `messagefoundry`-free** (verified: zero `from messagefoundry` imports). It
  **vendors** [`tee/hl7_fields.py`](../../tee/hl7_fields.py) and `tee/mllp.py` precisely so the cutover
  relay can sit on the Epic/Corepoint boundary without dragging in the engine or its attack surface.

So "one shared module both import" is a trap: it would force `tee/ → messagefoundry`, breaking the tee's
standalone invariant. The obvious-but-wrong alternatives — inline the de-id into each tool (banned by §9:
"don't duplicate copy-paste logic in harness/ and tee/"), or let the tee keep its **own** logic port (the
same duplication) — both lose. The pure-stdlib lens makes the resolution: a module small and pure enough
that **vendoring it costs nothing and the rule *table* is the single authority** (engine-side) with a
**parity-pinned copy** on the tee.

## Decision (proposed)

### 1. A pure, dependency-free `anon` package — engine-owned, tee-vendored (additive only)

The anonymizer ships as **`messagefoundry/anon/`**: a small, **pure-stdlib** package — no `hl7apy`, no
`python-hl7`, no engine state, I/O, or DB — sitting beside [`parsing/`](../../messagefoundry/parsing/). Like
`parsing/` it is a pure, side-effect-free library, but the §4 carve-out is **verbatim scoped to `parsing/`**
and does **not** automatically extend to a new sibling. Accepting this ADR **amends CLAUDE.md §4** to add
`anon/` to the console carve-out (listed in *To resolve on acceptance*); until then the console may not import
it. The harness is unaffected — it imports engine packages freely. Files:

- `anon/rules.py` — the **default field-selection map** (data; §2): `FieldRule(path, SurrogateKind)` rows
  naming *which* HL7 field gets *which kind* of surrogate. No transform expressions — just a field→kind map.
- `anon/surrogates.py` — the **code** half: a registry of **pure surrogate functions** keyed by
  `SurrogateKind` (`surrogate_name`, `surrogate_address`, `surrogate_mrn`, …), each a deterministic
  keyed renderer over pools lifted dependency-free from `generators/_hl7data.py` (*not* `_core.py`, which
  pulls `hl7apy` + the engine validator and so is **not** vendorable). The `_hl7data` encoders
  (`xpn()`→`Family^Given^Middle`, `cx()`, `xad()`, `xcn()`) emit **pre-joined, field-level `^`-strings**, so
  a surrogate composes a whole field's value, not a bare leaf (see the whole-field write constraint in §3).
  Adding a *new* kind of surrogate is writing a Python function here — never a data edit.
- `anon/hl7.py` — a **mutate-capable** MSH-separator field model (read/replace/re-encode + escaping),
  the write-side superset of `tee/hl7_fields.py`. On the **engine/harness** side it delegates to
  [`parsing/message.py`](../../messagefoundry/parsing/message.py) `Message` (already battle-tested:
  `_encoding_chars` reads MSH-1/MSH-2, whole-field `set()` assigns the surrogate's `^`-joined value
  verbatim, `repetitions()` handles repeating fields); the vendored tee copy carries an **equivalent stdlib
  re-encoder** so the tee needs no engine import. These two re-encoders are **behaviourally parallel, not
  byte-identical** — a divergence risk called out in Consequences.
- `anon/__init__.py` — the public surface: `anonymize(raw: str, *, dataset_key: str, rules=DEFAULT_RULES) -> str`
  and `leak_check(text: str) -> list[Hit]`. Sketch of the surface:

```python
# anon/rules.py  — DATA: which field → which kind of surrogate. No transform expressions.
class SurrogateKind(StrEnum):
    NAME = "name"; ADDRESS = "address"; MRN = "mrn"; SSN = "ssn"; PHONE = "phone"
    DOB = "dob"; ID = "id"; PROVIDER = "provider"; FREETEXT = "freetext"; KEEP = "keep"

@dataclass(frozen=True)
class FieldRule:
    path: str               # "PID-5", "MRG-1" — a whole-FIELD HL7 address, never a component or byte offset
    kind: SurrogateKind     # selects a pure surrogate function; KEEP = leave intact

DEFAULT_RULES: tuple[FieldRule, ...] = (...)         # the frozen default map (§3)
def load_rules(overlay: Path | None) -> tuple[FieldRule, ...]: ...   # default ⊕ anon.toml
                                                                     # parser permits ONLY path→kind/keep/drop;
                                                                     # any other key is rejected at load (§2)

# anon/surrogates.py  — CODE: how a surrogate is produced, one pure function per kind.
SURROGATES: dict[SurrogateKind, Callable[[str, DatasetContext], str]] = { ... }
```

**The tee vendors a byte-identical copy** at `tee/anon/` (mirroring how `tee/hl7_fields.py`/`tee/mllp.py`
were vendored), kept in sync by a CI parity check — the same discipline the tee already lives by. The
**harness imports `messagefoundry.anon` directly** (it already imports `parsing`/`generators`). This is the
**asymmetric resolution**: both sides run the *same rules*, the harness by import, the tee by a
parity-pinned vendor copy.

### 2. The rule model: field-*selection* is data, surrogate *production* is code (the load-bearing call)

A de-id rule has two halves, and the project identity dictates which half is which:

- **WHICH fields are scrubbed and WHAT *kind* of surrogate each gets** is **data** — the declarative
  `DEFAULT_RULES` field map (`FieldRule(path, SurrogateKind)`), optionally overlaid by an `anon.toml`. This
  is *config*, in the same sanctioned category as [`connections.toml`](0007-gui-manageable-connections-toml.md)
  transport config: a deployment customizing *which* PHI fields to scrub is data the way a connection's
  destination is data. §9 *requires* this centralization ("centralize the rules").
- **HOW a surrogate is produced** (the actual XPN/XAD/CX value, escaped, in the field's native datatype,
  keyed for consistency) is **code** — the `SURROGATES` registry of **pure Python functions** keyed by
  `SurrogateKind`. Authoring a *new* kind of surrogate is writing a function, not editing a rule.

This split is the **§12-safe line, and it is a sharper line than a single "declarative rule table" draws**.
The field map is pure *selection* — it can say "PID-5 → `NAME`" but it **cannot express a transform**: there
is no expression language, no field arithmetic, no conditionals, no `Filter`/`TransformStep`. The overlay
`anon.toml` may only *map a field to an existing `SurrogateKind`* (or `keep`/`drop`); it can never define new
behaviour. This incapability is **enforced by the loader**, not merely intended: `load_rules` validates each
overlay entry to permit **only** a `path → SurrogateKind` (plus `keep`/`drop`) and **rejects anything else at
load** — so the data layer is provably incapable of becoming a declarative *logic* surface. The moment a rule
needs to *do* something new, that is a code change in `surrogates.py`. It never touches `pipeline/`, never
enters a Router/Handler, and is tooling-side only ([CLAUDE.md](../../CLAUDE.md) §1/§4/§12 — code-first *logic*;
data only for config/shaping). **This shapes test data, not message routing.**

**Default rule set + override + per-deployment customization.** `DEFAULT_RULES` ships frozen in
`anon/rules.py` and is the recommended scrub map (§3 lists it). A deployment overrides via an optional
`anon.toml` in the run directory: `[hl7.fields]` adds/retargets a field to a `SurrogateKind`; `[hl7.keep]`
drops a field from scrubbing. **A site can add fields to scrub, but the leak-check (§5) is the fail-closed
backstop only for *known tokens* if its map under-scrubs** (a missed field with no denylisted token is not
caught — §5) — the overlay widens or narrows *selection*, never the surrogate logic.

### 3. Structure-preserving surrogates (replace, don't blank) — keyed and deterministic

Default behaviour is **`surrogate`, not `redact`**: PHI fields are replaced with **realistic synthetic
values of the same HL7 datatype** so field widths, repetitions, component grammar, and routing keys still
exercise the pipeline. The surrogate *functions* (the `SURROGATES` code registry, §2) draw from the
**vendored `_hl7data.py` pools** (`FAMILY_NAMES`, `STREETS`+`CITIES` as coherent `(city,state,zip)` tuples,
NANP-reserved fictional phones) rendered by `cx()`/`xpn()`/`xad()`/`xcn()`.

The **default field map** (`DEFAULT_RULES`) scrubs the standard PHI fields and `KEEP`s the routing/coded
ones: PID-3/4/18 (`MRN`/`ID`), PID-19 (`SSN`), PID-20 (`ID`), PID-5/6/9 (`NAME`), PID-7 (`DOB`), PID-11
(`ADDRESS`), PID-13/14 (`PHONE`); **MRG-1 (`MRN`), MRG-3 (`MRN`), MRG-4 (`NAME`), MRG-7 (`NAME`)** so an A40
patient-merge does not leak the prior MRN/name; NK1-2 (`NAME`), NK1-4 (`ADDRESS`), NK1-5/6/7 (`PHONE`),
**NK1-3 relationship `KEEP`** (table-coded, not identifying); GT1-3 (`NAME`), GT1-5 (`ADDRESS`), GT1-6/7
(`PHONE`), GT1-12 (`SSN`); IN1-16 (`NAME`), IN1-19 (`ADDRESS`), IN1-36/49 (`ID`), IN2-2 (`SSN`), IN2-3
(`FREETEXT`), **IN1-2/3/4 plan/company codes `KEEP`**; PV1-7/8/9/17 (`PROVIDER`), PV1-19 (`ID`); PD1-4
(`PROVIDER`); ORC-12/OBR-16/OBR-32 (`PROVIDER`); OBX-5 (`FREETEXT`, free-text observations only), OBX-16
(`PROVIDER`); NTE-3 (`FREETEXT`). **MRG-1 shares the `MRN` surrogate keying with PID-3** (same
`field_kind`), so across the merge pair old→old-surrogate and new→new-surrogate map consistently and the
merge linkage survives. **MSH-7/9/10/12 are `KEEP`** so tee correlation + parity-diff (#14) and
routing/validation realism survive, and the coded clinical segments (DG1/AL1/PR1) are `KEEP`.

**Free-text default = full redaction.** `OBX-5` and `NTE-3` carry narrative that *commonly embeds
identifiers* (name/MRN/DOB/phone) which field-level surrogation cannot reach, and the leak-check (§5) only
catches *denylisted tokens*, not a stray real MRN in prose. So the **`FREETEXT` default is a blunt
full-redact** (replace the narrative wholesale), and a deployment may opt a field into surrogation via
`anon.toml` only with eyes open. Free-text is the **primary residual-leak surface** the leak-check backstops
but cannot fully cover (§5, Consequences).

All substitution goes **through the parsed model + re-encode**, **never raw string slicing**
([CLAUDE.md](../../CLAUDE.md) §8). Because the `_hl7data` encoders emit **field-level `^`-joined** values, a
`FieldRule.path` is a **whole-field** address (`PID-5`, `MRG-1` — never a component like `PID-5.1`) and the
surrogate is applied via `Message.set`'s **verbatim whole-field write**: it reads MSH-1/MSH-2 separators and
assigns the `^`-joined value as the field's components. (That write path rejects an embedded field separator,
and the repetition separator when rep-scoped — surrogate encoders never emit those.) Component-level scrubbing
of a single subfield would need a per-component surrogate emitting a bare leaf; that is **out of scope** (§7).
Parsing is **tolerant** (python-hl7 peek path on engine side / vendored splitter on tee side), **never strict
hl7apy** — the whole point is to preserve quirks, and a non-conformant message must still de-id (anonymize
what's reachable; **fail closed** = withhold + error, never emit un-anonymized).

### 4. Consistency + the re-identification hazard

Consistency is **deterministic keyed pseudonymization**: the surrogate for a value is
`Random(f"{dataset_key}|{field_kind}|{original_value}")`-seeded, so the **same MRN → same surrogate within
one dataset** (cross-message ordering/merge, e.g. A40 with MRG-1 keyed identically to PID-3, stays testable)
without storing any map.

**R6 — no persisted pseudonymization map.** A persisted original→surrogate map *is* a re-identification key
and *is* PHI; this design **never writes one** (see *Reproducibility* below and Option 4). Any in-memory
original→surrogate cache lives only for the run's lifetime, is classified PHI-equivalent, and is **never
written beside the output, never committed, never logged** ([PHI.md](../PHI.md) §9 / §1 threat model). No
original→surrogate pair is ever emitted together with `dataset_key`.

**`dataset_key` is a per-run secret salt.** It is drawn from `secrets.token_bytes`/`os.urandom` with **≥128
bits** of entropy, held **only in process memory**, classified **PHI-equivalent** (it is itself a
re-identification key for the seeded PRNG), **never written / logged / committed**, and **discarded at run
end**. Keying is **one-way** (seeded PRNG, no inverse), so no surrogate can be inverted to its original.

**Irreversibility is salt-dependent, not cryptographic.** `random.Random` seeded from a string is **not** a
keyed hash; the brute-force resistance here rests entirely on the salt never being persisted/logged and on
**no `(original, surrogate)` pair ever leaking alongside `dataset_key`** — within a run, with a small
surrogate pool, reversal is feasible if the salt or a plaintext pair leaks. If true cryptographic
brute-force resistance is later required, switch the seed derivation to an HMAC/BLAKE2 keyed hash; that is a
*To resolve on acceptance* question, called out below.

**Reproducibility model.** The per-run random salt means the **same real message anonymized twice yields a
*different* fixture** — good for one-shot exports, but it makes a regenerated "committable anonymized
dataset" (§6 harness) **non-deterministic across runs** (a diff of regenerated fixtures will churn). The
choice — random-per-run (non-reproducible output, strongest re-id posture) vs a pinned-per-dataset salt
(reproducible commits, weaker posture because the salt must be retained) — is left to the owner pass; this
ADR **defaults to random-per-run** and flags the tension. A pinned salt, if chosen, is itself a
re-identification key and falls under R6's handling.

Errors carry field **names/types**, never the cleartext value (no `f"failed on PID-5 value {x}"`); inside the
engine/console lean on `safe_exc()`. The standalone tee has **no** `safe_exc()`/`RedactionFilter` (those live
engine-only in [`redaction.py`](../../messagefoundry/redaction.py), PHI.md §7), so the vendored tee path
carries its **own minimal exception discipline** (field names/types only) — see §6.

### 5. Leak-check: `scan_forbidden` is the single authority, with a parity-pinned tee copy, gating fail-closed

Every anonymized dataset is run through the **reconciled forbidden-token set** *after* anonymization and
**before** it may be written to any shareable location — **fail-closed** (a single surviving forbidden token
blocks the whole output). The mechanism, spelled out so the SoT claim is honest:

1. **One authoritative token list.** The `FORBIDDEN` set in
   [`scan_forbidden.py`](../../scripts/publish/scan_forbidden.py) becomes an **importable module-level
   constant/function** (today it is a CLI script with two callers — `publish.ps1` and the pre-commit hook;
   making it importable is net-new work, not mere "exposure").
2. **Fold in the drifted copy.** `tests/test_load_config.py`'s `_FORBIDDEN_SUBSTRINGS` (adds the
   estate-vendor tokens) **and** its
   `54\d{4}` site-code pattern are merged into the authoritative list, and `test_load_config.py` imports the
   merged SoT (its divergent copy is **deleted**). This collapses the two drifted engine-side sources into one.
3. **The tee vendors the token *table*** under the §1 byte-parity CI check. So the honest count is **one
   engine-side authority + one parity-pinned tee copy** — *not* literally one file, but one authority with a
   byte-identical, CI-enforced fork (the same hedge §1 uses for the code). The parity check covers the
   **token list**, not just the code.

**Two coexisting match modes, not one replacing the other.** A **new, separate** case-insensitive
**substring** match mode is invoked **only by the anonymizer's `leak_check` over message bodies** — where
fail-closed-on-false-positive is acceptable and safer than missing `^ACMEHOSP^` inside a field (which the
publish-prose `\b…\b` word-boundary form misses). The existing **publish/pre-commit path keeps its `\b`
word-boundary regexes** over staged source/config files — substring matching is **not** a global change to
the publish guard. (Caveat for the owner pass: a bare `54\d{4}` substring over HL7 bodies — dense with
6-digit timestamps/order numbers/set IDs — will mass-false-positive; it must be anchored to a field/component
boundary or kept prose-scoped before it lands in the body-scan path. Some short tokens may likewise
false-positive on unrelated synthetic IDs; on an anonymizer's *output* a fail-closed false positive is the
safer error, but the trade-off is real — flagged below.) This is non-negotiable: **anonymization that
silently misses a field is worse than none** — though note the limit in the next paragraph.

**What the leak-check does and does not catch.** `scan_forbidden` detects **known partner/site tokens**, not
*structural* PHI: it has no MRN-shape, SSN-shape, DOB-shape, phone-shape, or name detectors. So a field whose
PHI the rule map **missed** sails through the fail-closed gate *clean* unless that field happens to contain a
denylisted token — a real MRN is not a denylisted string. **Rule-map completeness is therefore the primary
control; the leak-check backstops known *strings*, not missed *fields*.** Adding structural detectors
(MRN/SSN/DOB/phone shape, NANP-reserved vs real) to the post-anon check as a *true* field-level backstop is a
candidate improvement, scoped out for this slice with the residual called out (Consequences).

### 6. Integration points

- **Tee — anonymize on export.** A **new** subcommand `tee anonymize-captures` (NOT folded into the body-
  free `tee export`, whose PHI-safe-by-construction contract is load-bearing): reads
  `RelayStore.captures(direction="corepoint_copy")`, pipes each `CaptureRow.raw` through `tee.anon.anonymize`,
  runs `leak_check`, and on a clean pass writes de-identified bodies (`--out`). **Precondition:** captures
  are written **only when the relay ran with `--capture-bodies`** (the body table is empty otherwise), so the
  subcommand must **error clearly when no captures exist** rather than silently writing an empty corpus. It
  **composes with** the test-data-only banner + `scan_forbidden` (anonymize is how you *earn* the right to
  leave test-data-only — gated by the leak-check, never bypassing the guard). **stdout/stderr discipline:**
  the path must **not echo input bodies or any pre-anon field value**; exceptions carry field names/types
  only (the tee's own minimal redaction, §4); the only normal output is the de-identified file. **Do not
  redirect raw-capture processing logs to any committed/CI sink** (mirrors [CLAUDE.md](../../CLAUDE.md) §9 on
  dryrun/generate output).
- **Harness — anonymize on capture + send.** Insert `anonymize` at the single
  [`CaptureSink._write`](../../harness/reconcile/capture.py) choke point so persisted JSONL carries
  de-identified `raw` (latin-1 round-trip preserved). Add a **file-backed corpus source** feeding
  `Corpus.next()`'s existing MSH-10 restamp so the harness can **send a committed anonymized dataset**.

### 7. Scope

**In:** HL7 v2 first (the migration need). **Seam, not built:** dispatch on `content_type` ([ADR
0004](0004-payload-agnostic-ingress.md)) so X12 (`parsing/x12/`)/FHIR/raw plug in later — never HL7-parse a
non-HL7 body. **Out:** statistical expert-determination de-id, free-text NLP scrubbing (NTE-3/OBX-5 narrative
default to **blunt full-redaction**, §3 — not entity-level NLP), **per-component (bare-leaf) surrogates** (the
default encoders are field-level `^`-joined, §3), structural PHI detectors in the leak-check (§5), and any
re-identification/linkage tooling.

### 8. Relationship to the planned de-id framework

On landing, this **would become** the de-id framework's **first bounded slice** — a *test-data* anonymizer,
not the full enterprise pipeline. **While this ADR is Proposed nothing is built**, so it does **not** yet flip
[PHI.md](../PHI.md) §9 from `[ROADMAP]` to built — that flip, and the lockstep CLAUDE.md §9 / §4 (carve-out)
and PHI.md §12/§13 edits, happen **only when the code lands**, never on acceptance (CLAUDE.md §9: "don't
reference a framework that doesn't exist"). The rule table is **designed to be reusable** as the future
AI-assistant `deidentified` data-scope source (PHI.md §9 forward-links to it on landing).

## Options considered

1. **Vendored pure-stdlib module + duplicated copy (CHOSEN) vs a shared installable package both import vs the tee keeping its own logic.** A shared `messagefoundry`-package import would force `tee/ → engine`, killing the standalone invariant the cutover relay depends on. The tee keeping its *own* logic is the copy-paste duplication §9 bans. **CHOSEN:** a module pure enough that vendoring is free, with the **rule table as the single engine-side authority** and a CI parity check pinning the copies byte-identical — duplication of *bytes* under one authority, not duplication of *logic*. **Rejected** both alternatives.
2. **Two-layer model — data field-map over code surrogate functions (CHOSEN) vs a single all-declarative rule table vs pure code-only rules.** A *single declarative table* that also encoded surrogate behaviour (an `action`/transform column, conditionals) is the seductive middle and the **§12 trap** — it grows into a de-id *DSL*, declarative *logic* authoring we declined (#26). *Pure code-only* (every rule a Python function, no data layer) honours §12 but fails §9's "centralize/inspect the rules" and makes per-deployment field customization a code edit. **CHOSEN:** split them — **field *selection* is data** (like [ADR 0007](0007-gui-manageable-connections-toml.md) transport config, overlay-able, inspectable, leak-auditable) and **surrogate *production* is code** (a registry the overlay can only *select* from, never extend, **enforced by the loader** rejecting any non-`path→kind`/`keep`/`drop` key). The data layer is provably incapable of expressing a transform, so the §12 line holds tighter than a single table would. **Rejected** both the all-declarative table and the all-code form.
3. **Surrogate substitution (CHOSEN) vs blank/redact.** Blanking destroys field widths/repetitions/routing keys — the exact shapes the fixtures exist to exercise. **CHOSEN** datatype-faithful surrogates from the existing `_hl7data.py` pools. **Rejected** redaction as the default (kept only as the per-rule action for free-text, which defaults to full redaction — §3).
4. **Per-run salted keyed pseudonymization (CHOSEN) vs a persisted consistency map vs a fixed global key.** A persisted map *is* PHI and a re-identification key — **forbidden by design (R6, §4)**. A fixed key makes surrogates brute-forceable back to originals. **CHOSEN** an in-memory, per-run-salted seed (CSPRNG, ≥128 bits, discarded at run end): consistent within a dataset, irreversible across runs (salt-dependent, not cryptographic — §4), nothing persisted. **Rejected** both. (Reproducibility tension and an optional HMAC/BLAKE2 upgrade noted in §4 / *To resolve on acceptance*.)
5. **Reuse + reconcile `scan_forbidden` (CHOSEN) vs a new anonymizer-private denylist.** A second denylist is exactly the drift that already bit the repo (the `test_load_config.py` set diverged from `FORBIDDEN`). **CHOSEN** one reconciled engine-side authority (importable, folding in the test copy + `54xxxx` pattern, that test deleting its fork) with a parity-pinned tee copy, and a **separate body-only substring match mode** (the publish/pre-commit path keeps `\b` word-boundary). **Rejected** a private list.
6. **Vendor `_hl7data.py` pools (CHOSEN) vs a new dep (e.g. Faker) vs importing `generators/`.** Importing `generators/` is impossible for the tee (`_core.py` pulls `hl7apy` + the engine). Faker is a new runtime dep, not vendorable into the dependency-free tee, and unjustified when conformant pools already exist. **CHOSEN** lifting the pure pools/encoders — **zero new dependencies**. **Rejected** Faker and the cross-package import.

## Consequences

**Positive**
- **Zero new runtime dependencies.** Pure stdlib + a lift of already-pure pools; the tee stays
  `aiosqlite`-only-plus-stdlib, the engine gains no dep. Satisfies the §5/§7 minimal-dependency gate with
  nothing to vet.
- **Tee standalone invariant preserved.** No `messagefoundry` edge added to `tee/`; the vendor-a-pure-module
  pattern is the one the tee already proves with `hl7_fields.py`/`mllp.py`.
- **Structure-faithful, replayable fixtures.** Surrogates keep widths/repetitions/grammar and never touch
  MSH-7/9/10/12/correlation keys, so #14 parity-diff and A40 merge logic (PID-3 ↔ MRG-1, keyed identically)
  still exercise on the de-identified set.
- **One reconciled denylist authority.** The fail-closed leak gate makes a "silently missed *token*" a build
  failure, and folding the two drifted denylists into one importable authority fixes a latent drift the repo
  already recorded.

**Negative / risks**
- **PHI-leak risk in the anonymizer's own paths.** It processes raw PHI by definition; a careless log/error
  could leak the **input** body, a pre-anonymization field, or the in-memory surrogate cache (PHI under R6).
  The §4/§7/§9 "no full body, no field value in an exception" rules are a **hard invariant** the build must
  honour — input stays off stdout/logs, errors carry field *names* only, output is gated behind the
  leak-check; the standalone tee carries its **own** minimal redaction (no engine `safe_exc()`).
- **Leak-check catches tokens, not structural PHI.** `scan_forbidden` detects known partner/site **strings**,
  not MRN/SSN/DOB/name *shapes*, so a field the rule map missed passes the "fail-closed" gate clean unless it
  contains a denylisted token. **Rule-map completeness is the primary control**; the leak-check is necessary,
  not sufficient. Free-text (OBX-5/NTE-3) is the **highest-risk residual** — hence its full-redact default
  (§3). Structural detectors are a deferred improvement (§5/§7).
- **Vendored-copy drift — bytes *and* behaviour.** Two copies can diverge; the rule/surrogate/token *files*
  are mitigated by a CI **byte-parity** check (the existing tee discipline) under one authority. But the
  engine-side `anon/hl7.py` (delegating to `Message`) and the tee's **standalone stdlib re-encoder** are
  **behaviourally parallel, not byte-identical** by design — byte-parity cannot pin their escaping/repetition/
  MSH-separator semantics. A divergence (e.g. `O'Brien`, a repetition `~`) would silently yield *different*
  surrogates from the *same* rules. Mitigation: a **shared golden corpus** (same input → same anonymized
  output) run against **both** consumers, not just the byte-parity check on the data files. Real maintenance
  cost — the accepted price of the tee's standalone posture.
- **Reproducibility vs re-id posture.** Random-per-run salting (the default) makes regenerated "committable"
  fixtures non-deterministic across runs (diffs churn); a pinned-per-dataset salt would be reproducible but
  must be retained and is itself a re-identification key (R6). Tension flagged for the owner pass (§4).

**Out of scope (deferred / explicitly NOT promised)**
- X12/FHIR/raw anonymization (seam left per ADR 0004; **not** built — never HL7-parse a non-HL7 body).
- Statistical/expert-determination de-id, k-anonymity, and free-text **NLP** scrubbing depth (NTE-3/OBX-5
  default to blunt full-redact only — §3).
- Per-component (bare-leaf) surrogates and structural PHI detectors in the leak-check (§3/§5).
- Any re-identification, linkage, or persisted pseudonym-map capability — **forbidden by design (R6, §4;
  [PHI.md](../PHI.md) §9 / §1 threat model)**.
- A pipeline/Router/Handler de-id surface — this is tooling-side only and is **not** a declarative-logic
  precedent (§12).

## To resolve on acceptance

- [ ] Confirm `messagefoundry/anon/` (engine-owned) + `tee/anon/` (vendored byte-identical, CI-parity-checked)
      as the home — vs a single installable package — and that the rule *table* is the named engine-side
      authority with a parity-pinned tee copy.
- [ ] Ratify the **two-layer rule model** — declarative field-*selection* map (data, overlay-able by
      `anon.toml`) over a code `SURROGATES` registry — as the §12-safe line, and confirm `load_rules`
      **validates the overlay to permit only `path → SurrogateKind`/`keep`/`drop`** (rejecting anything else
      at load, so the §12 incapability is parser-enforced).
- [ ] Ratify `DEFAULT_RULES` (the field list in §3), especially the **MRG-1/3/4/7 additions** (A40 merge,
      MRG-1 keyed identically to PID-3), the `FREETEXT` **full-redact** default for OBX-5/NTE-3, and the
      `KEEP` set (MSH-7/9/10/12, NK1-3, IN1-2/3/4, coded clinical segments) so correlation + routing realism
      survive.
- [ ] Approve the **`scan_forbidden` reconciliation**: make `FORBIDDEN` importable; fold in
      `test_load_config.py`'s tokens + `54xxxx` pattern and **delete that test's divergent copy**; add a
      **body-only** substring match mode (publish/pre-commit stays on `\b`); **anchor or prose-scope `54\d{4}`**
      before it touches the body scan (6-digit false-positive risk). This **touches owner-managed publish-guard
      config**, so it needs an explicit owner pass.
- [ ] Confirm the **CSPRNG (≥128-bit), in-memory-only, discarded-at-run-end** keying, the no-re-id-map rule
      (R6), and the **reproducibility model** (random-per-run default vs pinned-per-dataset) — and whether an
      HMAC/BLAKE2 keyed-hash upgrade is required for cryptographic brute-force resistance.
- [ ] Confirm the integration surfaces: `tee anonymize-captures` (new subcommand, **not** folded into
      `tee export`; requires `--capture-bodies`; errors when no captures exist; no raw bodies to stdout/CI),
      harness `CaptureSink._write` hook, and the file-backed corpus source.
- [ ] Approve the **doc lockstep, gated on code landing (not acceptance):** add `anon/` to the CLAUDE.md §4
      console carve-out; flip PHI.md §9 `[ROADMAP]`→built; update CLAUDE.md §9 and PHI.md §12/§13.

---

*On acceptance: build `messagefoundry/anon/` + the vendored `tee/anon/` behind the standard quartet gate
(`ruff format --check` · `ruff check` · `mypy messagefoundry` · `pytest` with `QT_QPA_PLATFORM=offscreen`),
add the vendored-copy byte-parity CI check (covering the rule/surrogate/token files) plus a shared golden
corpus run against both re-encoders, reconcile `scan_forbidden`, then — on that code landing — perform the
PHI.md §9 / CLAUDE.md §4/§9 doc flips and move this ADR's README row to Accepted.*
