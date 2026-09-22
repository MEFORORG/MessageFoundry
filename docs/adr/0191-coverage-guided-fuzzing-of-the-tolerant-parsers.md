# ADR 0191 — Coverage-guided fuzzing of the tolerant parsers

- **Status:** **Accepted -- BUILT** with the change.
  <!-- Proposed (no code yet) -> Accepted (build may start) -> Superseded by NNNN / Rejected -->
- **Date:** 2026-09-22
- **Related:** [ADR 0155](0155-dast-dynamic-security-testing-of-the-running-engine.md) (**DAST of the
  running engine -- the section 6.1 *Dynamic* row's instrument, built 2026-07-31.** Different work,
  not an earlier pass at this: 0155 drives a running service over its authenticated HTTP API, this
  fuzzes a pure library in-process. See *Context* for why that distinction is load-bearing and how
  this ADR's first draft got it wrong) ·
  [ADR 0034](0034-static-analysis-triage-policy-accepted-risk-register.md) (the accepted
  risk this closes the engine half of) ·
  [ADR 0054](0054-low-allocation-builtins-hl7-parser.md) (the built-ins tolerant
  backend, and the fallback guard the fuzzer *traverses* -- it cannot report through it; see option
  5) · [ADR 0012](0012-x12-edi-codec.md) (X12) ·
  [ADR 0025](0025-dicom-codec-store-connectors.md) (DICOM) ·
  [ADR 0030](0030-anonymization-test-harness-tee.md) (de-identification, the prerequisite for ever
  seeding from captured traffic) · [CLAUDE.md](../../CLAUDE.md) section 0 (severity in the
  conditional), section 4 (`parsing/` is a pure library) and section 9 (PHI) ·
  [Secure_Development_Standards.md](../Secure_Development_Standards.md) section 6.1 (the *Dynamic*
  tier) · BACKLOG #277

---

## Context

**BACKLOG #277 asks for independent-verification and dynamic-testing paths as an alternative to a
funded penetration test.** Its Lane 1 names four instruments: OWASP ZAP, Schemathesis against the
FastAPI schema, boofuzz against the MLLP listener, and coverage-guided fuzzing of the tolerant
parsers. This ADR covers the fourth and only the fourth.

**No coverage-guided fuzzing was wired.** That is the claim this section supports, and it is
narrower than the one the first draft made. The instrument is given rather than only its result,
because a count is a fact about one ref and one scope and moves when either does. Read at
`origin/main` (`e290caef2`), 2026-09-22:

```
git grep -lEi 'zap|schemathesis|atheris|boofuzz' origin/main -- .github pyproject.toml scripts
git grep -lEi 'bandit|pip-audit|semgrep'         origin/main -- .github pyproject.toml scripts
```

The needle returns **one** file, and that hit is a **false positive**: `zAp` inside a base64
`integrity` hash in the vendored `.github/actions/cla-assistant-lite/upstream-package-lock.json`.
Drop the `i` and it returns **zero**. So the true count of coverage-guided fuzzing or DAST tooling
in that scope is **zero**, not one, which strengthens this section's argument while invalidating the
arithmetic its first draft carried. The control, same instrument and same scope, returns **22** files
(21 case-sensitive) -- 9 restricted to `.github/workflows/`, 75 over the whole tree -- so the zero is
a measurement and not a dead probe.

**The first draft of this paragraph said the control "fired across five files". That reproduces at no
scope, and it is corrected here rather than quietly dropped.** It came from the dispatching brief and
was carried in good faith; a figure in an accepted ADR is a permanent record, so a reader who checked
it would have found the evidence for a near-zero unreproducible and had no way to tell a bad number
from a bad claim.

**THE FIRST DRAFT ALSO CONCLUDED THAT THE SECURE_DEVELOPMENT_STANDARDS SECTION 6.1 *DYNAMIC* TIER
"WAS DEFINED AND NEVER RUN". THAT IS FALSE, AND IT WAS THE FOUNDING PREMISE OF THIS ADR.** DAST is
built and shipped: [ADR 0155](0155-dast-dynamic-security-testing-of-the-running-engine.md) is
`Accepted (2026-07-31) -- increment 1 built`, and `.github/workflows/dast.yml`,
`scripts/security/dast_auth_sweep.py`, `scripts/security/dast_target.py` and
`scripts/security/dast-policy.json` are all on `origin/main`. ADR 0155's own *Scope boundary* section
states which part of the section 6.1 row it fills; read it there rather than here.

**The false premise survived because the probe above was BACKLOG #277's own.** Its needle is
`zap|schemathesis|atheris|boofuzz` -- the four instruments that row names -- and DAST arrived under
none of those names, so a zero for Lane 1's tooling was read as a zero for the whole tier. The
probe is correct for what it asks and was never asked the right question (CLAUDE.md section 11,
SDS-3.8). `git grep -il dast` breaks it in one line and returns 42 files at the same ref. **Do not
re-verify a row's premise by re-running that row's own probe**; it reproduces the row's answer by
construction, which is what it did here, twice, before two reviewers reached the defect by
independent routes.

**What is true, and what this ADR may therefore claim.** The section 6.1 *Dynamic* row names one
instrument -- `DAST / authenticated testing of the running app` -- and does not name fuzzing at all.
ADR 0155 covers the authenticated HTTP API plane and is explicit about the surfaces it does not
reach, among them the unauthenticated MLLP, TCP, X12 and DICOM ingress plane, which it defers on
size rather than on value and whose hard part it names as the oracle. This ADR supplies an oracle
for the *parsers* behind that plane -- each codec's documented `ValueError` subclass -- and runs
in-process, touching no listener and no running engine. **So the two are different work, not two
passes at the same tier row: 0155 is dynamic testing of a running service, this is an in-process
fuzz of a pure library.** Neither subsumes the other, and this change adds no coverage to 0155's
row.

**Whoever next re-scores WP-BL3-02 or the corresponding ASVS cell should read the previous paragraph
as the whole of the relationship.** This ADR does not newly cover a tier that was empty, because it
was not empty; and it is not a second instrument inside ADR 0155's scope, because it is outside it.

**The parsers are the right first slice, for a reason that is a property of the code rather than a
preference.** `messagefoundry/parsing/` is a pure, side-effect-free library (CLAUDE.md section 4's
one carve-out to the dependency rule) whose entire job is untrusted input. It needs no server, no
listener, no store and no network, so it fuzzes in-process in a single short job. The other three
Lane 1 instruments each need a live endpoint, which is a different problem and a separable one.

**There is an exception contract to fuzz against, and it is already written down.** Each codec's
error module states it: a malformed or hostile body raises that codec's `ValueError` subclass --
`HL7PeekError`, `X12Error`, `DicomError` -- so a Router or Handler that already routes `ValueError`
to the error/dead-letter path catches it without special-casing the format, and the count-and-log
invariant holds for free. `dicom/errors.py` says so in as many words, and adds the deliberate
distinction that a **missing optional extra** raises `RuntimeError` instead, so a deploy error is
not swallowed as a data error. That gives a fuzzer a decidable question instead of a vague one.

**What was already there is not this, and must not be counted as it.** BACKLOG #89 built a
hand-written adversarial corpus and a wall-clock timeout around strict validation. That is a fixed
set of inputs somebody thought of. Coverage-guided fuzzing generates inputs nobody thought of, and
steers by branch coverage toward the ones that reach new code. Neither subsumes the other.

## Decision

**Adopt [Atheris](https://github.com/google/atheris) -- Google's libFuzzer binding for CPython --
to fuzz the tolerant HL7 v2, X12 and DICOM parsers, behind an advisory CI job.**

**The invariant a target asserts.** Feed a parser arbitrary bytes; let every exception that is *not*
that codec's contract error propagate. A propagating exception is what libFuzzer records as a crash.
So the harness asks exactly one question: does a tolerant parser ever accept a body and then break
its own exception contract on a path the inbound pipeline already relies on?

**Targets parse and then read the accessors, which is the load-bearing design choice.** A Router does
not stop at `parse`; it reads routing fields off the result, before the ACK. So `hl7_peek` parses and
then reads all eleven named routing properties plus `routing()` and `segments()`, and `x12_peek`
parses and then reads the ten ISA identity properties plus the group and segment walk. Fuzzing
`parse` alone would have found nothing: the finding below lives entirely in the accessor tier.

**Four targets**, in `fuzz/targets.py`: `hl7_peek`, `hl7_tree` (the tolerant structural view),
`x12_peek`, `dicom_peek`.

**The harness is split so that Atheris is confined to one file.** Atheris publishes manylinux x86-64
wheels only -- 3.1.0 ships cp312/cp313/cp314 `manylinux2014_x86_64` and nothing else, no Windows and
no macOS wheel (measured against PyPI 2026-09-22). `fuzz/targets.py` therefore imports no Atheris and
runs everywhere; `fuzz/fuzz_parsers.py` is the only importer of it. The `[fuzz]` extra carries the
matching environment marker `sys_platform == 'linux' and platform_machine == 'x86_64'`, which is what
keeps the dependency out of the Windows legs' resolution even though `requirements.lock` is exported
`--all-extras`.

**A new extra rather than a new dependency group**, deliberately. The three existing
`[dependency-groups]` are consumed from committed `ci/locks/*.lock` files re-exported by the DEP-1
gate; a **fourth `ci/locks/*.lock` -- the eighth DEP-1 export** -- would mean editing that blocking
gate in three places. (The first draft wrote "an eighth `ci/locks/*.lock`", fusing the two counts:
`ci/locks/` holds three files, and the seven DEP-1 exports AC-5 names are those three plus
`requirements.lock`, `constraints.lock` and the two docker profile locks.) An extra rides the two
artifacts DEP-1 already checks and needed no gate change. `dev` is itself an extra here, so a tooling
extra is the established pattern.

**A `>=` floor, not the `==` its CI-toolchain siblings carry -- and the first draft justified that
with a claim about blast radius that is false.** It said those siblings are pinned because their
version is the contract of a gate that can red a pull request, "and this one cannot". The *job*
cannot; the *dependency* can. `requirements.lock` is exported `--all-extras`, so `atheris==3.1.0` is
in it, and `security.yml` audits that lock with `pip-audit` inside the **required**
`dependency-and-secret-scan` context. A CVE in a fuzzing tool can therefore red a required context
and hold the merge queue for everyone.

**That exposure is accepted rather than engineered around, and `security.yml` already argues the
case in those words.** Its DEP-1 step states the same consequence for the toolchain locks it audits
deliberately, noting that `requirements.lock` being `--all-extras` means "ruff, mypy and pytest
already do exactly this". Keeping atheris out of the audited lock would mean a fourth `ci/locks`
group, which is the gate edit this extra exists to avoid, and would also make the fuzzer the one
pinned, sticky toolchain nothing audits -- the "pinned, stale, unpatched is worse than floating"
failure [ADR 0034](0034-static-analysis-triage-policy-accepted-risk-register.md) section 3 names.
The escape hatch if it ever fires is the same one the rest of that step uses: `--ignore-vuln <ID>`
with the triage reason beside it. **The floor stays `>=` on its own merits** -- a newer Atheris
adopting a newer libFuzzer is a better fuzzer, not a changed verdict, because nothing reads this
job's result as a gate.

**Advisory, and structurally so.** Three independent things keep it advisory: the context is not in
`.github/required-contexts.txt` (branch-protection membership is the only thing that gates a merge),
the fuzz step carries `continue-on-error: true`, and `tests/test_required_contexts.py` now lists
`parser fuzzing (advisory)` in `_MUST_NOT_BE_REQUIRED`, so promoting it reds that test. There is
deliberately **no job-level `continue-on-error`**: GitHub reports such a job as SUCCESS, making a job
that cannot fail.

**Two of those three are pinned; the third was rename-fragile until this change, and the ADR claimed
otherwise.** `tests/test_security_posture.py` now refuses a job-level `continue-on-error` on this job
and asserts exactly one softened step -- both added after the fact, because the earlier text said
that module refused the idiom and it did not. Its cross-file sweep reaches only the jobs backing a
*required* context, which an advisory job by definition is not; that is a compensating control
resting on a false premise (CLAUDE.md section 11, SDS-3.7), and the claim was made true rather than
deleted.

The third guard is weaker than the other two by construction. `_MUST_NOT_BE_REQUIRED` holds **free
text**, matched at one place and never resolved against a real job, so renaming this job's `name:`
left it guarding a dead string while the job's new context was free to be promoted. Measured: of ten
mutations to `fuzz.yml`, that rename was the only one no test caught. The posture test now pins the
`name:` too, which closes the gap for this job without making the tuple self-checking in general.

**A fuzzer must not gate a merge, and that is a statement about what it measures.** A fuzz result is
a function of the time budget and the random seed, not of the diff. Requiring it would make merges
depend on what a mutator happened to reach in sixty seconds.

**Bounded in CI, unbounded locally.** 60 seconds per target on a path-gated pull request, 300 nightly,
`-max_len=8192`; the README documents the overnight form. The short pass is really a smoke test of the
harness -- coverage-guided fuzzing finds new branches with *time*.

**Seeds are synthetic by construction**: the committed synthetic samples under `samples/messages/`
plus small inline literals. No new message-shaped file is committed.

**The corpus lives outside the work tree** -- `$TMPDIR/messagefoundry-fuzz`, or `MEFOR_FUZZ_WORK_DIR`.
This is a control, not a convenience: every file the fuzzer writes is message-shaped and a corpus
grows without bound, so `git add -A` must not be able to reach it. That is stronger than a
`.gitignore` rule, which holds only while the pattern stays correct.

## The finding this already produced, and how it is carried

**A message carrying an empty segment -- a bare separator run such as `\r\r` -- parses, and then
every named routing property raises `IndexError`.** Not `HL7PeekError`. `_resolve_builtin` calls
`_builtin_hl7.raise_if_blank_segment_scan` *outside* its own `except (IndexError, ValueError)`,
deliberately, so a blank segment errors the way the legacy python-hl7 path errors. The consequence is
that the escaping exception is not a `ValueError`, so the documented `except ValueError`
dead-letter route does not catch it.

**In the conditional, per CLAUDE.md section 0 -- there are zero deployments.**
`_peek_for_loopback` in `pipeline/wiring_runner.py` catches `HL7PeekError` only and then reads
`peek.control_id` and `peek.message_type`. On first deployment, a loopback re-ingress of such a
message would raise through the re-ingress worker instead of recording the intended `peek_failed`
/ RECEIVED-to-ERROR disposition that function exists to produce.

**It is recorded, not fixed here.** Changing which exception the tolerant tier raises is a semantics
decision about bug-compatibility with python-hl7, and it is wider than this harness. Reported to the
dispatching Manager with the branch.

**So it is registered in `KNOWN_FINDINGS`, and the shape of that register is the point.** An advisory
job that is red the day it lands gets ignored, and an ignored fuzzer is indistinguishable from no
fuzzer. But a suppression that outlives its defect is worse than no carve-out. Two properties stop
that:

1. **The carve-out is narrow, and it is gated on BOTH an exception type and a structural
   condition.** It catches `IndexError` -- which *is* an exception-type gate, and this ADR's first
   draft said "never a bare exception type", which was wrong about its own code -- and then returns
   only when the parsed message carries a segment whose id is the empty string. Either half alone
   would be too wide; it is the conjunction that makes it narrow.

   Both halves are pinned in `tests/test_fuzz_targets.py`, and the second pin was added after the
   fact because **the type was unpinned and nothing showed it**: widening `except IndexError` to
   `except Exception` left all fourteen tests green. Both anti-vacuity tests drove a message with no
   blank segment, so both exercised the structural arm and neither reached the type. The current
   pair drives the condition absent with the same type (it must escape), and the condition present
   with a different type (it must also escape).
2. **It is pinned from outside.** A test asserts the reproducer still provokes the violation through
   the raw parser. When the defect is fixed, that test fails, and the failure is the instruction to
   delete the entry.

## Acceptance Criteria

**AC-1. The harness catches an injected fault.** `tests/test_fuzz_targets.py` injects a non-contract
exception on an accessor and asserts it escapes the target. Met.

**AC-2. The known-finding carve-out does not swallow its siblings.** Same exception type, same
target, structural condition absent -- it must escape. Met.

**AC-3. The harness finds a real defect under mutation, attributably.** Measured 2026-09-22 with a
random mutator standing in for libFuzzer (Atheris does not install on the authoring box, a Windows
machine), 20,000 iterations, fixed seed, over the committed synthetic seeds:

| Target | Arm | Result |
|---|---|---|
| `hl7_peek` | carve-out disabled | **`IndexError` after 13 inputs** -- rediscovered the registered finding unaided |
| `hl7_peek` | carve-out enabled (control) | clean over 20,000 |
| `x12_peek` | bounds check removed from `_element` (planted mutant) | **`IndexError` after 21 inputs** |
| `x12_peek` | mutant reverted (baseline control) | clean over 20,000 |

Both control arms matter. Without the `hl7_peek` control, the find is not attributable to the
carve-out; without the `x12_peek` baseline, the mutant's catch could have been a pre-existing defect
or a probe that always fires.

**AC-4. It adds no required status check and does not touch `.github/required-contexts.txt`.** Met --
the required set is unchanged by this ADR. **No count is given, deliberately** (CLAUDE.md section 5):
a checked-in number lags the server the moment branch protection moves, and this one sat in two
documents that `tests/test_numeric_required_set_claims_agree` cannot reach -- `docs/adr/**` is not in
its `_CLAIM_FILES`, and its pattern needs a digit, so a spelled-out count would evade it even if it
were. Read the live set from branch protection, or `.github/required-contexts.txt` for the
checked-in claim.

**AC-5. Re-locking moves only the expected artifacts.** `uv lock` plus all seven DEP-1 exports, run
with the gate's pinned `uv==0.12.0`: only `uv.lock`, `requirements.lock` and `constraints.lock`
changed, 18 insertions total. The five scoped locks are byte-identical, so DEP-1 stays green.

## Options considered

**1. Atheris (chosen).** Coverage-guided, in-process, native libFuzzer. Guides mutation by branch
coverage inside the real parser library, because `instrument_imports` instruments `hl7` too, not only
the engine's wrappers -- `parsing/peek.py` imports it at module top, so it loads while the context
manager is open. **`pydicom` did not, and this line used to claim it did.** `parsing/dicom/_deps.py`
imports pydicom inside function bodies, deliberately, to keep the engine importable without the
`[dicom]` extra; those run at parse time, after instrumentation has stopped. So `dicom_peek` was
guided only by the engine's thin wrapper and the mutator was blind to the DICOM parse surface.
`fuzz/fuzz_parsers.py` now imports pydicom explicitly inside the block; that is reasoned from
Atheris's documented behaviour rather than measured, because Atheris has no Windows wheel, and the
module docstring names the Linux check that would confirm it. Cost: Linux x86-64 only, which the
marker contains.
Provenance checked before adding it, per CLAUDE.md section 7: `atheris` on PyPI, source at
`github.com/google/atheris`, latest 3.1.0 -- the intended package, not a name-alike.

**2. Hypothesis (property-based).** Already a natural fit for a pure library and pure Python. Rejected
as the *wrong instrument for this question*, not as a bad tool: Hypothesis explores a space the author
describes, so it finds violations of properties somebody stated, and its shrinking is excellent. What
it does not do is steer by coverage toward unreached branches, which is precisely what was missing.
Worth adding later for the algebraic properties -- round-tripping, idempotence of `normalize` -- which
this harness does not test at all.

**3. `python-afl` / pythonfuzz.** Coverage-guided as well, but neither is maintained to a cp314
release; `atheris` 3.1.0 ships a cp314 wheel and this project requires Python >= 3.14.

**4. A hand-extended adversarial corpus (the BACKLOG #89 shape).** Cheapest, no dependency, runs on
Windows. Rejected as the thing that already exists: it cannot generate an input nobody thought of,
which is the whole gap.

**5. Fuzz `parse` only, and skip the accessors.** The obvious scope, and it would have measured
**nothing at all** at the HL7 tier, which is stronger than the "almost nothing" the first draft
claimed. `Peek.parse` cannot report a finding by construction: its built-ins arm falls back on any
unexpected error (ADR 0054's guard, logging and continuing), and the python-hl7 arm wraps every
exception into `HL7PeekError`, which every target treats as the contract being honoured. So the
HL7 parse tier is total with respect to this harness's question -- the fuzzer *traverses* those
branches but can never *report through* them. Every HL7 finding must come from the accessor tier,
and the one finding to date does.

**6. Make the job blocking.** Rejected; see the Decision. A time-budget-and-seed-dependent result must
not gate a merge.

**7. Upload crash artifacts from CI.** Rejected for now. libFuzzer already prints the crashing input,
which is enough to reproduce, and an artifact upload is one more permission and one more action for no
new information. Revisit if a nightly finding proves hard to reproduce locally.

## Consequences

**The Secure_Development_Standards section 6.1 *Dynamic* tier now has one instrument that runs.** One,
not all of them: three of Lane 1's four instruments are still unwired, and #277 stays open.

**This closes the engine half of ADR 0034's accepted risk for Scorecard's `Fuzzing` check
(WP-BL3-02), and it cannot close the record half.** The ASVS scorecard is a `[[cell]]` record in the
separate vault clone -- `docs/security/` is gitignored here, so `git ls-files docs/security` returns
zero from an engine checkout. **Nothing in this repository changes an ASVS verdict, and no prose here
should claim one has changed.** Whoever holds that record re-scores it against this change; this ADR
is the engine-side evidence, not the re-score.

**A secondary observation, reported rather than acted on.** The mutation run reached an internal fault
inside the built-ins parser (`_extract_separators`, an `IndexError` on `seps[0]`) within 13 inputs.
ADR 0054's fallback guard caught it exactly as designed -- fell back to python-hl7 and logged a
warning with `exc_info` -- so it is **not** a contract violation and not a finding against the
contract this harness tests. What it shows is that those internal faults are cheap to reach, so a
hostile sender could force the slow path and a stack-trace log line at will. No PHI in that log:
Python tracebacks print source lines, not values. Worth a look; not fixed here.

**The advisory job costs a runner slot only on a relevant diff.** Path-gated on
`messagefoundry/parsing/**`, `fuzz/**`, `tests/test_fuzz_targets.py` and its own workflow file,
because runner capacity is the merge queue's bottleneck and nothing here gates a merge.

**A carve-out register now exists, with a test that forces its own cleanup.** If `KNOWN_FINDINGS`
grows, that is a signal about the parsers, not about the harness -- and each entry has to carry a
reproducer and a narrow discriminator to be added at all.

## What this deliberately does NOT cover

**Two of the four targets still have an unpinned accessor sweep, and saying so is the point.** The
HL7 and X12 sweeps are now pinned by tests holding their own copy of the expected property list, so
shortening either list -- or the loop that reads it -- reds. `hl7_tree` walks a node structure and
`dicom_peek` drives `parse` plus a small metadata read, and neither has an equivalent pin, so either
could be quietly narrowed and the advisory job would go on reporting that every target survived its
budget. A half-closed hole reads as a closed one, so it is recorded here rather than left to be
inferred from which tests happen to exist.

**A `Peek.field()` target is missing and it is the widest surface there is.** `field()` takes an
arbitrary path expression and `summarize()` reaches it up to seven times on the pre-ACK path --
three for any message, seven on an ORM/ORU; no target calls it directly today. The named properties
reach it internally, which is how the known finding surfaced, but that is incidental coverage rather
than a target.

**The corpus fence is keyed to the running checkout, not to every worktree of this repository.** An
override pointing into a *sibling* worktree is accepted, and files written there are stageable from
that worktree. Fencing the whole worktree set would mean resolving git's worktree list at import
time, which is a dependency on git's layout that this module otherwise does not have. The realistic
mistake -- a relative path, or an unexpanded `~`, landing in the checkout you are running from -- is
the one that is refused.

**No size ceiling is fuzzed.** `-max_len=8192` sits 2048x below every parser's 16 MiB bound, so
those guards are unreachable in any CI pass; exercising one needs a deliberate long run with
`-max_len` raised past 16 MiB.

Stated plainly, because a fuzzing job's name invites the reader to assume more than it does.

- **The strict validators.** `hl7apy` (`parsing/validate.py`) and `pyx12`
  (`parsing/x12/validate.py`) are opt-in, off the hot path, and third-party. Not fuzzed.
- **The XML, FHIR, compression and binary-carriage codecs** -- `parsing/xml/`, `parsing/fhir/`,
  `parsing/compression.py`, `parsing/binary.py` -- and `sniff.py`, `split.py`, `consistency.py`,
  `groups.py`, `message.py`. All are reachable fuzz targets and none is wired. `compression.py` and
  `binary.py` are the two most worth doing next: both take attacker-influenceable bytes and both
  already carry bomb ceilings that want adversarial input.
- **The legacy `python-hl7` tolerant backend.** `_backend.USE_BUILTIN` defaults True and the targets
  fuzz the default only. The fallback path is exercised incidentally, never targeted.
- **Anything needing a live endpoint:** the MLLP listener (boofuzz), the HTTP API (ZAP,
  Schemathesis). Separable, still open under #277, and deliberately not scaffolded for here.
- **Semantic correctness.** A target asks whether the contract holds, never whether the parsed value
  is *right*. A parser that returns confidently wrong routing fields passes every target here.
- **Any judgement about real-world exploitability.** These are beta defects in a not-deployed
  engine (CLAUDE.md section 0).
