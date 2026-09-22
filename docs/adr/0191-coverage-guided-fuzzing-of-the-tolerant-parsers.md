# ADR 0191 — Coverage-guided fuzzing of the tolerant parsers

- **Status:** **Accepted -- BUILT** with the change.
  <!-- Proposed (no code yet) -> Accepted (build may start) -> Superseded by NNNN / Rejected -->
- **Date:** 2026-09-22
- **Related:** [ADR 0034](0034-static-analysis-triage-policy-accepted-risk-register.md) (the accepted
  risk this closes the engine half of) ·
  [ADR 0054](0054-low-allocation-builtins-hl7-parser.md) (the built-ins tolerant
  backend, and the fallback guard the fuzzer exercises) · [ADR 0012](0012-x12-edi-codec.md) (X12) ·
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

**Nothing of the kind was wired.** Measured at `origin/main` 2026-09-22: a grep of `.github/`,
`pyproject.toml` and `scripts/` for `zap|schemathesis|atheris|boofuzz` returned one hit, inside a
vendored `package-lock.json`. The control -- `bandit|pip-audit|semgrep` on the same instrument --
fired across five files, so the near-zero was a measurement and not a dead probe. So the
Secure_Development_Standards section 6.1 *Dynamic* tier was defined and never run.

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
gate; an eighth would mean editing that blocking gate in three places. An extra rides the two
artifacts DEP-1 already checks (`requirements.lock`, `constraints.lock`) and needed no gate change.
`dev` is itself an extra here, so a tooling extra is the established pattern. A **`>=` floor, not the
`==` its CI-toolchain siblings carry**: those are pinned because the version is the contract of a gate
that can red a pull request, and this one cannot.

**Advisory, and structurally so.** Three independent things keep it advisory: the context is not in
`.github/required-contexts.txt` (branch-protection membership is the only thing that gates a merge),
the fuzz step carries `continue-on-error: true`, and `tests/test_required_contexts.py` now lists
`parser fuzzing (advisory)` in `_MUST_NOT_BE_REQUIRED`, so promoting it reds that test. There is
deliberately **no job-level `continue-on-error`**: GitHub reports such a job as SUCCESS, making a job
that cannot fail, and `tests/test_security_posture.py` refuses the idiom.

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

1. **The carve-out is narrow.** It matches one named structural condition -- the parsed message has a
   segment whose id is the empty string -- never a bare exception type. `tests/test_fuzz_targets.py`
   pins that narrowness by injecting the *same* exception type with the condition absent and
   asserting it escapes.
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
the required set stays at eight contexts.

**AC-5. Re-locking moves only the expected artifacts.** `uv lock` plus all seven DEP-1 exports, run
with the gate's pinned `uv==0.12.0`: only `uv.lock`, `requirements.lock` and `constraints.lock`
changed, 18 insertions total. The five scoped locks are byte-identical, so DEP-1 stays green.

## Options considered

**1. Atheris (chosen).** Coverage-guided, in-process, native libFuzzer. Guides mutation by branch
coverage inside the real parser libraries, because `instrument_imports` instruments `hl7` and
`pydicom` too, not only the engine's wrappers. Cost: Linux x86-64 only, which the marker contains.
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

**5. Fuzz `parse` only, and skip the accessors.** The obvious scope, and it would have measured almost
nothing -- the one finding to date is entirely in the accessor tier.

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
