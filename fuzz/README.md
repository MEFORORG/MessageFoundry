# Fuzzing the tolerant parsers

Coverage-guided fuzzing of the HL7 v2, X12 and DICOM tolerant parsers, with
[Atheris](https://github.com/google/atheris) (Google's libFuzzer binding for CPython).
The decision and its limits are [ADR 0191](../docs/adr/0191-coverage-guided-fuzzing-of-the-tolerant-parsers.md).

## What it checks

Every codec writes its contract down in its own error module: a malformed body raises that codec's
`ValueError` subclass, so a Router or Handler that already routes `ValueError` to the
error/dead-letter path catches it without special-casing the format. A missing optional extra raises
`RuntimeError` instead, deliberately, so a deploy error is not swallowed as a data error.

So a target feeds a parser arbitrary bytes and lets every **other** exception propagate. An escaping
`IndexError`, `KeyError`, `AttributeError` or `RecursionError` is a finding: the parser accepted a
body and then broke its own contract on a path the inbound pipeline already relies on.

Each target parses **and then reads the accessors the inbound path reads**. Fuzzing `parse` alone
would have missed the finding already registered in `KNOWN_FINDINGS`.

## Run it

Atheris ships manylinux x86-64 wheels only, so this needs Linux on x86-64. On any other platform
install nothing and read the next section instead.

```bash
uv pip install --constraint constraints.lock -e ".[dicom,fuzz]"

# One target, one minute.
MEFOR_FUZZ_TARGET=hl7_peek python -m fuzz.fuzz_parsers -max_total_time=60

# Overnight, with a corpus that survives the run and accumulates across runs.
MEFOR_FUZZ_WORK_DIR=~/mefor-fuzz MEFOR_FUZZ_TARGET=hl7_peek \
  python -m fuzz.fuzz_parsers -max_total_time=28800 -jobs=4
```

Run it as a module from the repository root, so the root is on `sys.path`. Arguments after the
module name go straight to libFuzzer; `-max_total_time`, `-jobs`, `-runs` and `-dict` are the useful
ones. Target names: `hl7_peek`, `hl7_tree`, `x12_peek`, `dicom_peek`.

A longer run is the point. The CI pass is 60 seconds per target on a pull request and 300 nightly,
which mostly re-walks branches already reached; coverage-guided fuzzing finds new ones with time.

## Off Linux, and on every CI leg

`fuzz/targets.py` imports no Atheris, so the targets run under plain pytest everywhere:

```bash
pytest tests/test_fuzz_targets.py
```

That suite is what keeps the harness honest. It drives every target over its seeds and over
degenerate input, and it **injects faults** to prove the detector works: one test asserts a planted
non-contract exception escapes a target, and another asserts that the narrowed carve-out for the
known finding does not swallow the same exception type when the structural condition is absent. A
fuzz harness nobody has seen catch anything measures nothing.

## Where the files go

Seed corpora and crash artifacts go **outside the repository** -- `$TMPDIR/messagefoundry-fuzz` by
default, or `MEFOR_FUZZ_WORK_DIR`. That is a control, not a convenience: every file the fuzzer writes
is message-shaped, and a corpus grows without bound, so keeping it out of the work tree means
`git add -A` cannot reach it.

## Seeds, and the one thing not to do

Seeds are the committed synthetic samples under `samples/messages/` plus small inline literals in
`fuzz/targets.py`. To add one, add it there.

**Do not seed from captured traffic.** libFuzzer prints and writes the input it crashed on, so a
real corpus would put payload content into a CI log and into a crash artifact. De-identify first
(`messagefoundry/anon/`, ADR 0030) and keep such a run local. Synthetic messages come from
`messagefoundry generate`; that corpus is git-ignored and should stay so.

## Known findings

`KNOWN_FINDINGS` in `fuzz/targets.py` records a contract violation this harness has produced but
that is not fixed, so the advisory job is not red on arrival -- an advisory job that is red the day
it lands gets ignored, and an ignored fuzzer is indistinguishable from no fuzzer.

Each entry is narrow: it matches one named structural condition, never a bare exception type. And
each is pinned from the outside by `tests/test_fuzz_targets.py`, which asserts the reproducer still
provokes the violation. When the defect is fixed that test fails, and the failure is the instruction
to delete the entry. A carve-out cannot quietly outlive its defect and become a blanket suppression.

## Not covered

ADR 0191 has the full list and the reasoning. In short: the strict validators (`hl7apy`, `pyx12`),
the XML, FHIR, compression and binary-carriage codecs, the legacy `python-hl7` tolerant backend, and
everything needing a live endpoint -- the MLLP listener, the HTTP API, ZAP and Schemathesis.
