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

bash:

```bash
uv pip install --constraint constraints.lock -e ".[dicom,fuzz]"

# One target, one minute.
MEFOR_FUZZ_TARGET=hl7_peek python -m fuzz.fuzz_parsers -max_total_time=60

# Overnight, with a corpus that survives the run and accumulates across runs.
MEFOR_FUZZ_WORK_DIR="$HOME/mefor-fuzz" MEFOR_FUZZ_TARGET=hl7_peek \
  python -m fuzz.fuzz_parsers -max_total_time=28800 -jobs=4
```

PowerShell 7, for the same three commands. Note this means **pwsh on Linux x86-64**: Atheris has no
Windows wheel, so the form is given because it is this project's documented shell, not because the
fuzzer runs on Windows.

```powershell
uv pip install --constraint constraints.lock -e ".[dicom,fuzz]"

$env:MEFOR_FUZZ_TARGET = 'hl7_peek'; python -m fuzz.fuzz_parsers -max_total_time=60

$env:MEFOR_FUZZ_WORK_DIR = "$HOME/mefor-fuzz"; $env:MEFOR_FUZZ_TARGET = 'hl7_peek'
python -m fuzz.fuzz_parsers -max_total_time=28800 -jobs=4
```

**`$HOME`, never a bare `~`, and this is a containment rule rather than a style note.** Tilde
expansion is done by the shell, not by the variable, so any mechanism that sets the value without a
shell -- a quoted assignment, a Dockerfile `ENV`, a systemd unit, a CI `env:` block, PowerShell --
passes the literal `~` through to Python, where `Path("~/mefor-fuzz")` is a *relative* path that
resolves to `<repo root>/~/mefor-fuzz`. This recipe used to say `~/mefor-fuzz` and that is exactly
what it produced off bash. `work_root()` now expands the tilde itself and **refuses** any override
resolving inside the repository, so the mistake is an error rather than a corpus of message-shaped
files staged by `git add -A` (CLAUDE.md section 9). The refusal exits **3**, which the advisory
workflow reports as a harness fault rather than as a parser finding.

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

## Reproducing a finding from a CI run

The advisory job writes any finding to the **run's job summary**, with the crashing input as
base64. Read it there rather than in the step log: on run 35761703252 that input sat on line
568,193 of a 568,245-line log, which is why the summary exists.

Copy the base64 out of the summary and run the target on it. This needs no Atheris, so it works on
Windows. **Install the extra the target needs first**, or the run raises `RuntimeError: DICOM
parsing requires the optional 'dicom' extra` -- which `_dicom_peek` does not catch, so a missing
extra reads exactly like a confirmed finding:

```powershell
uv pip install --constraint constraints.lock -e ".[dicom]"

python -c "import base64; from fuzz.targets import TARGETS_BY_NAME; TARGETS_BY_NAME['dicom_peek'].run(base64.b64decode('<paste the base64 here>'))"
```

It raises the escaped exception, or returns silently if the contract holds. **A silent return means
you have the wrong bytes, not that the finding was spurious** -- a mis-copied base64 decodes to a
different unit, and a wrong unit parses cleanly and reads as an all-clear. Verified against run
35761703252: the printed unit is 155 bytes and reproduces byte-exact on Windows against the same
pydicom version, while a retyped copy decoded to 158 bytes and reported no finding at all.

**Check your bytes against the crash filename before you conclude anything.** libFuzzer names the
artifact by the SHA-1 of the unit, so the name in the log is a checksum you already have:

```powershell
python -c "import base64,hashlib; print(hashlib.sha1(base64.b64decode('<paste the base64 here>')).hexdigest())"
```

That matched `crash-e407a7c52d06668011f7624709f6f8927cbeb2b1` for run 35761703252. It catches any
mis-copy, including one that leaves the length unchanged, which comparing the hex dump against the
base64 does not.

On Linux you can also hand the decoded file straight to libFuzzer, which re-runs it under the
instrumented harness:

```bash
MEFOR_FUZZ_TARGET=dicom_peek python -m fuzz.fuzz_parsers ./crash-unit.bin
```

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
