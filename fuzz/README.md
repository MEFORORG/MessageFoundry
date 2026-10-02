# Fuzzing the tolerant parsers

Coverage-guided fuzzing of the HL7 v2, X12 and DICOM tolerant parsers, and of the byte-stream
decoders in front of them, with [Atheris](https://github.com/google/atheris) (Google's libFuzzer
binding for CPython). The decision and its limits are
[ADR 0191](../docs/adr/0191-coverage-guided-fuzzing-of-the-tolerant-parsers.md).

## What it checks

Every codec writes its contract down in its own error module: a malformed body raises that codec's
`ValueError` subclass, so a Router or Handler that already routes `ValueError` to the
error/dead-letter path catches it without special-casing the format. A missing optional extra raises
`RuntimeError` instead, deliberately, so a deploy error is not swallowed as a data error.

So a target feeds a parser arbitrary bytes and lets every **other** exception propagate. An escaping
`IndexError`, `KeyError`, `AttributeError` or `RecursionError` is a finding: the parser accepted a
body and then broke its own contract on a path the inbound pipeline already relies on.

Each target parses **and then reads the accessors the inbound path reads**. Fuzzing `parse` alone
would have missed the first finding it produced: an empty segment, fixed under BACKLOG #1594.

The targets added under vault BACKLOG #2683 cover the decoders a body passes through **before** it is
a message. Their refusals are named on each target in `fuzz/targets.py`; two are worth knowing here:

* `http_request` expects `HttpRequestError`, which is **not** a `ValueError`. The HTTP listener
  catches it by name and answers with its status.
* `binary_carriage` allows **no** exception at all out of `strip_documents`: the store backends'
  retention pass calls it with no `try`, so a raise there aborts the whole pass.

Three of the new targets also assert a property the decoder's own docstring states, and raise
`AssertionError` when it fails, which libFuzzer records like any other escape:

* `stream_frames` and `x12_frames` feed the same bytes once in one read and once cut into small
  reads, and the output must match. Reassembling a message a peer split across reads is the whole job
  of these decoders. With a small cap, neither may deliver a frame larger than the cap.
* `compression` checks that an accepted result is never larger than the ceiling it was given, which
  is the decompression-bomb guarantee.

## Run it

Atheris ships manylinux x86-64 wheels only, so this needs Linux on x86-64. From a Windows machine,
use WSL2 or a container: see [From a Windows machine](#from-a-windows-machine). To run the targets
without fuzzing, on any platform, see the section after that.

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
ones. Target names: `hl7_peek`, `hl7_tree`, `x12_peek`, `dicom_peek`, `stream_frames`, `x12_frames`,
`http_request`, `compression`, `binary_carriage`.

`stream_frames` and `x12_frames` read their **first input byte as a control byte**, not as stream
content: it picks the read size, and for `stream_frames` its low bit picks MLLP (even) or the raw-TCP
STX/ETX preset (odd). A crash unit for either of them therefore starts with that byte.

A longer run is the point. The CI pass is 60 seconds per target on a pull request and 300 nightly,
which mostly re-walks branches already reached; coverage-guided fuzzing finds new ones with time.

## From a Windows machine

Atheris has no Windows wheel, and nothing in this repository changes that. Run the fuzzer in Linux
x86-64 under Windows instead: WSL2, or a container. Either way, keep the corpus outside the work tree
(see [Where the files go](#where-the-files-go)).

**Windows on ARM cannot use WSL2 for this.** WSL2 there is an aarch64 Linux, and there is no aarch64
Atheris wheel. Use the container recipe with `--platform linux/amd64`, which runs under emulation and
is slow, or use an x86-64 Linux machine.

### WSL2

Once, from PowerShell: `wsl --install -d Ubuntu-24.04`, then reboot if it asks. Then, in the Ubuntu
shell:

```bash
# Clone inside the Linux file system, not under /mnt/c: the Windows mount is slow for a corpus that
# writes thousands of small files, and a Windows checkout's .venv is no use to Linux anyway.
git clone <the repository URL> ~/MessageFoundry
cd ~/MessageFoundry

# Install uv as its own documentation describes, then (Python 3.14 is the project floor):
uv venv --python 3.14 .venv
. .venv/bin/activate
uv pip install --constraint constraints.lock -e ".[dicom,fuzz]"

MEFOR_FUZZ_WORK_DIR="$HOME/mefor-fuzz" MEFOR_FUZZ_TARGET=hl7_peek \
  python -m fuzz.fuzz_parsers -max_total_time=60
```

From here the bash recipes in [Run it](#run-it) apply unchanged.

### A container (Docker Desktop, or any Linux x86-64 container runtime)

From PowerShell, in the repository root:

```powershell
docker run --rm -it --platform linux/amd64 `
  -v "${PWD}:/src:ro" -v mefor-fuzz:/fuzz `
  -e MEFOR_FUZZ_WORK_DIR=/fuzz -e MEFOR_FUZZ_TARGET=hl7_peek `
  python:3.14-slim bash -c "mkdir /work && tar -C /src --exclude=./.venv --exclude=./.git -cf - . | tar -C /work -xf - && cd /work && pip install --quiet --constraint constraints.lock -e '.[dicom,fuzz]' && python -m fuzz.fuzz_parsers -max_total_time=60"
```

Why each piece is there:

* **The checkout is mounted read-only and copied.** The editable install and the run happen in the
  copy, so nothing the container does can write into your work tree. The copy leaves out `.venv`,
  which is a Windows environment Linux cannot use, and `.git`, which the build does not need.
* **The corpus goes to a named volume, `mefor-fuzz`**, outside both the copy and your checkout, so it
  survives the container and accumulates across runs. The `/fuzz` path also clears the harness's own
  fence, which refuses a work directory inside the repository.
* **`pip` rather than `uv`**, because the image ships pip. `constraints.lock` carries no hashes, so
  pip reads it as a constraints file as it is.
* **`--platform linux/amd64`** is a no-op on an x86-64 host and is what makes the recipe run at all on
  an ARM one.

A crash artifact lands in the same volume, under `/fuzz/<target>/artifacts/`, because the harness
roots its default `-artifact_prefix` at `MEFOR_FUZZ_WORK_DIR`. libFuzzer also prints the crashing
unit as a `Base64:` line in the log, and that is enough to reproduce it natively on Windows: see
[Reproducing a finding from a CI run](#reproducing-a-finding-from-a-ci-run), which needs no Atheris.

### What has been verified, and what has not

Recorded 2026-10-02, for vault BACKLOG #2683, on Linux x86-64 with no Windows machine and no running
container daemon.

* **Run:** the container recipe's shell commands, without the container. The tree was copied with the
  same `tar` excludes into a fresh directory, installed into a fresh pip-seeded Python 3.14.0 virtual
  environment with `pip install --constraint constraints.lock -e ".[dicom,fuzz]"`, which installed
  atheris 3.1.0 and pydicom 3.0.2, and `python -m fuzz.fuzz_parsers` ran the `http_request` target for
  10 seconds from that copy.
* **Not run:** Windows itself, WSL2, Docker Desktop, the `docker run` line as a whole (in particular
  its PowerShell quoting and the Windows path in `${PWD}`), the `python:3.14-slim` image, and the
  emulated `linux/amd64` path on an ARM host. Treat those as written, not tested.

## Off Linux, and on every CI leg

`fuzz/targets.py` imports no Atheris, so the targets run under plain pytest everywhere:

```bash
pytest tests/test_fuzz_targets.py
```

That suite is what keeps the harness honest. It drives every target over its seeds and over
degenerate input, and it **injects faults** to prove the detector works. Every registered target has
an entry in its `_INJECTIONS` table, which plants a non-contract exception inside the code the target
drives and asserts it escapes; a separate test fails when a target is registered without one. Further
tests break the split-invariance, cap and ceiling properties on purpose and assert the target says so,
and one asserts that the narrowed carve-out for the known finding does not swallow the same exception
type when the structural condition is absent. A fuzz harness nobody has seen catch anything measures
nothing.

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

The register's first entry, the empty-segment finding, was fixed under BACKLOG #1594 and came out
with its carve-out. Its reproducer stays on as the `hl7_peek` seed `BLANK_SEGMENT_HL7`.

**It holds one entry today**, produced by `binary_carriage` within its first 299 executions on the
run that added it (vault BACKLOG #2683). An HL7 body whose MSH-2 carries fewer than four encoding
characters is accepted by `Peek.parse` and `Message.parse`, and `build_ack` answers it `AA`; then
`Message.field` raises a bare `ValueError` on the first read, and `strip_documents`,
`iter_obx_documents` and `extract_obx_document` all let it out. The retention document-strip pass
calls `strip_documents` with no `try`, so one such stored body would abort that pass on every run. The
reproducer, the full summary and the discriminator are on the entry in `fuzz/targets.py`. It is
registered and not fixed: fixing it is an engine change, and this harness does not make one.

## Not covered

ADR 0191 has the original list and the reasoning. That list predates vault BACKLOG #2683, which
added targets for the compression and binary-carriage codecs it names; the ADR's own text has not
been amended for that here. What is still not covered: the strict validators (`hl7apy`, `pyx12`),
and everything needing a live endpoint -- the listeners' socket loops, the HTTP API, ZAP and
Schemathesis. The legacy `python-hl7` backend is retired.

### Decode surfaces checked under vault BACKLOG #2683

Each entry point below takes bytes an outside party chooses. "Target" means it now has one; "ruled
out" says why it does not.

| Surface | Verdict | Why |
|---|---|---|
| `mllpcodec.MLLPDecoder`, over `framing.FrameDecoder` (the MLLP listener's reassembler) | target `stream_frames` | Pure and stateful over socket reads; nothing covered it. |
| `transports/tcp.py` delimiter framing | covered by `stream_frames` | The TCP source and destination build the same `FrameDecoder` from a preset or explicit bytes; the target drives the STX/ETX preset. What `tcp.py` adds is the socket loop. |
| `parsing/x12/interchange.py` `X12FrameReader`, used by `transports/x12.py` | target `x12_frames` | The transport is a socket wrapper around this reader. The same target drives `split` and `check_integrity`. |
| `transports/http_listener.py` `_read_head` and `_read_body` | target `http_request` | The unauthenticated, pre-ingress request parser. Driven through `_read_request` on an in-memory `StreamReader`. |
| `transports/http_listener.py` header-mode authentication (`_authorize_head`) | ruled out, for now | Needs a configured `HttpSource` with credentials. The next candidate on this surface. |
| `parsing/compression.py`, all four decompressors | target `compression` | `gzip_decompress` runs on a File feed with `decompress="gzip"`; the rest are Handler-facing. |
| `parsing/binary.py`: carriage `decode`, `parse_doc_ref`, `strip_documents`, `iter_obx_documents`, `extract_obx_document` | target `binary_carriage` | Produced the known finding above. |
| `parsing/binary.py` `reattach_documents_in_hl7` | ruled out | Delivery side: it runs on a skeleton the engine wrote, through an async store reader. |
| `parsing/sniff.py` | ruled out as a target of its own | Prefix tests with no exception path. The archive-member checks run inside `zip_decompress`, so `compression` reaches them. |
| `parsing/split.py` `split_batch` (File ingress batch split) | ruled out | A regex split and string operations on a `str`, with no exception path. |
| `mllpcodec.build_ack` | ruled out | Its reads are the `Peek` accessors `hl7_peek` sweeps, and it wraps them in `except PEEK_READ_FAULTS`. |
| `parsing/xml` `XmlMessage.parse` and `parsing/fhir` `FhirPeek` | ruled out, after a probe | Both wrap a C decoder (lxml, the stdlib `json`) that Atheris cannot instrument. A 25-second Atheris probe of both ran 2,134,668 executions, plateaued at 82 coverage edges, and found nothing. |
| DICOM C-STORE SCP and DICOMweb STOW-RS | ruled out | Need a live association or request. The dataset parse behind them is `dicom_peek`. |
