# Proposed backlog items from Fable review packet 10b (engine root modules packet 10 could not reach)

**These are proposals, not items.** No number is allocated and nothing here is written into
`docs/BACKLOG.md`. The Manager allocates serially after the packets land (owner instruction relayed
2026-09-12) and files from this list. Each proposal is in the house format minus the heading number,
with the duplicate search recorded. The byte-level reproductions are in the vaulted findings document
`docs/reviews/FABLE-PACKET-10B-ROOTREST-2026-09-11-FINDINGS.md` (vault branch
`vault/fable-packet10b-rootrest`); this file names the subject, the mechanism and the fix only.

Engine ref measured: `fa7bc9e3e`. Every impact claim is conditional: there are zero deployments
(`CLAUDE.md` section 0). The duplicate search ran over `docs/BACKLOG.md` and
`docs/archive/backlog/BACKLOG-CLOSED.md` by symptom, path and symbol, with item status read through
`parse_items`, and over the new `## N.` headings in the open PRs 1064, 1066, 1069, 1070, 1071 and 1072.

---

## A failed upload write leaves a body outside every uploads sweep

> **Filed - not started.** Measured at `fa7bc9e3e` by making the blob write fail half-way, and
> separately by making the sidecar's `os.replace` fail: `save` raised, and the uploads root was left
> holding a `.<id>.blob.<hex>.tmp` in the first case and a sidecar-less `<id>.blob` in the second.
> `list_files` returned zero, `prune_expired` ten years later removed zero, `reseal_to_active` returned
> zeros, because every sweep walks `_iter_sidecars`, which yields `.meta` names only.

**Cluster:** PHI, uploads. **Priority:** P1. **Verdict:** fix. **Severity:** Medium.

`messagefoundry/uploads.py` `_atomic_write_text` writes the temp file and then `os.replace`s it with
no cleanup if the write raises; `UploadStore.save` writes the blob and then the sidecar with no cleanup
if the second write fails. Disk-full is the realistic trigger and the blob is the large write. Under the
identity cipher the leftover holds base64 of the plaintext upload; under a configured key it holds
ciphertext that `rotate-key` will never re-seal and that `ResealResult.skipped` does not count. A first
deployment that hit this would keep a partial patient message beside its uploads for the life of the
directory, outside the retention window the module promises.

**Fix.** Unlink the temp file in a `finally` when `os.replace` did not run; unlink the blob when the
sidecar write fails; add a sweep (in `prune_expired` or at store open) for `.*.tmp` older than a few
minutes and for any `.blob` with no sidecar, counted in the prune result; add a test that fails the
second write and asserts the directory is clean afterwards. Finding P10b-01 in the vaulted document.

**Duplicate search:** none. #1112 (open) is the cross-shard quota ledger and #1169 (open) the
strict-ciphertext read, both adjacent and neither covering this; #1224 (closed) is the prune audit
actor. Searched `.tmp`, `orphan`, `prune_expired`, `reseal`, `_atomic_write_text`, `uploads_dir`.

---

## The startup attestation's fail-closed mode is a no-op when its baseline is missing, stripped or shadowed

> **Filed - not started.** Measured at `fa7bc9e3e` with the fabricated-install shape
> `tests/test_startup_attestation.py` uses. Positive control: a tampered module with `RECORD`
> untouched raised `IntegrityError`, one audit row, one alert. Then the same tampered module with
> `RECORD` deleted: no raise, `no_record=True`, zero rows, zero alerts, a DEBUG line. With `RECORD`'s
> package rows removed: no raise, classified editable. With a clean `RECORD` but the package loaded from
> a directory outside the install root: `attested=True checked=0 drift=0` and the INFO line
> `startup integrity: 0 engine file(s) attested clean`. All three under
> `[integrity].fail_closed_on_drift=true`.

**Cluster:** security, integrity. **Priority:** P1. **Verdict:** fix. **Severity:** Medium.

`messagefoundry/integrity.py` `attest_engine` returns a no-op result for an absent or empty `RECORD`
and for a `RECORD` with no first-party `.py` rows (the third editable-install signal), and
`_record_relpath` skips any loaded file outside the install root, so `checked` can be zero with
`attested=True`. `run_startup_attestation` acts only on `result.drift`. The module's stated adversary
has venv-write and restart rights, and that actor can delete or rewrite the baseline as easily as a
module; a re-sealed `RECORD` passes clean, and neither ADR 0041 D3 nor the docstring says the baseline
sits in the same trust domain as the code. The shadow shape needs no venv write at all, only a
`messagefoundry/` directory the service's working directory resolves before site-packages (packet 10's
P10-11 seen from the control's side).

**Fix.** Under `fail_closed_on_drift`, treat a missing or row-less `RECORD` on a distribution with no
`direct_url.json` editable flag as drift rather than editable; treat `attested=True` with
`checked == 0` as drift; log the no-op posture at WARNING and write the `startup_integrity` audit row
for it; add the four shapes as tests; state in ADR 0041 D3 and the module docstring that the control
detects an inconsistent edit and not a consistent one. Finding P10b-02.

**Duplicate search:** none. #54 (closed) built the control; #1432 and #1438 (closed) and #1442
(open) are the asset and line-ending halves; #1134 (open) cites a recorded digest in this module.
Searched `fail_closed_on_drift`, `attest_engine`, `RECORD baseline`, `no_record`, `shadow`.

---

## service.py elevates bare cmd.exe, net and powershell.exe from the operator's launch directory

> **Filed - not started.** Measured at `fa7bc9e3e` on Windows 11: with a `net.cmd` planted in a
> temporary directory and that directory as the working directory, `cmd.exe /c net stop
> "MessageFoundry"` and the `restart` chain both ran the planted script (with the
> `NoDefaultCurrentDirectoryInExePath` variable this session's shell sets removed, which is the
> Windows default); `ShellExecuteW` with a null `lpDirectory` started its child in the caller's
> working directory. The elevation step itself was not driven, because it needs a UAC prompt accepted;
> Microsoft documents a null `lpDirectory` as "the current working directory is used" for `runas` as
> for `open`.

**Cluster:** security, Windows deployment. **Priority:** P1. **Verdict:** fix. **Severity:** Medium.

`messagefoundry/service.py` `control_service` and `control_service_ex` hand `"cmd.exe"` and
`/c net stop "<name>" & net start "<name>"` to `ShellExecute` with the `runas` verb and no directory;
`install_service` does the same with a bare `"powershell.exe"`; `service_state` runs a bare `sc`.
The module docstring says both elevated forms run a "System32-only `net` command" and "neither
elevates user-writable code"; no executable is pinned. `service_status.py`, the read-only sibling, pins
`%SystemRoot%\System32\sc.exe` for exactly this hijack and carries a stricter name guard, so the
elevated path has the weaker of two drifting copies. The launch directory of the tray or of
`messagefoundry service restart` is an ordinary directory; a config repository an unprivileged
contributor can push a root-level `net.cmd` into is one. A first deployment whose operator ran the
service control from such a checkout would see the expected UAC prompt and, on accepting it, run the
planted script as administrator.

**Fix.** Resolve every executable to an absolute System32 path from `%SystemRoot%` the way
`service_status._sc_path` does, and pass that directory as `lpDirectory`; import the one guard and
parser from `service_status.py` instead of carrying a second copy; add a test that the argument string
names an absolute path; make the docstring true. Finding P10b-03.

**Duplicate search:** none for the executable resolution. PR 1064's proposed item on the two
status parsers' substring search is the read-side half of the same duplication and stays separate.
Searched `ShellExecute`, `System32`, `net.exe`, `net.cmd`, `PATH hijack`, `control_service`,
`install_service`, `_runas`, `_SAFE_SERVICE_NAME`, `parse_service_state`.

---

## The Corepoint importer's JSON and flat paths emit a live field-write stub the validated path removed as unsafe

> **Filed - not started.** Measured at `fa7bc9e3e`: a JSON export with one unrecognised action class
> targeting `PV2-3` generated `msg.set("PV2-3", msg.field("PV2-3") or "")`; against a synthetic ADT
> with no PV2 that line raised `KeyError`, and with the target changed to `PID-30` it grew the PID
> segment from six fields to thirty-one.

**Cluster:** importer. **Priority:** P2. **Verdict:** fix. **Severity:** Medium.

`messagefoundry/corepoint_import.py` `_generate_steps` emits the stub whenever `stub_path` is set.
`_decline`, on the validated role-parsed path, passes `None` with a comment saying exactly why the
stub is unsafe; `_map_action` (the superseded JSON layer) and `_map_statement` (the fallback for an
export whose `@Data` carries no span markup) still pass the recovered target, and `parse_any` keeps
that layer live for any input not starting with `<`. A generated handler deployed from either would
dead-letter every message lacking the target segment and pad the segment of every message that has it.

**Fix.** Pass no stub target from `_map_action` and `_map_statement`, carrying the recovered field in
the marker text as `_decline` does; delete the stub emission; add a test that a generated module holds
no `msg.set` for an unmapped action on either input layer. Finding P10b-04.

**Duplicate search:** none. #105 (open) is the importer feature item and its partial-build record.
Searched `stub_path`, `passthrough`, `msg.set(p`, `corepoint_import`, `import corepoint`.

---

## The Corepoint importer recurses once per sibling branch marker

> **Filed - not started.** Measured at `fa7bc9e3e`: an `<If>` body holding 1,500 bare
> `<Line Data="Else"/>` lines raised `RecursionError`; 900 parsed; the same for `Catch` under
> `<Try>`, and the render path recurses the same way.

**Cluster:** importer, untrusted input. **Priority:** P3. **Verdict:** fix. **Severity:** Low.

`_split_branches` recurses on `steps[i + 1:]` once per marker it splits at, so it is both recursive
and quadratic in width, while `_MAX_NESTING` bounds depth only. The module promises that a structural
problem is reported and never raised as an uncaught traceback.

**Fix.** Rewrite `_split_branches` as a loop; have the CLI map `RecursionError` with the other
structural errors. Finding P10b-05. Sibling of PR 1066's proposed `RecursionError` items on the DICOM
and FHIR parsers.

**Duplicate search:** none. Searched `_split_branches`, `RecursionError`, `_MAX_NESTING`.

---

## _lit and _comment_text render values the generated Corepoint module cannot carry

> **Filed - not started.** Measured at `fa7bc9e3e`, three runs: a literal containing a code point
> outside the Basic Multilingual Plane rendered as two lone surrogates whose `encode("utf-8")` raises;
> a JSON `"default": null` rendered as `default=null`, a `NameError` at import; a NUL in a JSON class
> name produced a module `compile` refuses.

**Cluster:** importer. **Priority:** P3. **Verdict:** fix. **Severity:** Low.

`_lit` is `json.dumps`, whose escaping is a valid Python literal for BMP text and not for astral text
(surrogate pairs) or for JSON scalars (`true`, `false`, `null`, `NaN`). The surrogate shape reaches
both input layers through any quoted `ItemCopy`/`ItemAppend` literal and would fail at delivery for
every message once deployed; the other two are JSON-layer only.

**Fix.** Render strings with `repr()` (or `ensure_ascii=False` plus a surrogate check), refuse
non-string scalars with `CorepointImportError`, strip C0 controls in `_comment_text`; three fixtures.
Finding P10b-06.

**Duplicate search:** none. Searched `_lit`, `json.dumps`, `surrogate`, `non-BMP`, `NUL`.

---

## import corepoint prints a raw traceback on an OSError its own docstring says it maps

> **Filed - not started.** Measured at `fa7bc9e3e`: `--out` pointing at an existing file,
> `FileExistsError` escaped `import_corepoint`, and `_import` in `__main__.py` catches only
> `CorepointImportError`.

**Cluster:** CLI. **Priority:** P3. **Verdict:** fix. **Severity:** Low.

The module docstring for `import_corepoint` says it raises `OSError` on a filesystem failure and that
"the CLI maps both to a clean error". It does not, and the last-resort excepthook is installed only by
`serve` (packet 10's P10-08), so the traceback prints raw.

**Fix.** Catch `OSError` and `RecursionError` in `_import` and route through `_emit_error`. Finding
P10b-07.

**Duplicate search:** none; packet 10's proposed last-resort-hook item is the general case and this is
the handler's own stated contract. Searched `import corepoint`, `_import`, `_emit_error`.

---

## scrub_credentials leaks the tail of a brace-quoted ODBC password and of a quoted value with spaces

> **Filed - not started.** Measured at `fa7bc9e3e`: `PWD={Pa;ss}word}` scrubbed to
> `PWD=<redacted>;ss}word}`; `ad_bind_password='my secret pass'` to
> `ad_bind_password=<redacted> secret pass'`. Nine other shapes scrubbed cleanly in the same run.

**Cluster:** PHI, logging. **Priority:** P2. **Verdict:** fix. **Severity:** Low.

`messagefoundry/secretscrub.py`'s value classes stop at `;`, whitespace and quotes. Braces are the
documented ODBC form for a password carrying `;`, which is the connection-string shape the SQL Server
store builds. #1478 (open), the module's own item, lists three residuals and neither of these.

**Fix.** When the value opens with `{` consume to the matching `}`, when it opens with a quote consume
to the matching quote, then fall back to the current class; add both shapes to the fixture table.
Finding P10b-08.

**Duplicate search:** none for these shapes. #1478 (open) and #1475 (open) are the vocabulary and
its derivation; PR 1064's #1547 is the DSN pattern's cost. Searched `secretscrub`,
`scrub_credentials`, `PWD={`, `brace`, `value class`, `ODBC`.

---

## convert_hl7_timestamp silently resolves an ambiguous or non-existent local time

> **Filed - not started.** Measured at `fa7bc9e3e`: `20261101013000` from `America/New_York`
> (01:30 on the fall-back day, which occurs twice) converted to `053000+0000`, the daylight reading;
> `20260308023000` (02:30 on the spring-forward day, which does not exist) converted to
> `073000+0000`. No error, no signal.

**Cluster:** transforms. **Priority:** P3. **Verdict:** fix. **Severity:** Low.

`messagefoundry/timezone.py` attaches the source zone with `datetime.replace(tzinfo=...)`, so
`fold=0` decides both cases and nothing documents it. The module's own `hl7_now` docstring says a bare
local stamp is ambiguous across a fall-back. A migration comparing output against Corepoint's would
differ by an hour for one hour a year.

**Fix.** Document the choice; offer a strict keyword that raises on an ambiguous or non-existent
input. Finding P10b-09.

**Duplicate search:** none. #1196 (open) is the `hl7_now` offset stamp, already built; #59 (closed)
built the helpers. Searched `convert_hl7_timestamp`, `fold`, `ambiguous`, `fall-back`,
`spring-forward`.

---

**Findings deliberately not filed** (part 7 of the vaulted document): the quadratic role scanner on
a crafted export, the reserved-device-name module stem (refuted on Windows 11), the empty `.txt`
upload, the `MSH`-plus-binary sniff (the route's second check holds), a directory at a sidecar path, the
display-only filename passing a bidi override (packet 17), the `$`-anchored guards admitting a trailing
line feed (cmd drops the rest; folded into the service item's fix), the two negative controls that
stayed green for a stated reason, and four documentation-accuracy flags handed to packet 18.
