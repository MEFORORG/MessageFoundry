# Proposed backlog items from Fable review packet 14 (ops surfaces)

**These are proposals, not items.** No number is allocated and nothing here is written into
`docs/BACKLOG.md`. The Manager allocates serially after the packets land (owner instruction relayed
2026-09-12) and files from this list. Each proposal is in the house format minus the heading number,
with the duplicate search recorded. The byte-level reproductions are in the vaulted findings document
`docs/reviews/FABLE-PACKET-14-OPS-2026-09-11-FINDINGS.md` (vault branch `vault/fable-packet14-ops`);
this file names the subject, the mechanism and the fix only.

Engine ref measured: `70063ab55`. Every impact claim is conditional: there are zero deployments
(`CLAUDE.md` section 0). Synthetic values only.

Scope: `messagefoundry/verify/`, `support/`, `tray/`, `anon/`, `generators/`, `security/`. No item is
proposed for `generators/` or `security/`: neither produced a finding.

---

## Proposal 1. Anonymizer: `_skip_obx5` exempts every non-textual OBX-2, so an embedded ED document and untyped free text in OBX-5 pass `anonymize_checked` as clean

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-01), by execution.
> `messagefoundry/anon/hl7.py` `_skip_obx5` skips the OBX-5 `FREETEXT` rule for any OBX whose OBX-2 is
> not one of `TX`, `FT`, `ST`, `CF`. Meant for numeric results, the exemption reaches `ED` (the ADR
> 0028 base64 carriage the engine's own `generators/documents.py` produces), `RP`, `CWE`/`CE` with a
> free-text component, and an **empty** OBX-2. OBX-5 is a mapped path, and the structural detectors run
> over unmapped fields only, so neither layer of `anonymize_checked` can see the skipped value. Measured
> at `70063ab55`: OBX-2 `ED` with a base64 document, OBX-2 empty with a name and MRN in prose, OBX-2
> `NM` with a name and phone, and OBX-2 `CWE` with a name in the text component were all emitted with
> the values intact and the coverage report silent about OBX-5.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build.
**Severity:** high. A first adopter running the tee's `anonymize-captures` over a real ORU or MDM feed
with embedded reports would write those reports verbatim into a dataset the tool has just certified
shareable. An embedded PDF is the most PHI-dense field an HL7 message carries.

**The closed item's premise.** BACKLOG #331 (closed) records as its residual analysis that "OBX-5/NTE-3
default to a blunt full-redact ... so the highest-risk residual is not this one". The code makes that
false for exactly the cases above (SDS-3.7). `test_obx5_freetext_only_when_value_type_textual` certifies
the `NM` exemption and no test feeds `ED`, an empty OBX-2, or free text under a non-textual type.

**Fix.** Invert the rule: a short allowlist of value types safe to preserve (`NM`, `SN`, `DT`, `TM`, `TS`,
`ID`, `IS`, and `CE`/`CWE` only when their text components are empty); everything else, including `ED`,
`RP` and an absent OBX-2, is textual and redacted. Tests for `ED`, empty OBX-2, `NM`-with-text and
`CWE`-with-text. Correct #331's residual note. Apply the same change to `tee/anon/hl7.py`, which is a
non-parity seam the parity test will not carry.

**Duplicate search.** No open item. #331 (closed) built the structural detectors and scoped OBX-5 out on
the premise above. #94 (open, DEMAND-GATE) is BLOB offload of OBX-5 documents, unrelated. Searched both
ledgers for `_skip_obx5`, `OBX-2`, `OBX-5 ED`, `encapsulated`, `anon`.

---

## Proposal 2. `verify` self smoke reports PASS when the synthetic message routes nowhere and delivers nowhere; an empty config directory is SKIP with a self-contradicting reason

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-02), by execution.
> `messagefoundry/verify/smoke.py` `smoke_self` fails only on `DryRunResult.error`, which
> `pipeline/dryrun.py` sets for a parse failure, a strict-validation failure or a router/handler
> exception. `UNROUTED`, `FILTERED` and a not-deployed sole destination return `error=None`. Measured
> at `70063ab55`: a router returning `[]` is `PASS disposition=unrouted, handlers=0, deliveries=0`; a
> handler returning `None` is `PASS ... deliveries=0`; a sole outbound `deployed=False` is `PASS ...
> deliveries=0`; a config directory with zero modules is `SKIP config has multiple inbound connections;
> choose one: ` with an empty list. Negative control: making the `result.error` arm return PASS left all
> 17 smoke tests green, so the FAIL branch has no covering test either.

**Cluster:** Ops & Deployment. **Priority:** P1. **Verdict:** build.
**Severity:** medium. `docs/testing/VERIFY.md` says the self smoke "proves your routers/handlers load and
route a message cleanly" and the package docstring says the tool answers "does a message actually
flow?". A deploying site with a router matching nothing, or a sole outbound not yet deployed, would read
a green acceptance report. Same family as packet 10's `check` "0 run(s) clean" and `audit-verify` on a
fresh database.

**Fix.** PASS only when `len(result.deliveries) >= 1`; otherwise FAIL naming the disposition and the two
counts. Check `len(reg.inbound) == 0` before `dry_run` and FAIL as "config loaded no inbound connection".
Add tests for unrouted, filtered and dry-run error. The `select_inbound` wording is packet 11's.

**Duplicate search.** No open or closed item. Packets 8 and 10 reported the empty-config-directory
family for `serve`, `validate` and `check`; their items are proposals not yet allocated, so they are
named by subject here. Searched both ledgers for `smoke.self`, `smoke_self`, `self smoke`, `dry-run
routing`, `empty config`.

---

## Proposal 3. `verify store.connect` creates the SQLite store it then reports PASS against, and `host.writable` creates directories on the box

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-03), by execution.
> `messagefoundry/verify/smoke.py` `check_store_connectivity` opens the configured store through
> `open_store`, whose schema-ensure creates the file; `verify/checks.py` `check_writable_dir` calls
> `mkdir(parents=True)` before probing. Measured at `70063ab55`: with the store file absent the check
> returned PASS and left a 372,736-byte database behind; with the parent directory absent it returned
> FAIL; `check_writable_dir` on a three-level missing path returned MANUAL and created all three levels.
> `docs/testing/VERIFY.md` introduces the default run as side-effect-free.

**Cluster:** Ops & Deployment. **Priority:** P2. **Verdict:** build.
**Severity:** medium. Two halves. A mistyped `[store].path` reads PASS because the check creates whatever
it is pointed at, so the row cannot fail for the reason its title names. And a first deployment's
operator running `verify` as an administrator on a fresh box would leave an administrator-owned store
and directories at the configured path before starting the service under another identity, which is
the identity gap the check's own PASS text warns about, manufactured by the check. Closed #43 fixed the
caveat wording only.

**Fix.** For SQLite, refuse to create: open with the `mode=ro` URI, or test `Path.exists()` and FAIL
("no store at <path>; run `serve` once, or check `[store].path`"). Never `mkdir` in `check_writable_dir`;
FAIL when the directory is absent. Tests asserting the file and directory do not exist after the check.
Say in `VERIFY.md` which sections write.

**Duplicate search.** #43 (closed) is the calling-user caveat text, not the side effect. Searched both
ledgers for `store.connect`, `check_store_connectivity`, `verify creates`, `side-effect`.

---

## Proposal 4. Support bundle: `config-summary.json` and `status.json` carry raw exception text that never passes through the redactor

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-04).
> `messagefoundry/support/bundle.py` `config_summary` writes `str(exc)` of any exception raised while
> loading the config into the bundle; `status_snapshot` writes the store-open failure the same way.
> Only `app-log.txt` goes through `redact_log_text`. Measured at `70063ab55`: a config module raising
> at import with a host and a secret literal in its message put both into `config-summary.json`
> verbatim. A `SyntaxError` was clean (basename and line only). The SQLite store limb was clean; the
> server-backend limbs (asyncpg names the user on an authentication failure and the host tuple on a
> refused connection) could not be measured, neither driver extra being installed.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build.
**Severity:** medium. The bundle exists to leave the box and its manifest asserts "no secrets". A config
that fails to load is exactly when a bundle is wanted. An operator module raising with connection
details, or a factory validation error echoing its `input` (the pydantic hazard
`verify/runner.py::_settings_error_detail` already guards against), would ship them.
`store/privilege.py` already wraps a store exception in `redact_log_line`; the bundle does not.

**Fix.** Route both strings through `redact_log_line` and bound them (the `safe_text` shape). One test
per member with a synthetic secret in the raised message. Until then, name the two unredacted members
in the manifest's `phi_contract`.

**Duplicate search.** No open or closed item. #1183 (open, ASVS 13.3.2 research) names "log, support
bundle, error text" as the cell's verb surface and records the redactor's secret vocabulary; it does not
name these two members. Searched both ledgers for `config-summary`, `config_summary`, `db_error`,
`support bundle exception`.

---

## Proposal 5. Anonymizer: an opt-in `require_full_coverage`, and surface the coverage report on the clean path

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-05), by execution.
> `anonymize_checked` raises only on `report.hits`; the unmapped-field coverage report built under #331
> reaches the caller only inside a `LeakError` or through the optional `on_report` hook. The structural
> detectors are, by design, a dashed SSN, a punctuated NANP phone and an `MR`/`MRN`-typed CX. Measured
> at `70063ab55`: a `ZPD` segment carrying a name, an eight-digit DOB and an undashed SSN was emitted
> clean; a name in PV1-3 was emitted; a bare ten-digit phone in NK1-8 was emitted; a dashed SSN in
> GT1-17 was refused. The coverage list also carries PID-1 and PID-8 on every message.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build.
**Severity:** medium. `CLAUDE.md` section 9 says "fail-closed" without qualification and the function's
docstring says it is "how you earn the right to write a dataset". A first adopter with a Z-segment or
a site-specific field would get a clean verdict and no visible report. #331's narrow-detector choice is
not contested; what is missing is a way to make the coverage report binding.

**Fix.** `require_full_coverage: bool = False` on `anonymize_checked` that refuses when any unmapped
field outside a small benign set (set ids, sex, patient class) is present; emit the coverage clause on
the clean path (INFO on the tee CLI); state the real fail-closed scope in `CLAUDE.md` section 9 and
`docs/PHI.md`.

**Duplicate search.** #331 (closed) built the report and the detectors and left the report advisory.
No open item. Searched both ledgers for `unmapped field`, `unmapped_fields`, `require_full_coverage`,
`coverage clause`.

---

## Proposal 6. Bundle and log redactor: add narrow shape passes for FHIR JSON, DICOM tag dumps and XML

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-06), by execution.
> `support/redact.py` delegates PHI to `messagefoundry/redaction.py`, whose passes are HL7 segment,
> HL7 field run, date run and multi-token name run. Measured at `70063ab55` with synthetic values: FHIR
> JSON (`"family"`/`"given"` split into single quoted tokens, an identifier value) leaked the given name
> and the MRN; a DICOM `PatientName=...^... PatientID=...` line leaked both; XML leaked the MRN; a bare
> `MRN <digits>` in prose leaked. HL7 was clean and X12 over-redacted (the safe direction).

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build.
**Severity:** medium. The engine is documented payload-agnostic, the DICOM and FHIR transports raise
with peer-supplied text, and the bundle and `GET /logs/tail` are the two artefacts designed to leave the
box. `redaction.py` declares a single-token residual; structured payloads produce single tokens by
construction, so the residual is the ordinary case for three of the four non-HL7 formats. The primary
control (never log a body) still stands.

**Fix.** Label-anchored passes in the shared redactor: JSON keys from a small PHI vocabulary (`family`,
`given`, `name`, `birthDate`, `identifier` values, `telecom`, `address`), DICOM `(0010,00xx)` tag values
and `PatientName=`/`PatientID=` labels, and XML elements with the same vocabulary. One fixture per shape
with a positive control, in the pattern `tests/test_log_redaction_secret_domain.py` already uses.

**Duplicate search.** No open or closed item. Searched both ledgers for `redact FHIR`, `redact X12`,
`redact DICOM`, `non-HL7 redact`, `redactor JSON`.

---

## Proposal 7. Tray: the poll thread dies on the first exception from `poll_once`, freezing the icon with no signal

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-07), by execution.
> `messagefoundry/tray/poller.py` `_run` guards only the `on_update` callback; `poll_once` runs outside
> the `try`. Measured at `70063ab55`: a `scm_reader` injected to raise `OSError` on its second call left
> the poll thread dead after one update, with the only output on the thread's stderr excepthook, which
> under `pythonw` goes nowhere.

**Cluster:** Ops & Deployment. **Priority:** P3. **Verdict:** build.
**Severity:** low. June's "no long-lived task survived its first unexpected exception" shape in
miniature. The readers are documented never to raise and in practice only a `ctypes` load failure
would; the guard costs one `try`.

**Fix.** Wrap `poll_once` in the supervisory `try`, `log.exception`, publish an `UNKNOWN` snapshot. A
poller test that injects a raising reader and asserts the thread survives and a later tick recovers.

**Duplicate search.** No open or closed item. Searched both ledgers for `poll thread`, `poll_once`,
`mefor-tray-poller`, `poller exception`.

---

## Proposal 8. `verify host.console` names a retired console and a missing extra; `host.noflash` greps a source-text token

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-08).
> `messagefoundry/verify/checks.py` `check_console_importable` reports `PySide6` presence as "Console
> importable" and, when absent, "install the [console] extra". `pyproject.toml` has no `console`
> extra; the PySide6 operator console was retired (#103, ADR 0088) and the operator console is the web
> console at `/ui`. `check_console_no_window` reads `messagefoundry/service.py` as text and passes on
> the substring `CREATE_NO_WINDOW`, which the file's comment satisfies on its own.

**Cluster:** Ops & Deployment. **Priority:** P3. **Verdict:** build.
**Severity:** low. Both rows are MANUAL or SKIP so the exit code is unaffected; a deploying operator
following the row would look for an extra that does not exist.

**Fix.** Delete `host.console` or re-point it at the web console (in live mode, probe `/ui` the way
`tray/probe.py` does). For `host.noflash`, import `messagefoundry.service` and check `_NO_WINDOW != 0`
on win32 instead of grepping source.

**Duplicate search.** No open or closed item. Searched both ledgers for `host.console`, `[console]
extra`, `check_console_importable`, `host.noflash`.

---

## Proposal 9. `verify smoke.disposition` does not know `NOT_DEPLOYED`

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-09), by reading.
> `store/store.py` `MessageStatus` carries `NOT_DEPLOYED` (#233). `verify/smoke.py`
> `check_smoke_disposition`'s terminal set and `_classify_disposition`'s dead-letter set both omit it,
> so a live smoke whose destinations are all `deployed=False` would poll for the full timeout and then
> FAIL with "did not reach a terminal disposition" when it had.

**Cluster:** Ops & Deployment. **Priority:** P3. **Verdict:** build.
**Severity:** low. Right verdict, wrong reason, fifteen seconds late.

**Fix.** Add `NOT_DEPLOYED` to both sets with its own FAIL text; one `_classify_disposition` case.

**Duplicate search.** No open or closed item. Searched both ledgers for `NOT_DEPLOYED verify`,
`smoke.disposition`, `check_smoke_disposition`.

---

## Proposal 10. Tray `classify_health` accepts any 200 JSON object with a `status` key as the engine

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-10), by reading.
> `messagefoundry/tray/probe.py` `classify_health` returns `OK` for a 200 whose body is a dict with a
> `status` key. The tokenless `/health` body is `status`, `version` (null) and `observed_client` (null)
> because ASVS 13.4.6 withholds the version from an unauthenticated caller, so the engine gives the
> tray nothing distinctive by design. `{"status":"ok"}` is the commonest health body in the industry,
> so `FOREIGN` ("Port in use by another program") is reachable only for non-JSON responders.

**Cluster:** Ops & Deployment. **Priority:** P3. **Verdict:** build.
**Severity:** low. Cosmetic; the tray is a status hint.

**Fix.** Key on the exact tokenless key set (`status`, `version`, `observed_client`), and say in
`tray/state.py` that `FOREIGN` is best-effort.

**Duplicate search.** No open or closed item. Searched both ledgers for `classify_health`, `foreign
health`.

---

## Proposal 11. Test fixtures that certify through the wrong control: the bundle suite's `MEFOR_*` fixtures, the tray's import layering, and the rules file's wheel claim

> Filed 2026-09-12 - not started. Found by Fable review packet 14 (finding P14-11), by negative
> control. With `_MEFOR_SECRET` in `support/redact.py` replaced by a never-matching pattern,
> `tests/test_support_bundle.py::test_redact_mefor_secret_keeps_name` and
> `test_log_tail_redacted_no_phi_no_secret` stayed green: their fixtures are pure-alphanumeric and 24
> or more characters, which `_LONG_B64` sweeps regardless (the #1183 shape the module docstring warns
> about); only the secret-domain family test went red. Separately, nothing pins the tray's import
> layering (`tests/test_dependency_boundaries.py` has no `tray` rule; `test_tray_boundary.py` pins the
> render model only), and `tests/test_semgrep_handler_rules.py::test_rules_file_ships_in_the_package`
> resolves the rules file through the source tree in an editable install rather than a built wheel.

**Cluster:** Quality & Testing. **Priority:** P3. **Verdict:** build.
**Severity:** low. The live controls exist elsewhere in each case; these are tests that would stay
green through a regression they name.

**Fix.** Hyphenated fixtures under 24 characters in the bundle suite; a fresh-interpreter import
assertion for `tray/` in the pattern of `test_verify_does_not_import_the_generators`; and either a
built-wheel content check for the rules file or a comment pointing at `integrity.py`'s runtime
attestation as the real control (packet 13 owns the wheel question).

**Duplicate search.** #1183 (closed) is the earlier instance of the backstop-satisfied fixture and was
fixed for the bearer case. No open item. Searched both ledgers for `_LONG_B64`, `backstop`, `tray
boundary`, `dependency boundary tray`, `rules file wheel`.

---

## Findings deliberately not filed

- **P14-12 (documentation claims the code contradicts)** is handed to packet 18 by name in the findings
  document: `support/__init__.py` "stdlib only", `anon/__init__.py` "byte-identical", `VERIFY.md` lines
  15 and 67, `CLAUDE.md` section 9 "fail-closed", closed #331's residual note.
- **The `_DSN_PASSWORD` quadratic scan** documented in `support/redact.py` lines 108-114 is handed to
  packet 16 (bounded resources); no open item names it, and that packet files it or decides it is not
  a defect.
- **`dry_run` reporting `filtered` for a `deployed=False` outbound** where the engine records
  `NOT_DEPLOYED`, and `select_inbound`'s empty-registry message, are handed to packet 11 (dry-run).
- **The package root loading `config` into every importer, including the tray**, is packet 1's P1-03
  and is recorded there.
- Everything in the findings document's part 7 (refuted and deprioritized).
