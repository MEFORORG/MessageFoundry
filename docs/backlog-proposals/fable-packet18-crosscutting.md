# Proposed backlog items from Fable review packet 18 (cross-cutting passes)

**Propose-only. No number is allocated here and `docs/BACKLOG.md` is untouched** (owner instruction
2026-09-12: the Manager allocates serially after the packets land). Each proposal is in the house
format minus the heading number. The reproduction for every finding is in the vaulted
`docs/reviews/FABLE-PACKET-18-CROSSCUTTING-2026-09-11-FINDINGS.md`; this file names subject, mechanism
and fix without pasting a reproduction.

Duplicate search ran over `docs/BACKLOG.md` and `docs/archive/backlog/BACKLOG-CLOSED.md` at
`fa7bc9e3e` (grep by symptom, path and symbol, then `parse_items` over every heading for status) and
over the bodies of the 30 open pull requests, including the five that file other packets' items
(1064, 1066, 1069, 1070, 1071) and packet 5's proposals PR (1072).

---

## Proposal 1. Controls across the engine report success without exercising what they name; admit every invariant test with its red, make zero a non-OK outcome, test every stated premise, and score instruments by exit code

**Filed - not started.** Six review packets measured thirteen controls that report success through a
regression, in three kinds. Tests that cannot fail: the runner's ACK-after-commit (140 tests green
with the ACK returned before the commit), both Postgres locks and the SQL Server finalize lock, seven
audit writes, four store-level guarantees on the shipped inline path, a follower gate whose failure
signal the code swallows, a Windows config-source test that asserts a stub it installed. Gates that
pass on nothing: `audit-verify` on a zero-byte file, the `check` dryrun gate with zero deployed
inbounds, an empty config directory through `serve`, `validate` and `check`, the dependency-boundary
test with five package names that do not exist, the refused-config-key ratchet reading a document that
names a refused key twice as being at zero. Controls whose stated premise is false: the `db_lookup`
read-only gate finding a `;` that T-SQL does not need, the unsafe-db-lookup lint reading only the
call's own argument, the SQL Server audit lock's "single writer per process" under the built sharding
topology, ADR 0159's "no next borrower" on SQLite, and a `record_audit` comment contradicted by
`_ensure_schema` in the same file. The pattern reached four reviewers' own instruments.

**Cluster:** Quality record / test quality. **Priority:** P1. **Verdict:** build.
**Severity:** conditional (section 0). High: a first deployment would carry the reliability invariant,
both server-store locks, the audit chain's cross-process integrity, the read-only lookup carve-out,
the dependency boundary and the audit-verify compliance job, each behind a control that would report
success through a regression. No instance is a live defect alone; the class is that a regression in
any of them ships green.

**Why one item.** Every instance shares a generative rule: a control is admitted on what it is called,
and nothing asks what it would take for it to report success while doing nothing. BACKLOG #1092
(closed 2026-08-10) named that rule and corrected the quality record's claims; the pattern then
recurred thirteen times in five weeks in the controls themselves, so the record was not where the fix
belonged.

**The fix, as a class.** (1) A test that pins a named invariant, lock, gate or audit write ships with a
planted-violation sibling in the same file, the shape `test_the_scanner_catches_a_deliberately_bad_line`
already uses. (2) Every verifier or gate that iterates a collection reports its count and treats zero
as `SKIPPED` with a reason or `FAILED`, never `OK`; a lint over `tests/` for `assert not <list>` with no
preceding count assertion. (3) A control's premise is stated beside it and has a test that fails when
the premise is false. (4) Instruments are scored by exit code and `FAILED` lines, never by parsed summary
text, run under `PYTHONSAFEPATH=1`, and print which tree answered. (5) A bounded, checked-in list of
mutations over the named invariant tests that must go red, run nightly, seeded from the thirteen above.
Promote plan section 7's and section 8's rules into `docs/Code_Quality_Standards.md`, and carry Signal
1's grade with the measured scope of its instrument.

**Duplicate search.** Ancestor, not duplicate: #1092 (closed). Related: #1000 (a required check green
over the wrong directory), #1018 (guards that go quiet), #1380 (the mirror, a checker that falsely
accused, retracted in full). The instance items are cited, not absorbed: #1608, #1610, #1605, #1548
(PR 1064), and packets 7, 8, 9, 10's proposals. Searched `cannot fail`, `negative control`, `pass on
nothing`, `verified 0`, `SDS-3.7`, `systemic`, `false premise` in both files and every open PR body.

---

## Proposal 2. The dependency-boundary test passes when its walk finds no files; add a walk floor and a planted-violation guard, and land it with #1596 and #1615

**Filed - not started.** `tests/test_dependency_boundaries.py` walks `_ENGINE_PACKAGES` with
`rglob("*.py")` and asserts an empty violation list. Measured at `fa7bc9e3e`: a planted
`from fastapi import FastAPI` in `transports/base.py` turns it red with the file named (the outward
rule is enforced); the same test with all five package names replaced by names that do not exist
passes in 0.22 s. Nothing asserts the package directories exist, that the walk visited any file, or
that a planted violation is caught; the one guard-the-guard test proves relative imports resolve, not
that a resolved forbidden import is reported.

**Cluster:** Developer Experience & CI. **Priority:** P2. **Verdict:** build.
**Severity:** conditional. Medium: this is the test `Code_Quality_Standards.md` cites for Signal 1
and the one June's low-30 asked for; a package rename, a test relocation, or a checkout whose
`parents[1]` is not the repository would report the boundary clean while checking nothing, and CI
could not tell that green from a real one.

**Fix.** Assert each `root / package` is a directory and the walk visited at least a floor of files
per package; add `test_the_walk_catches_a_planted_violation` over a `tmp_path` tree; in the same PR
take #1615 (add `messagefoundry_webconsole`, and `starlette` and `uvicorn` beside `fastapi`) and #1596
(the inward rule that `parsing/` imports nothing under `messagefoundry` except `parsing`, `timezone`
and `controlchars`), because all three edit the same forty lines.

**Duplicate search.** Two of three halves are filed on open PRs: #1596 (PR 1066, inward rule) and
#1615 (PR 1071, console name). The walk guard is new. Searched `test_dependency_boundaries` (#1092
only, closed), `inward`, `rglob`, `walk` with `boundary`.

---

## Proposal 3. The file sources log a partner-chosen file name at WARNING in twenty places the redaction chain cannot see; add `safe_name` and `safe_exc`

**Filed - not started.** `transports/file.py` has 11 `logger.warning` sites carrying `path.name` and
`transports/remotefile.py` has 9 carrying the remote name, all on quarantine, retry, archive or delete
arms; two of them also log the raw exception where `mllp.py` uses `safe_exc`. The engine's own
`_file_key` docstring (file.py, BACKLOG #142) says a filename "can embed an MRN" and must never be
logged. Measured at `fa7bc9e3e` with all four root filters from `logging_setup` installed: a WARNING
carrying `MRN123456789_ADT.hl7`, `DOE_JANE_19800505_ADT.hl7` or `PID-100001-DOE-JANE.hl7` reaches the
handler verbatim; only a space-separated name with a delimited date is redacted. The name heuristic
needs whitespace and the date heuristic needs delimiters; a filename supplies neither.

**Cluster:** PHI. **Priority:** P2. **Verdict:** build.
**Severity:** conditional. Medium: on a first deployment with a partner that names drops by MRN,
accession or patient name (common), every quarantined or retried file would write that identifier to
the NSSM-captured general log at WARNING, the sink the C-1 fix exists to keep clean, whose directory
ACL (June H-13) is unsettled. No attacker gain; the concern is a benign partner's naming convention.

**Fix.** One `safe_name(path)` helper returning a short hash prefix plus the extension and byte length
(the `_file_key` shape), used at all twenty sites; `safe_exc` at the two raw-exception sites; one test
per source that logs an identifier-shaped name and asserts the captured record carries no long digit
run and no underscore-joined capitalised pair.

**Duplicate search.** No match. Searched `path.name`, `basename`, `_file_key`, `#142`, `file name`
with `log`, `MRN` with `filename`. #1130 and #1238 contain a server-chosen name as a path, not as a
log value. Packet 2's P2-11 and packet 9's P9-11 were handed to packet 18 for this ruling and are not
separately proposed by them.

---

## Proposal 4. The six sequenced operator documents carry a refused config key, a pre-ADR-0172 TLS model, 0.1.0 install pins and a retired console extra; fix them, add a pin-drift test, and widen the refused-key ratchet to the prose shape

**Filed - not started.** `docs/README.md` sequences six documents for a new operator. Measured or
read at `fa7bc9e3e`: `USER-GUIDE.md` tells the operator at two sites (the console section and the
troubleshooting list) that the console is served when `[api].serve_ui` is on, and `load_settings` on
that key refuses it with the ADR 0118 relocation message, while the same document's earlier section
names the right key; `USER-GUIDE.md` gives `http://` console and health URLs and `DEPLOYMENT.md` has no
mention of ADR 0172, describes the API's TLS as two branches and calls the remote-bind refusal a
cleartext refusal, for an engine that mints a self-signed pair unconditionally and always serves TLS;
`INSTALL-GUIDE.md` and `EARLY-ADOPTER-GUIDE.md` pin `messagefoundry==0.1.0` under a caution written
for 0.1.0 while the tree is 0.3.2 (the console pin on the same page is current);
`EARLY-ADOPTER-GUIDE.md` lists a `console` extra for the retired desktop console that the extras table
does not contain. `SYSTEM-REQUIREMENTS.md` and `testing/VERIFY.md` were accurate on every claim
checked. The guard for the refused-key class, `tests/test_docs_cite_no_refused_config_keys.py`, is
green with the USER-GUIDE at an implicit zero because its scanner matches assignment shape only; driven
on the USER-GUIDE's lines it returns nothing.

**Cluster:** Documentation correctness. **Priority:** P2. **Verdict:** build.
**Severity:** no engine effect (section 0). Medium because the cost lands on exactly the reader these
six documents exist for: a first operator following them in order would install a wheel two minor
versions behind, look for an extra that does not exist, browse to a scheme the engine does not serve,
and on the troubleshooting path be told to confirm a key that fails the load.

**Fix.** The named line edits (the exact lines are in the vaulted document, part 4.5); a `docs/`
version-pin drift test comparing every `messagefoundry==` and `messagefoundry-webconsole==` pin in
the six documents against the two `__version__` values, with a planted stale pin as its control; extend
the ratchet's scanner with a prose form (a backticked `[section].key` from `_RELOCATED_TO_SECURITY`
inside an instruction sentence) or hold the six operator documents at zero under a stricter rule; and a
`DEPLOYMENT.md` and `USER-GUIDE.md` pass for ADR 0172, which is the documentation half of packet 10's
P10-06 and should land with it.

**Duplicate search.** Same class as #1383 and #1388 in a different document (both scoped to
`SECURITY.md`; #1383's SECURITY.md half is built). #1263 (file:line citations validated by nothing)
is adjacent. Searched `serve_ui` (21 open hits: ADR 0118 research rows and #1383/#1388), `0.1.0`,
`USER-GUIDE`, `DEPLOYMENT.md` with `0172` (none), `console extra`, `EARLY-ADOPTER`.

---

## Proposal 5. Documentation sweep: eight docstring, comment and document claims that stand at `fa7bc9e3e` and that no proposal carries

**Filed - not started.** Re-read at `fa7bc9e3e` from the flags packets 1 to 10 handed to packet 18,
minus every flag a packet's own proposal or an open PR already carries. The eight: (1) `transports/base.py`
lines 10 to 12 say adding a transport "never touches the channel model" and `config/models.py` line 29
says "Plugins may register additional values", while `ConnectorType` is a closed enum (packet 2's
P2-10). (2) The `record_audit` comment in `store/sqlserver.py` says a transaction-scoped applock taken
as the first statement "does not release on commit and strands", and `_ensure_schema` in the same file
takes exactly that lock first and says it auto-releases; one is wrong and the wrong one steered a
control out of the database (packet 4's P4-06). (3) `docs/PHI.md` section 6 names
`summary_search_display` and `dead_letter_display` as the summary audit actions; the code writes
`summary_access` (packet 7). (4) The `inline` fast-path keyword (`build_inbound_connection`, ADR 0057)
appears in neither `CONNECTIONS.md` nor `CONFIGURATION.md` (packet 8). (5) `messagefoundry/__init__.py`
says "The PySide6 console (and any other client) drives it"; that console was retired (BACKLOG #103;
packet 10). (6) `docs/CONFIGURATION.md` omits `[api].tls_client_crl_file`, the only one of 359
`ServiceSettings` keys not documented (census with a positive and a negative control), and
`docs/SECURITY.md`'s mTLS row says "no revocation checking", a row written 2026-07-23 a month before
#1005 shipped CRL checking on 2026-08-22. (7) `docs/CONNECTIONS.md` documents the SFTP `private_key` as
"PEM private-key text or a path" with no type restriction while `remotefile.py` loads
`paramiko.RSAKey` only, so an Ed25519 or ECDSA key is refused at connect with no document saying so.
(8) `docs/AI.md` states "the MVP assistant only ever sends code, never message bodies" as an engine
guarantee; packet 7 measured it to be a client property (pointer only: #95 is the open item).

**Cluster:** Documentation correctness. **Priority:** P3. **Verdict:** build (small).
**Severity:** no engine effect. Low. Each is a reader believing something the code does not do; the
`record_audit` comment is the one with a code consequence and P4-01's fix needs its measurement anyway.

**Fix.** One documentation PR with each edit named; settle (2) by one measurement recorded beside both
sites.

**Duplicate search.** No match on any of the eight anchors. Searched `Plugins may register`,
`record_audit` with `applock` or `first statement`, `summary_search_display`, `inline` with `fast-path`
or `0057`, `PySide6 console` (5 open hits, all the retired-console history), `tls_client_crl_file`
(none; #1005 closed is the code), `RSAKey` and `Ed25519` (#1168, an unrelated PKCS#1 item), `only ever
sends code` (#95 open, cited).

---

## Findings deliberately not proposed

- **P10-01** (the dryrun `error` field): packet 10's item 1 carries it; packet 18's PHI ruling upholds it
  at Medium.
- **Every flag already filed or proposed elsewhere:** P1-09 (#1602), P3-07 (#1611), P3-09 (#1615),
  P5's ADR 0159 scoping (#1548's fix), P2-02 and P2-07 docstrings (packet 2), P4-03 (packet 4), P6's two
  `SECURITY.md` sentences (packet 6), P7's `PHI.md` NULL-client sentence (packet 7 B-5), P8-08's
  rationale (packet 8 H), P9's egress line and gate docstring (packet 9 B3, B2), P10-01's comment
  (packet 10 item 1), P10-06's flag text (packet 10 item 6).
- **The cross-packet duplicates**, for the Manager to merge at allocation rather than for this packet to
  re-file: packet 5's proposal 1 duplicates #1548 on PR 1064; packet 8's item B and packet 10's item 5
  are one item; #1596, #1615 and proposal 2 above edit one test; packet 1's #1596 and packet 10's item
  9 are the two halves of P1-03; packet 9's B2 and packet 10's item 12 are one defect in two files;
  packet 6's P6-01 (the review's one inherited High still standing) has no PR carrying it.
- Everything in the vaulted document's part 7 (refuted and deprioritized).
