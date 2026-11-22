# HAPI HL7v2 sample messages

A small, type-diverse set of HL7 v2.x messages vendored from the **HAPI HL7v2** project's
test fixtures, for exercising MessageFoundry parsing/routing (e.g. feeding through MLLP with
[`samples/send_mllp.py`](../../send_mllp.py)).

`send_mllp.py` sends a whole file as ONE frame, and a listener refuses a frame holding more than
one MSH. So only the one-message files below can be sent with it. `oml_o21.hl7` holds 13
messages: drop it in a `File(...)` inbox instead, which splits a file into one message each.
`batch_18_messages.txt` also carries `//` and `/* */` comment lines, which that splitter keeps:
the leading comment block becomes an `ERROR` record of its own, and a comment line after a
message rides along at its end. Strip the comment lines first.

## Provenance

- **Source:** https://github.com/hapifhir/hapi-hl7v2
- **Commit:** `de1503651040` (`master`)
- **License:** Mozilla Public License 2.0 (MPL-2.0). These are external test *inputs*, not
  source linked into the engine — using them to drive tests is unaffected by the license.
  If any file is ever modified, MPL-2.0 requires that file to carry its source notice.

All files except `batch_18_messages.txt`, `oml_o21.hl7` and `adt_a03.txt` are copied **verbatim** (bytes
unchanged) from the upstream paths below; the `hapi-osgi-test` tree carries byte-identical
duplicates of several of these and was skipped.

All three modified files were scrubbed with the project's own de-identification framework
([`messagefoundry_toolkit/anon/`](../../../messagefoundry_toolkit/anon/), ADR 0030), the same
deterministic, salt-keyed surrogate machinery the tee relay and test harness use, over
`DEFAULT_RULES` plus a committed rule overlay for each file. **No ad-hoc redaction logic was
written** (§9: centralize the rules, don't reimplement beside the framework). Each overlay scrubs
the fields this corpus needs that are not defaults, and lists every other field the leak-check
walks as reviewed and kept, so no field it walks is undecided. The leak-check does not walk the
MSH header, so no MSH field is in a keep list. Only `adt_a03.txt`'s overlay scrubs MSH fields.
[`tests/test_anon_hapi_samples.py`](../../../tests/test_anon_hapi_samples.py) holds each file to its
overlay. The salt is not recorded: these surrogates are final, not reversible, and the files are
not intended to be re-derived. Line endings, segment order and every line's field count are
unchanged.

**What the scrub does not replace.** A run of `DEFAULT_RULES` is not Safe Harbor
de-identification, and ADR 0030 and [`docs/PHI.md`](../../../docs/PHI.md) §9 say why. In these files,
at least: `MSH-7` and the other MSH routing fields keep their upstream values, except `MSH-4`,
`MSH-6` and `MSH-7` in `adt_a03.txt`; a query time, an
order's requested time in `batch_18_messages.txt` and an order's quantity and timing keep their
timestamps, an identifier keeps its assigning authority (a hospital or system name), and the coded
clinical content is kept.

### `batch_18_messages.txt` is MODIFIED — de-identified, not verbatim

> **Source notice (MPL-2.0 §3.3).** This file is a **modified** copy of
> `hapi-test/.../ca/uhn/hl7v2/util/messages.txt` from
> https://github.com/hapifhir/hapi-hl7v2 at commit `de1503651040`, licensed MPL-2.0.
> The modification is de-identification only, described below.

Upstream this file carries patient demographics — names, dates of birth, street addresses,
telephone numbers, medical-record numbers and valid-format SSNs — whose internal consistency
(SSN area numbers agreeing with state of residence, real locality phone prefixes, named
institutions) is not what a placeholder generator produces. Whatever its true provenance,
shipping it unchanged is incompatible with this project's synthetic-data-only rule
([`CLAUDE.md`](../../../CLAUDE.md) §9).

**How.** It was scrubbed twice. The first pass used `DEFAULT_RULES` plus a hand-written overlay
that was never committed. It left identifiers behind: `PID-2`, the order and accession numbers,
the operator ids in `ORC-10/11`, the query id, subject and qualifier in `QRD-4/8/11`, the insurance
group fields `IN1-8/9/10`, and the locations and dates the default map gained only later
(BACKLOG #5557).
So the whole file was scrubbed again, over every message, by `DEFAULT_RULES` plus
[`tests/fixtures/anon/batch_18.anon.toml`](../../../tests/fixtures/anon/batch_18.anon.toml), which
says why each of its fields is not a default.

**What was deliberately preserved**, because it is what the corpus is *for*: 18 messages, 133
lines, every segment in its original order with unchanged field counts, CRLF line endings, the
`//` and `/* */` comments, the `~~` repetitions, the OBX narrative text, the
`ORU`/`BAR`/`ACK`/`ORM`/`QRY` mix and the HL7 2.1 to 2.4 version spread. Both unusual MSH-2
encoding sequences survive intact, including the 3-character `MSH|^~}|` that no conformant parser
accepts. It is a tolerant-parsing test case, and the anonymizer (correctly) refuses such a
message, so MSH-2 was repaired for the scrub and the malformation restored afterward.

**What the scrub changed beyond identifier values**, at least:

- A scrubbed date keeps only its year. A date of birth is drawn at random, so some now fall after
  the message that carries them.
- An empty placeholder such as `^^` in a field a rule scrubs now holds a surrogate: a fabricated id
  in an identifier field, or `[REDACTED]` in a location field. A surrogate is keyed on the value,
  so every patient whose `PID-2` was `^^` now shares one fabricated id, and two placer numbers
  that were empty share one too.
- The `""` null in `PID-12` became `[REDACTED]`.
- An identifier's check digit, and a namespace written in its second component, are blanked.
- Clinicians are drawn from a small pool, so two upstream clinicians can share one surrogate.

Routing fields (MSH, message type, trigger, version) are untouched, so routing behaves exactly as
before. Do not use this corpus to test patient matching, ages or clinician identity.

### `oml_o21.hl7` is MODIFIED — de-identified, not verbatim

> **Source notice (MPL-2.0 §3.3).** This file is a **modified** copy of
> `hapi-test/.../ca/uhn/hl7v2/parser/example_oml_o21.hl7` from
> https://github.com/hapifhir/hapi-hl7v2 at commit `de1503651040`, licensed MPL-2.0.
> The modification is de-identification only, described below.

Upstream this file carries the names of patients, of the staff who ordered, collected and
interpreted, and of an insurer, across 13 messages (BACKLOG #5558). Most are placeholders, but
not all of them plainly are, so it was scrubbed, by `DEFAULT_RULES` plus
[`tests/fixtures/anon/oml_o21.anon.toml`](../../../tests/fixtures/anon/oml_o21.anon.toml).

**What was deliberately preserved:** the 13 messages, the bare-CR segment endings and the empty
lines between messages, the OML/OUL/ORL/ORU mix, the numeric results, and the order, group and
specimen numbers, which upstream invented as placeholder runs and which tie each ORC to its OBR
and SPM. The department names and the patients' assigning authorities are kept too. The same
limits as above apply. In addition, the default `OBR-32` rule writes a clinician's id, family and
given name over the interpreter field, so in two messages its start time is gone and its second
component holds a surname.

The parser parity record, `tests/golden/python_hl7_oracle.json`, still holds this file's upstream
bytes as its own frozen input, the upstream names included. Nothing can regenerate that record
(ADR 0054), so this scrub does not reach it, and those names are still in the repository there.

### `adt_a03.txt` is MODIFIED — de-identified, not verbatim

> **Source notice (MPL-2.0 §3.3).** This file is a **modified** copy of
> `hapi-test/.../ca/uhn/hl7v2/parser/adt_a03.txt` from
> https://github.com/hapifhir/hapi-hl7v2 at commit `de1503651040`, licensed MPL-2.0.
> The modification is de-identification only, described below.

Upstream this one-message file carries a named hospital and ward and a patient key. It also
carries an identifier shaped like an Italian fiscal code, a birth date, a visit number and two
clinicians (BACKLOG #5825). The names are placeholders, but the hospital, ward and identifiers are
not plainly so. So it was scrubbed, by `DEFAULT_RULES` plus
[`tests/fixtures/anon/adt_a03.anon.toml`](../../../tests/fixtures/anon/adt_a03.anon.toml), which
also scrubs the message time and the sending and receiving facility in the MSH header and says why.

**What was deliberately preserved:** the five segments in order, their field counts, and the CRLF
line endings with no final line ending. In the header, the sending and receiving applications, the
message type, the control id and the version are kept. So are the identifiers' assigning
authorities and type codes, and the coded procedure. The same limits as above apply.

**What the scrub changed beyond identifier values**, at least:

- The facility in `MSH-4` and `MSH-6`, and the hospital and ward in `PV1-3` and `PV1-6`, are now
  `[REDACTED]`.
- The message, event, discharge and procedure dates keep only their year; the birth date is drawn
  at random.
- The fiscal-code and SSN repetitions of `PID-3` held one upstream value and now hold two
  different surrogates, and the effective and expiration dates of the SSN repetition are blanked.
- The patient name gained a middle initial, and the clinicians are drawn from the surrogate pool.

The name, sex, birth date and procedure no longer need agree with one another. Do not use this
sample to test patient matching, ages, sex or clinician identity.

## Manifest

| File | Type (MSH-9) | HL7 ver | Msgs | Upstream path |
|------|--------------|---------|-----:|---------------|
| `adt_a01.txt` | ADT^A01^ADT_A01 | 2.4 | 1 | `src/docs/examples/ADT_A01.txt` |
| `adt_a03.txt` | ADT^A03 | 2.5 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/adt_a03.txt` |
| `omd_o03.txt` | OMD^O03^OMD_O03 | 2.5 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/omd_o03.txt` |
| `omd_o03_rep.txt` | OMD^O03^OMD_O03 | 2.5 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/omd_o03_rep.txt` |
| `oml_o21.hl7` | mixed (see below) | 2.5, 2.5.1 | 13 | `hapi-test/.../ca/uhn/hl7v2/parser/example_oml_o21.hl7` |
| `erp_z99_v231.hl7` | ERP^Z99^ERP_R09 (Z-event) | 2.3.1 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/cv.04_001_chem.hl7` |
| `batch_18_messages.txt` | mixed (see below) | 2.1 to 2.4 | 18 | `hapi-test/.../ca/uhn/hl7v2/util/messages.txt` |

`batch_18_messages.txt` is **18 concatenated messages** (no FHS/BHS batch wrapper): 1 ORU^R01,
11 BAR^P01, 1 ACK, 3 ORM^O01, 2 QRY^Q01 — a useful mix of versions (2.1/2.2/2.4) for testing a
splitter and tolerant parsing.

`oml_o21.hl7` is **13 concatenated messages**, separated by empty lines (no FHS/BHS batch
wrapper): 7 OML^O21, 4 OUL^R22, 1 ORL^O34 and 1 ORU^R01, in HL7 2.5 and 2.5.1.

Across the set: **36 messages** covering ADT, OMD, OML, OUL, ORL, ORU, BAR, ACK, ORM, QRY and a
custom Z-event, HL7 versions **2.1 to 2.5.1**.

> Note: HAPI's larger message corpus lives as inline strings inside its Java test sources, not
> as standalone files; only the files above ship as discrete messages. XML-encoded HL7 messages
> in the repo were excluded (MessageFoundry's hot path is pipe-delimited python-hl7).
