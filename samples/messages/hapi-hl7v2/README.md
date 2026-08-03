# HAPI HL7v2 sample messages

A small, type-diverse set of HL7 v2.x messages vendored from the **HAPI HL7v2** project's
test fixtures, for exercising MessageFoundry parsing/routing (e.g. feeding through MLLP with
[`samples/send_mllp.py`](../../send_mllp.py)).

## Provenance

- **Source:** https://github.com/hapifhir/hapi-hl7v2
- **Commit:** `de1503651040` (`master`)
- **License:** Mozilla Public License 2.0 (MPL-2.0). These are external test *inputs*, not
  source linked into the engine — using them to drive tests is unaffected by the license.
  If any file is ever modified, MPL-2.0 requires that file to carry its source notice.

All files except `batch_18_messages.txt` are copied **verbatim** (bytes unchanged) from the
upstream paths below; the `hapi-osgi-test` tree carries byte-identical duplicates of several of
these and was skipped.

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
([`CLAUDE.md`](../../../CLAUDE.md) §9), so every identifier was replaced.

**How.** Scrubbed with the project's own de-identification framework
([`messagefoundry/anon/`](../../../messagefoundry/anon/), ADR 0030) — the same deterministic,
salt-keyed surrogate machinery the tee relay and test harness use — over `DEFAULT_RULES` plus a
rule overlay for the fields this corpus uses that the default map does not cover: `GT1-8/16/17/18`,
`IN1-4/5/6/7/11/18/44`, `OBR-35`, and the non-standard `DST` segment (`DST-2/7/9/27/35`), which
mirrors `IN1` at a shifted offset. **No ad-hoc redaction logic was written** (§9: centralize the
rules, don't reimplement beside the framework). The salt is not recorded — these surrogates are
final, not reversible, and the file is not intended to be re-derived.

**What was deliberately preserved**, because it is what the corpus is *for* — 18 messages, 133
lines, every segment in its original order with unchanged field counts, CRLF line endings, the
`//` and `/* */` comments, `""` null markers, `~~` repetitions, the OBX narrative text, the
`ORU`/`BAR`/`ACK`/`ORM`/`QRY` mix and the HL7 2.1–2.4 version spread. Both unusual MSH-2 encoding
sequences survive intact, including the 3-character `MSH|^~}|` that no conformant parser accepts
— it is a tolerant-parsing test case, and the anonymizer (correctly) refuses such a message, so
MSH-2 was repaired for the scrub and the malformation restored afterward.

Routing/coded fields are untouched, so message type, trigger and version-based routing behave
exactly as before. Only identifier *values* changed.

## Manifest

| File | Type (MSH-9) | HL7 ver | Msgs | Upstream path |
|------|--------------|---------|-----:|---------------|
| `adt_a01.txt` | ADT^A01^ADT_A01 | 2.4 | 1 | `src/docs/examples/ADT_A01.txt` |
| `adt_a03.txt` | ADT^A03 | 2.5 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/adt_a03.txt` |
| `omd_o03.txt` | OMD^O03^OMD_O03 | 2.5 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/omd_o03.txt` |
| `omd_o03_rep.txt` | OMD^O03^OMD_O03 | 2.5 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/omd_o03_rep.txt` |
| `oml_o21.hl7` | OML^O21^OML_O21 | 2.5.1 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/example_oml_o21.hl7` |
| `erp_z99_v231.hl7` | ERP^Z99^ERP_R09 (Z-event) | 2.3.1 | 1 | `hapi-test/.../ca/uhn/hl7v2/parser/cv.04_001_chem.hl7` |
| `batch_18_messages.txt` | mixed (see below) | 2.1–2.4 | 18 | `hapi-test/.../ca/uhn/hl7v2/util/messages.txt` |

`batch_18_messages.txt` is **18 concatenated messages** (no FHS/BHS batch wrapper): 1×ORU^R01,
10×BAR^P01, 1×ACK, 3×ORM^O01, 2×QRY^Q01 — a useful mix of versions (2.1/2.2/2.4) for testing a
splitter and tolerant parsing.

Across the set: **24 messages** covering ADT, OMD, OML, ORU, BAR, ACK, ORM, QRY and a custom
Z-event, HL7 versions **2.1 → 2.5.1**.

> Note: HAPI's larger message corpus lives as inline strings inside its Java test sources, not
> as standalone files; only the files above ship as discrete messages. XML-encoded HL7 messages
> in the repo were excluded (MessageFoundry's hot path is pipe-delimited python-hl7).
