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

Files are copied **verbatim** (bytes unchanged) from the upstream paths below; the
`hapi-osgi-test` tree carries byte-identical duplicates of several of these and was skipped.

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
