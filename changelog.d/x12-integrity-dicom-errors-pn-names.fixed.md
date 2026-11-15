- **X12 `check_integrity` reports more envelope breaks.** Besides the control-number pairs and
  counts, it now also reports an `SE` with no open `ST`, a `GE` with no open `GS`, and an `ST`
  outside any `GS`. Those interchanges used to tie out with no problems. (`BACKLOG #5808`)
- **More malformed DICOM objects dead-letter as a `DicomError`.** The DICOM parse-error tuple now
  covers `zlib.error`, `ArithmeticError` and `LookupError`. A Deflated Explicit VR Little Endian
  object with a corrupt body used to raise `zlib.error` straight out of `DicomPeek.parse` and
  `DicomDataset.parse`. (`BACKLOG #5803`)
- **`person_name_components` and `pid_from_dataset` write PID-5 in XPN order.** The DICOM name
  prefix now goes to XPN-5 and the suffix to XPN-4; they were swapped. A name is cut to its five
  DICOM components, and a blank (spaces-only) component is written empty. When the alphabetic
  group has no family, given or middle name, an ideographic or phonetic group is used and marked
  `I` or `P` in XPN-8; such a name used to come back empty. This helper sets no character set, so
  a Handler sending a non-ASCII name must declare it in MSH-18 and match the outbound connection's
  `encoding`. (`BACKLOG #5804`)
