- **A DICOMweb STOW-RS 2xx reply that does not confirm the store is no longer recorded as
  delivered.** A reply body that is not parseable dicom+json, repeats a key, or is nested too deep
  is a permanent refusal (`unparseable-reply`), and so is a 202 that names no stored instance in a
  ReferencedSOPSequence, an empty 202 included (`unconfirmed-202`). An empty 200 is still
  delivered. The refusal text names no reply content. (`BACKLOG #5914`)
