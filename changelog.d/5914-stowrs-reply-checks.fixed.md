- **A DICOMweb STOW-RS 2xx reply that does not parse, or a 202 that names no stored instance, is no
  longer recorded as delivered.** Each is a permanent refusal (`unparseable-reply`,
  `unconfirmed-202`), and a malformed FailedSOPSequence is `unparseable-reply`, since it proves no
  rejection. Not every 2xx that fails to confirm the store is refused: an empty 200, or one of only
  JSON whitespace after a leading BOM, is still delivered, and so is a 200 dataset that
  confirms nothing unless one of those rules refuses it. The rule in full is docs/CONNECTIONS.md
  *DICOMweb*, *Status classification*. The refusal text names no reply content. (`BACKLOG #5914`)
