- **A DICOMweb STOW-RS 2xx reply that does not parse, or a 202 that names no stored instance, is no
  longer recorded as delivered.** Each is a permanent refusal (`unparseable-reply`,
  `unconfirmed-202`), and a malformed FailedSOPSequence is `failed-sop`. Not every 2xx that fails to
  confirm the store is refused: an empty 200, and a 200 dataset that confirms nothing, are still
  delivered. The rule in full is docs/CONNECTIONS.md *DICOMweb*, *Status classification*. The
  refusal text names no reply content. (`BACKLOG #5914`)
