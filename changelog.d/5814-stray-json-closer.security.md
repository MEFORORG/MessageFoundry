- **`redact` reads a stray JSON closer on the text as received, and on its own result.** A
  field-run scrub could consume an opener so a later closer looked matched to the JSON walk, and a
  stray closer of the same kind as the open container ended a PHI-keyed value early, so a
  single-token value after it was kept. Such a text is now the placeholder alone, as a mismatched
  closer already was. A closer inside a string, in prose before the first PHI key, or after that
  key's container closed is read as before. (vault `BACKLOG #5814`)
