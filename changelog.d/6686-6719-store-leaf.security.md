- **A `.mfbak` header is accepted only in the exact form the writer emits.** The frames' tag
  covers that form, so a header re-spelled with the same fields, an extra key or a coerced value
  is now refused rather than decrypted. (`BACKLOG #6686`)
- A reference value json refuses with a `TypeError`, `ValueError` or `RecursionError` is refused
  with a new `TypeError` that carries no json notes, which could name a reference key, no cause or
  context, and no text from a foreign error. Any other exception propagates as raised.
  (`BACKLOG #6711`)
