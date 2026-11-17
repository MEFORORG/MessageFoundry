- **A `.mfbak` header is accepted only in the exact form the writer emits.** The frames' tag
  covers that form, so a header re-spelled with the same fields, an extra key or a coerced value
  is now refused rather than decrypted. (`BACKLOG #6686`)
- A reference value json refuses as unencodable is refused with an error that carries no json
  notes, which could name a reference key, and no text from a foreign error. (`BACKLOG #6711`)
