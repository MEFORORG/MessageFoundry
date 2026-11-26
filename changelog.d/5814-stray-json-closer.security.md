- **`redact` reads a stray JSON closer on the text as received, and on its own result.** A
  field-run scrub could consume an opener so a later closer looked matched to the JSON walk, and a
  stray closer of the same kind as an open array ended a PHI-keyed value early, so a single-token
  value after it was kept. Where a closer after a PHI key meets an open container of another kind
  while that key's scope is open, the text is now the placeholder, followed by any trailing bound
  note. **Known cost, in the safe direction:** the check is not scoped to the PHI value, so such a
  closer anywhere in the key's scope, as in a malformed sibling or in prose after the key, blanks
  a text that used to keep everything but the value. The docstring of `_stray_json_closer`, in
  [messagefoundry/redaction.py](../messagefoundry/redaction.py), states how far a key's scope runs
  and at least the shapes the check misses.
  (vault `BACKLOG #5814`)
