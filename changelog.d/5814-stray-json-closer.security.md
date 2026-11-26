- **`redact` reads a stray JSON closer on the text as received, and on its own result.** A
  field-run scrub could consume an opener so a later closer looked matched to the JSON walk, and a
  stray closer of the same kind as an open array ended a PHI-keyed value early, so a single-token
  value after it was kept. Where a closer after a PHI key meets a container of another kind before
  that key's container closes, the text is now the placeholder alone, as a mismatched closer
  already was, with any trailing bound note kept. Read on the result too, so a text whose flat pass
  consumed an opener after a PHI key now ships as the placeholder where it used to keep its other
  fields. **Known cost, in the safe direction:** the check is not scoped to the PHI value, so a
  mismatched closer anywhere in the key's scope blanks a text that used to keep everything but the
  value. That includes at least one in a malformed sibling after a PHI value, one in prose after a
  top-level key on its line, and one on a later line of a traceback that leaves a PHI-keyed dict
  unclosed. The docstring of `_stray_json_closer` says how far a key's scope runs. The check still
  misses at least a closer with no open container, a stray closer of the key's own container's
  kind, and one inside a string, whether it opened before the key or in the value; that docstring
  lists them. (vault `BACKLOG #5814`)
