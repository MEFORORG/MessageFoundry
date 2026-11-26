- **`redact` can return the placeholder for a whole text that holds a mismatched or stray JSON
  closer after a PHI JSON key.** A field-run scrub could consume an opener so a later closer looked
  matched to the JSON walk, and a stray closer of the same kind as an open array ended a PHI-keyed
  value early, so a single-token value after it was kept. Such a text can now be returned as the
  placeholder, followed by any trailing bound note. Text shaped like a PHI JSON key can do it too,
  including text inside a JSON string. **Known cost, in the safe direction:** this can blank text
  beyond the key's value, including some balanced inputs. The check is a heuristic walk and misses
  some shapes. For the exact behaviour, read the code from `_redact_noted` in
  [messagefoundry/redaction.py](../messagefoundry/redaction.py); the `KNOWN_COST` and `MISSED`
  lists in `tests/test_b5814_stray_closer_before_flat_passes.py` pin examples, neither of them a
  complete list.
  (vault `BACKLOG #5814`)
