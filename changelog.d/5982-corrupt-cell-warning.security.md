- **A queue row refused at its queue tag no longer carries the cipher's refusal text.** This
  covers a cell sealed for another row, and a corrupt cell, for example bad base64 or a
  ciphertext too short for a tag, under any cipher. The error raised for it names the cipher
  error's class and its cause, and is raised with no cause or context. So no record of that error
  carries the cipher's text: not a claim's WARNING, not uvicorn's ERROR traceback for a read the
  API does not handle, and not a dead-lettered row's `last_error` or `dead` event detail. The
  refusal is handled as before: a claim dead-letters, audits and alerts it, and a read is refused
  and alerted. A claim's dead-letter WARNING names a queue-tag refusal by its class and cause, and
  any other error by its class. What is lost is diagnostic: which way a corrupt cell is corrupt,
  and under Vault Transit the key service's own refusal text, are no longer in the error, its
  WARNING or the dead-lettered row. Known
  limits, at least: a cell under a key the store does not hold, or with a marker this build cannot
  parse, is a plain cipher error rather than a queue-tag refusal. Its text, which can echo a field
  cut from the stored value, is still kept in the row's `last_error` and `dead` event detail, and
  is still printed in the traceback of a read that does not handle it. (`BACKLOG #5982`)
