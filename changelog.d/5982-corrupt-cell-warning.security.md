- **A queue row refused when its sealed cell is opened no longer carries the cipher's refusal
  text.** This covers a cell sealed for another row, a corrupt cell, for example bad base64 or a
  ciphertext too short for a tag, a cell under a key the store does not hold, and a marker this
  build cannot parse. The error raised for it is the class it was before, a queue-tag refusal or
  the cipher's own class. Its message holds fixed wording, the cipher error's class and a fixed
  code, such as `bad_base64`, `tag_mismatch`, `unknown_key` or `unparseable_marker`, and the
  cipher's error is neither its cause nor its context. So none of these carries the cipher's
  text: a claim's WARNING, uvicorn's ERROR traceback for a read the API does not handle, and a
  dead-lettered row's `last_error` and `dead` event detail. The refusal is handled as before: a
  claim dead-letters it, auditing and alerting a queue-tag refusal, and a read is refused. A
  claim's dead-letter WARNING names a queue-tag refusal by its class and cause, and any other
  error by its class alone. Opening the cell no longer holds the refusal in a reference cycle, so
  other rows' opened bodies in the caller's frames are no longer kept alive by that cycle until
  the next cyclic collection. What is lost is diagnostic, at least: the key id the cipher's text
  echoed, the marker version or algorithm id an unparseable marker named, the remedy named for a
  retired key that is not supplied, and, under Vault Transit, the Transit key name, the hvac
  error's class and which kind of non-AEAD refusal it was. Known limits, at least: a key service
  that gave no verdict is raised as the cipher gave it, since a claim reads its cause to set the
  row aside, so its text still reaches the fault a claim logs at ERROR; an unmarked value's
  refusal keeps its text, which names a column and a remedy and no value; and a store-once row's
  shared body, which the store opens with its own decrypt after the queue cell has opened, keeps
  the cipher's text in its refusal. (`BACKLOG #5982`)
