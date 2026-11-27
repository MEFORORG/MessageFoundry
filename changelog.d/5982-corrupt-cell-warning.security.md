- **A queue row refused at its queue tag is logged at WARNING without the cipher's refusal
  text.** This covers a cell sealed for another row, and a corrupt cell, for example bad base64
  or a ciphertext too short for a tag, under any cipher. The row is still dead-lettered, audited
  and alerted as before. Its report's WARNING names the row, its stage and the cause, and the
  claim's dead-letter WARNING names the error's class and cause in place of its text. The
  cipher's reason stays in the dead-lettered row's `last_error`, and is logged at DEBUG where the
  log level admits it. Known limit: a cell under a key the store does not hold is not a queue-tag
  refusal, and its claim WARNING still carries the cipher's text. (`BACKLOG #5982`)
