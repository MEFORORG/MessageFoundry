- **A queue row refused at its queue tag is logged at WARNING without the cipher's refusal
  text.** This covers a cell sealed for another row, and a corrupt cell, for example bad base64
  or a ciphertext too short for a tag, under any cipher. The refusal is handled and reported as
  before: a claim dead-letters, audits and alerts it, and a read is refused and alerted. Its
  report's WARNING names the row, its stage and the cause, and a claim's dead-letter WARNING
  names the error's class and cause in place of its text. Which way a corrupt cell is corrupt is
  therefore no longer logged; a claim whose dead-letter write succeeds keeps the error's text,
  cut to length, in the row's `last_error`. Known limits, at least: a cell under a key the store
  does not hold, or with a marker this build cannot parse, is not a queue-tag refusal, and its
  claim WARNING still carries the cipher's text. (`BACKLOG #5982`)
