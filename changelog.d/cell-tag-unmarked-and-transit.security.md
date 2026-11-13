- **A planted unmarked cell, and a cell Vault Transit refuses for its tag, are now integrity
  refusals.** A message or preset cell read through its row tag re-raised the cipher's plain error
  in both cases, so a list view, a scope check or a stage handoff that contains only the tag error
  would have answered a 500, written no audit row and left the row in flight. The Transit cipher
  now gives its authenticated-decrypt error where Vault's reason for refusing a value is wholly the
  AEAD's own authentication failure, on a single decrypt's HTTP 400 or a batch result's per-value
  error; a key-version refusal, a 403, a 404 and an outage keep their own error. An unmarked value refused in a tagged cell is drift: audited and contained, with
  the cipher's existing unmarked-value alert as its only alert.
