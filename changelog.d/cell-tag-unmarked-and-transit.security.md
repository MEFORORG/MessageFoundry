- **A planted unmarked cell, and a cell Vault Transit refuses for its tag, are now integrity
  refusals.** A message or preset cell read through its row tag re-raised the cipher's plain error
  in both cases, so a list view, a scope check or a stage handoff that contains only the tag error
  would have answered a 500, written no audit row and left the row in flight. The Transit cipher
  now gives its authenticated-decrypt error where every reason Vault gives for refusing a value is
  the AEAD library's own authentication-failure text, unwrapped, on a single decrypt's HTTP 400 or
  a batch result's per-value error. That text was not read from Vault's or OpenBao's source, so a
  release that wraps it would leave such a refusal the cipher's plain error. At least a key-version
  refusal, a 403, a 404 and an outage keep their own error. Transit gives the same refusal for a
  data key that is not the one that sealed the cell, so a recreated key reads as drift too. An
  unmarked value refused in a tagged cell is drift: audited and contained, with the cipher's
  existing unmarked-value alert as its only alert, and its WARNING and audit row written once an
  hour per cell column.
