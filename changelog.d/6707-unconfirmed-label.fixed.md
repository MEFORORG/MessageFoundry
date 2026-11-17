- **A Transit audit MAC 400 reads "refused" only when Vault's reply names a version refusal.** A
  400 that would have read as a refused key version, but whose reply names none, unknown or empty
  Vault wording included, now takes the "could not be confirmed" text. Only the text changes: the
  row is still a break with the tamper alert. Why a 400 took that text is logged at most once an
  hour for each audit key and reason, and a body past the re-parse bound is not read even when
  hvac parsed it.
  (vault `BACKLOG #6707`)
