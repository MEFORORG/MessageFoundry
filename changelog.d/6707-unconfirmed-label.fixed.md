- **A Transit audit MAC 400 reads "refused" only when Vault's reply names a version refusal.** A
  Vault 400 whose errors list names no version refusal, or whose body is past the re-parse bound,
  now takes the "could not be confirmed" text, and the row is still a break with the tamper alert.
  Any fault while reading such a 400 now takes that text too; before, only running out of memory
  or stack did, and other faults made the walk unable to run. Why a 400 took that text is logged,
  rate limited, without the reply's text.
  (vault `BACKLOG #6707`)
