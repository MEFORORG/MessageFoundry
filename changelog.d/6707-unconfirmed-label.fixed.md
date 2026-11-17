- **A Transit audit MAC 400 reads "refused" only when Vault's reply names a version refusal.** A
  400 that would have read as a refused key version, but whose reply names none, now takes the
  "could not be confirmed" text, and the row is still a break with the tamper alert. A fault while
  reading such a 400 now also takes that text and is a break with the alert, where the walk could
  not run before. Why a 400 took that text is logged, rate limited, without the reply's text.
  (vault `BACKLOG #6707`)
