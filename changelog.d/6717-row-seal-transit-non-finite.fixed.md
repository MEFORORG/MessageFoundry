- **The Vault Transit row sealer refuses a non-finite float, and reads a non-text seal as
  malformed.** It now refuses to seal a float that is a NaN or an infinity, as the local sealer
  already did, and both raise `NonFiniteSealValueError`, a `ValueError` subclass. A stored seal
  that is not text (a blob or a number) reads as malformed under Transit rather than raising: a
  session read with one fails its seal check, and a write over such a row is refused as a failed
  seal. The bytes a seal covers are unchanged. (`BACKLOG #6717`, `BACKLOG #6718`)
