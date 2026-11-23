Row seals: the Vault Transit row sealer now refuses to seal a float that is a NaN or an infinity,
as the local sealer already did, and both raise `NonFiniteSealValueError`, a `ValueError` subclass.
The Transit sealer reads a stored seal that is not text (a blob or a number) as malformed rather
than raising, so a write over such a session row is refused as a failed seal (BACKLOG #6717,
#6718). The bytes a seal covers are unchanged, so a seal written before this change still verifies.
