- **An anonymizer salt UTF-8 cannot encode is refused without carrying the salt.** Such a salt,
  as an undecodable byte in an environment variable becomes on POSIX, was refused with the codec's
  own error, which quoted that character in its message and kept the whole salt on its `object`
  attribute. It is now refused with a `ValueError` that quotes none of it and has no chained
  exception. `python -m tee anonymize-captures` names the variable the salt came from when the
  keyer refuses it. Both the toolkit keyer and the copy vendored into the tee changed. The keyer's
  16-character floor, which also refuses every salt under 16 bytes, is unchanged, and it is not a
  128-bit floor (BACKLOG #4652).
