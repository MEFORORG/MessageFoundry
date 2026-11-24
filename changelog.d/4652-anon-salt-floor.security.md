- **The anonymizer salt must be at least 32 characters, up from 16.** `secrets.token_hex(16)`
  (32 characters, 128 bits) and the recommended `secrets.token_urlsafe(24)` pass;
  `secrets.token_hex(8)` (16 characters, 64 bits) is now refused. This is a length floor, not an
  entropy measurement: `secrets.token_urlsafe(16)` carries 128 bits in 22 characters and is
  refused, and a guessable 32-character string can pass. The existing entropy screen stays as
  the low-entropy check. The too-short refusal now names the generator.
- **An anonymizer salt UTF-8 cannot encode is refused without quoting the salt in the message or
  carrying it on the exception chain.** An undecodable byte in an environment variable becomes
  such a character on POSIX, and Windows can hold an unpaired surrogate. The keyer used to let
  the codec's own error through, which quoted that character and kept the whole salt on its
  `object` attribute. It now raises a `ValueError` that quotes none of it and chains no exception.
  The frames its traceback carries can still hold the salt as a local, so a traceback renderer
  that captures locals would print it.
- `python -m tee anonymize-captures` names the variable the salt came from when the keyer refuses
  it. Both the toolkit keyer and the copy vendored into the tee changed (BACKLOG #4652).
