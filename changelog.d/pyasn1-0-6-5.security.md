- **The repository's locks pin pyasn1 0.6.5, past CVE-2026-119194, CVE-2026-119195, CVE-2026-119196
  and CVE-2026-119197.** In 0.6.4 and earlier, crafted BER, CER or DER input could cost quadratic CPU
  in `decode()`, through schema-less containers, constructed strings, indefinite-length `ANY` or binary
  `REAL`. A site using the optional `[webauthn]` extra has pyasn1's BER decoder on its passkey
  registration path, for Android Key attestation, so it would otherwise keep the old decoder there.
