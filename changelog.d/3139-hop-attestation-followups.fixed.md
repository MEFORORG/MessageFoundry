- **A refused or malformed hop attestation is now reported plainly.** These are follow-ups to the
  strict hop-policy reader (vault BACKLOG #2232). The build check already refused each config here.
  - The `tls-hop-attested` line of `messagefoundry check` escapes control characters in a reason.
    A `DatabaseRef` reason holding a newline used to split the line. It also marks an entry the build
    check refuses as `REFUSED`, and no longer says every listed hop is allowed.
  - `serve` now refuses a reference set whose source carries a raw `env()` hop-policy flag at start,
    before any sync. It used to fail only at the set's first sync, which logged just `WiringError`.
    The sync now also logs the refusal text, which names the set and the flag but no value.
  - The `db_lookup` and `DatabaseRef` reader of `tls_hop_attested_reason` refuses a non-string or a
    control character, as the factories and the FHIR lookup already did.
  - A hop-policy flag refusal mentions `env()` only when the value is an `env()` reference.
  - The FHIR lookup executor and the anonymous FTP guard name the connection when they refuse a flag.
  (`vault BACKLOG #3139`)
