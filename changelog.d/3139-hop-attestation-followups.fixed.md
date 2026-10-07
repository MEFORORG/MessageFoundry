- **A refused or malformed hop attestation is now reported plainly.** These are follow-ups to the
  strict hop-policy reader (vault BACKLOG #2232). The build check already refused each config here.
  (`vault BACKLOG #3139`)
  - The `tls-hop-attested`, `cleartext-accepted` and `tls-revocation-attested` lines of
    `messagefoundry check` show each entry as `name ("reason")`. A name outside letters, digits and
    `_.:-` is quoted too. Quotes, controls and non-ASCII characters are escaped, so a newline cannot
    split the line, and a lookalike quote cannot fake the end of a reason.
  - The `tls-hop-attested` line marks an entry the build check refuses as `REFUSED`, at the end of
    the entry. The mark comes from a field the engine sets, not from the reason text. The line no
    longer says every listed hop is allowed.
  - `serve` now refuses a reference set at start, before any sync, when its source carries a hop
    flag or attestation pair the build check refuses. That covers at least a raw `env()` or other
    non-boolean flag, and a missing, blank, non-string or control-character reason. It used to fail
    only at the set's first sync, which logged just `WiringError`. The sync now also logs the
    refusal text, which names the set and the flag but no value.
  - The `db_lookup` and `DatabaseRef` reader of `tls_hop_attested_reason` refuses a non-string or a
    control character, as the factories and the FHIR lookup already did.
  - A hop-policy flag refusal mentions `env()` only when the value is an `env()` reference.
  - The FHIR lookup executor and the anonymous FTP guard name the connection when they refuse a flag.
