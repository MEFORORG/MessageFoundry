- **A refused `tls_allow_expired` hop on REST, SOAP or FHIR names a remedy that can admit it.**
  The revocation refusal on those three destinations offered `[tls].crl_file`, which cannot admit a
  hop that sets `tls_allow_expired`, and did not name that setting as the cause. It now names it and
  offers the per-connection attestation, or removing the setting, as MLLP, the DICOM SCU and FTPS
  already did. On a REST hop with an ECH sidecar the ECH remedy stands. The refusal, the WARNING and
  the attested-crossing audit line on such a hop now use the expiry-relaxed record's words, so a log
  search for "verified TLS hop with tls_allow_expired crossed" finds these crossings, and one for
  "crossed without certificate revocation checking" no longer does. The requests-based CRL refusal
  no longer offers a revocation-checking proxy, which cannot clear it. No decision changes: the same
  hops are refused, warned on or admitted as before. (`BACKLOG #2977`)
