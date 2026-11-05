- **A refused `tls_allow_expired` hop on REST, SOAP or FHIR names a remedy that can admit it.**
  The revocation refusal on those three destinations offered `[tls].crl_file`, which cannot admit a
  hop that sets `tls_allow_expired`, and did not name that setting as the cause. It now names it and
  offers the per-connection attestation, or removing the setting, as MLLP, the DICOM SCU and FTPS
  already did. On a REST hop with an ECH sidecar the ECH remedy stands. The PostgreSQL store's
  revocation refusal and the requests-based CRL refusal no longer offer a revocation-checking proxy,
  a lever no setting can declare. No decision changes: the same hops are refused, warned on or
  admitted as before. (`BACKLOG #2977`)
