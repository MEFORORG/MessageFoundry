- **A content-coded egress reply body is refused instead of read as text.** The deliveries this
  fixed include at least SOAP, REST, FHIR and DICOMweb: a reply whose `Content-Encoding` named
  anything but `identity`, such as `gzip`, was decoded as text, so a SOAP Fault or a STOW-RS
  failure inside a 2xx would have been recorded as delivered. On those deliveries a coded 2xx body
  is now the `reply-misframed` refusal where the body is needed, and is dropped with a
  `reply_dropped` event where it is not. A SOAP or FHIR delivery that reads a coded non-2xx body
  logs a WARNING and classifies on the status alone; REST and DICOMweb do not read a non-2xx
  body. Other reads that check reply framing refuse a coded body too, at least the OIDC token
  and JWKS reads and `fhir_lookup` with their own error. On a coded 2xx token reply with a body,
  the SMART and OAuth2 token reads raise a permanent refusal with the code `token-reply-coded`:
  a delivery that mints its bearer dead-letters the message without a retry, since each retry
  would send the client credential again (owner ruling 2026-11-18), and a probe that mints one
  fails. The replies the
  coding check skips are listed on `reply_framing_fault`; they include at least a `204`, a
  `Content-Length: 0` reply and a reply to `HEAD`. (`BACKLOG #5910`)
