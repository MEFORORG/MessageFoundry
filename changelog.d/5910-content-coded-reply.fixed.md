- **A content-coded egress reply body is refused instead of read as text.** The deliveries this
  fixed include at least SOAP, REST, FHIR and DICOMweb: a reply whose `Content-Encoding` named
  anything but `identity`, such as `gzip`, was decoded as text, so a SOAP Fault or a STOW-RS
  failure inside a 2xx would have been recorded as delivered. On those deliveries a coded 2xx body
  is now the `reply-misframed` refusal where the body is needed, and is dropped with a
  `reply_dropped` event where it is not. A SOAP or FHIR delivery that reads a coded non-2xx body
  logs a WARNING and classifies on the status alone; REST and DICOMweb do not read a non-2xx
  body. Other reads that check reply framing refuse a coded body too, at least the OIDC token
  and JWKS reads and `fhir_lookup` with their own error. The SMART and OAuth2 token reads raise
  `AmbiguousFramingError`, a transient `DeliveryError` that a delivery retries, not a
  `reply-misframed` refusal. The replies the coding check skips are listed on
  `reply_framing_fault`; they include at least a `204`, a `Content-Length: 0` reply and a reply to
  `HEAD`. (`BACKLOG #5910`)
