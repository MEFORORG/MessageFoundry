- **A content-coded egress reply body is refused instead of read as text.** At least a SOAP,
  REST, FHIR, DICOMweb or OIDC reply whose `Content-Encoding` names anything but `identity`, such as `gzip`,
  was decoded as text, so a SOAP Fault or a STOW-RS failure inside a 2xx would have been recorded
  as delivered. A coded 2xx body is now the `reply-misframed` refusal where the body is needed,
  and is dropped with a `reply_dropped` event where it is not. A SOAP or FHIR delivery that reads
  a coded non-2xx body logs a WARNING and classifies on the status alone; REST and DICOMweb do not
  read a non-2xx body. A `Content-Length: 0` reply, a `204`, a `304`, any `1xx` and a reply to
  `HEAD` are not refused. (`BACKLOG #5910`)
