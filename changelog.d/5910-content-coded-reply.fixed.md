- **A content-coded egress reply body is refused instead of read as text.** A SOAP, REST, FHIR,
  DICOMweb or OIDC reply whose `Content-Encoding` names anything but `identity`, such as `gzip`,
  was decoded as text, so a SOAP Fault or a STOW-RS failure inside a 2xx would have been recorded
  as delivered. A coded 2xx body is now the `reply-misframed` refusal where the body is needed,
  and is dropped with a `reply_dropped` event where it is not. A coded non-2xx body is logged and
  the delivery fails on its status. A `Content-Length: 0` reply, a `204`, a `304` and a reply to
  `HEAD` are not refused. (`BACKLOG #5910`)
