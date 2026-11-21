- **A zero or negative request timeout is refused when the connection is built.** The SOAP, FHIR
  and DICOMweb destinations' `timeout_seconds`, a `fhir_lookup` connection's `timeout_seconds`,
  `smart_timeout_seconds` and `oauth2_timeout_seconds` now refuse a value that is not above zero,
  naming the key and withholding the value, as the REST destination's `timeout_seconds` already
  did. Before, each built a connection whose every request failed. (`BACKLOG #5959`)
