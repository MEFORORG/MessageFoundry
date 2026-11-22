- **A static HTTP request value `http.client` could never send fails the connection at build.**
  A FHIR destination or `FhirLookup` whose static `url` is not ASCII or holds whitespace or a `#`,
  or whose static header `http.client` would not send, and a FHIR destination whose
  `conditional_query` is all whitespace, used to build and then fail every message. They are
  refused at build now. So are, at least: a REST, SOAP or DICOMweb destination whose `url` (for
  DICOMweb, its STOW-RS target) is not ASCII or holds whitespace or a control character; a
  `smart_token_url` or `oauth2_token_url` of that shape; and, on each of these connections, a
  static header whose name is not an RFC 9110 token or whose value holds a control character
  other than HTAB. Where a URL is sent with no path appended (REST, SOAP, DICOMweb's target and
  the token URLs), whitespace around it is not refused, since urllib strips it. On REST, SOAP and
  the token URLs a fragment is not refused either, since urllib drops it before sending to the
  peer. Both are refused where a setting reads the URL as written: on a REST or SOAP destination
  with HTTP Digest, whose password is keyed on it; on a SOAP destination with `ws_addressing` on,
  whose `wsa:To` carries it; and in a `smart_token_url` with no `smart_audience`, whose default
  `aud` is it. On REST, SOAP and DICOMweb a header name that
  reads as `Proxy-Authorization` is left to the proxy-header rule, as before. A refusal names the
  setting and, for a header, its key, never a value. (`BACKLOG #5911`)
