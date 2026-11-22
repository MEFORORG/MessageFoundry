- **A static HTTP request value `http.client` could never send fails the connection at build.**
  A FHIR destination or `FhirLookup` whose static `url` is not ASCII or holds whitespace or a `#`,
  or whose static header `http.client` would not send, and a FHIR destination whose
  `conditional_query` is all whitespace, used to build and then fail every message. They are
  refused at build now. So are, at least: a REST, SOAP or DICOMweb destination whose static `url`
  is not ASCII or holds whitespace or a control character; a `smart_token_url` or
  `oauth2_token_url` that is not ASCII or holds whitespace or a control character; and, on each
  of these connections, a static header whose name is not an RFC 9110 token or whose value holds
  a control character other than HTAB. A REST or SOAP `url` may still hold a `#`, since urllib
  drops the fragment there and those connectors append no path. A header name that reads as
  `Proxy-Authorization` keeps the proxy-header rule's own refusals. A refusal names the setting
  and, for a header, its key, never a value. (`BACKLOG #5911`)
