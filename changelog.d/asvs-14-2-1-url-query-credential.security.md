- **A credential in a connection `url`'s query string is a recorded loosening now (ASVS 14.2.1).**
  Every outbound and `FhirLookup` build logs a WARNING naming the connection and the parameter
  names, never a value, when the resolved `url` carries a parameter named like a credential (`key`,
  `sig`, `signature`, or a name ending in `token`, `secret`, `password` and the rest of the engine's
  credential vocabulary, in snake_case or camelCase). `messagefoundry check` gains an advisory
  `url-query-credential` line, and `security_loosenings()`, and so `GET /security/posture`, gains a
  `url_query_credential` entry. `GET /metadata` and `graph --json` now withhold such a URL whole, as
  `<scheme>://<redacted>`, and the same for any URL setting with an `@`, `%40` or `%3A` in it (they
  used to mask only a userinfo password and keep the user, host and path). On a first
  deployment such a URL would have been accepted with no line anywhere and served verbatim by those
  views. It is warned rather than refused, unlike a credential in the URL's user part: a query
  credential does authenticate, and some partner APIs take it nowhere else. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
