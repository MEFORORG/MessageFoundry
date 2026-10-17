- **A credential in a connection `url`'s query string is a recorded loosening now (ASVS 14.2.1).**
  A WARNING names the connection and the parameter names, never a value, when the resolved `url`
  of an outbound or a `FhirLookup` carries a parameter named like a credential (`key`, `sig`,
  `signature`, or a name ending in `token`, `secret`, `password` and the rest of the engine's
  credential vocabulary, in snake_case or camelCase). It fires at least on a build check and on a
  start; a reload's rebuilds skip it. docs/SECURITY-LOOSENING.md says where it fires.
  `messagefoundry check` gains an advisory
  `url-query-credential` line, and `security_loosenings()`, and so `GET /security/posture`, gains a
  `url_query_credential` entry. `GET /metadata` and `graph --json` now withhold such a URL whole,
  and any other URL setting that may carry a credential; they used to mask only a userinfo password
  and keep the user, host and path. The rule is in `config/wiring.py`
  (`_url_may_carry_a_credential`). On a first
  deployment such a URL would have been accepted with no line anywhere and served verbatim by those
  views. It is warned rather than refused, unlike a credential in the URL's user part: a query
  credential does authenticate, and some partner APIs take it nowhere else. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
