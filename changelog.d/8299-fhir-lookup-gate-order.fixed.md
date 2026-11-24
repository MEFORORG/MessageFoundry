- **A `FhirLookup` refused for a setting leaves no crossing record from another lookup first, in
  at least these cases.** Its url and header screens, the length limits on its static url and
  headers, its `timeout_seconds` and its hop declarations are now checked for every lookup before
  any lookup reaches a hop gate, and so are the `BACKLOG #5800` SMART refusals of an unencodable
  `smart_scope`, `smart_private_key` or `smart_private_key_password` and an over-length
  `smart_token_url`, and the `[tls].crl_check_chain` refusal of an `http` lookup. The `#5800`
  refusal of an over-length proxy header on the token hop, the `crl_check_chain` refusal of an
  `https` lookup and the SMART provider's other checks still run later in the build. A lookup's bearer is judged against a
  cleartext `http` read before its SMART token provider is built. A length refusal now names the
  lookup. A refusal from
  a check that runs later in the build can still follow such a record. A FHIR destination or
  `FhirLookup` whose `headers` is not a table, which sets one of `basic_user` and
  `basic_password` without the other, puts a `:` in `basic_user`, or sets `bearer_token` beside a
  Basic pair is refused at build. These used to build and then send no headers, no Basic
  credential, a Basic credential split at the wrong colon, or Basic in place of the bearer.
  (`BACKLOG #8299`)
