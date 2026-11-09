- **A FHIR connection that takes `update_url_form` from `env()` is now named as a loosening.**
  `GET /security/posture` resolves the value against the running graph's values and names the
  connection if it resolves to `"path"`. `messagefoundry check` does not resolve it, so it names
  such a connection marked possibly, and so does the posture route for a value it cannot resolve.
  `FHIR()` now leaves an `env()` `update_url_form`, `interaction` or `conditional` to the build when
  it checks the path form and the Bundle entry lists, so it no longer refuses an `env()` interaction
  beside a literal path form or beside entry lists; it still checks the lists' literal items, and
  still refuses an `env()` interaction beside entry lists and a literal path form or conditional,
  or beside `allowed_entry_types` with no `allowed_entry_methods`, which no interaction builds with. A literal conditional beside a literal `transaction` or
  `batch` interaction is now refused at load, with the build's reason, rather than only at build. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #2571`)
