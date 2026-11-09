- **A FHIR connection that takes `update_url_form` from `env()` is now named as a loosening.**
  `messagefoundry check` and `GET /security/posture` name it, marked possibly where the value is not
  resolved. The rule is in the `update_url_form` entry of
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
  (`BACKLOG #2571`)
