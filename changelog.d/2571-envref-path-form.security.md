- **A FHIR connection that takes `update_url_form` from `env()` is now named as a loosening.**
  `messagefoundry check` and `GET /security/posture` name it, marked possibly where the value is not
  resolved. Neither names a `deployed=False` connection whose `update_url_form` is an `env()` value,
  and a posture read with no loaded graph names no connection. The rule and the cases it leaves off
  are in the `update_url_form` entry of [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
  (`BACKLOG #2571`)
