- **`audit_all_platforms --skip-private <name>` leaves a private package's pin out of the audit.**
  Given before the lock and repeatable, it is for a package no advisory database can look up,
  which `pip-audit --strict` otherwise fails; the pin is printed as not audited, and every other
  pin is still looked up. It refuses the engine's own name and each MessageFoundry package the
  release records as published, at least `messagefoundry-webconsole`, `messagefoundry-harness`
  and `messagefoundry-toolkit`, since an advisory database can look each one up. It also refuses a
  name the lock does not pin, a list that skips every pin, and the flag after the lock. See
  [ADOPTER-CI.md](../docs/ADOPTER-CI.md). (`BACKLOG #3786`)
