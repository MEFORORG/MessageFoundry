- **[RISKY-COMPONENTS.md](../docs/RISKY-COMPONENTS.md) assesses the `postgres` extra.** Its one
  added name, `asyncpg`, is designated on tiers 1, 2 and 3, native, in a new `postgres` section, and
  the extra leaves the page's list of unassessed extras. The public-data readings in
  `security/risky-component-readings.json` were re-read on 2026-11-27 for all 42 assessed
  distributions. 17 pins had moved since the last snapshot, through lock bumps that landed after
  it, so those 17 wheels and `asyncpg` were surveyed again by hand in
  `security/bundled-code-survey.json`. `hl7apy` leaves the poorly-maintained table: a 1.4.0b1
  pre-release was uploaded on 2026-10-26. `messagefoundry verify` no longer calls `asyncpg`
  pure-Python; its protocol and codec code is compiled. (`BACKLOG #5933`)
