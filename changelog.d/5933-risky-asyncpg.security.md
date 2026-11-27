- **[RISKY-COMPONENTS.md](../docs/RISKY-COMPONENTS.md) assesses the `postgres` extra.** Its one
  added name, `asyncpg`, is designated on tiers 1, 2 and 3, native, in a new `postgres` section, and
  the extra leaves the page's list of unassessed extras. The public-data readings in
  `security/risky-component-readings.json` were re-read on 2026-11-27 for all 42 assessed
  distributions. That re-read moved 17 pins, so those 17 wheels and `asyncpg` were surveyed again
  by hand in `security/bundled-code-survey.json`. `hl7apy` leaves the poorly-maintained table: a
  1.4.0b1 pre-release was uploaded on 2026-10-26. (`BACKLOG #5933`)
