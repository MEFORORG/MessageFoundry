- **An identity holding `messages:view_raw` without `messages:view_summary` is refused when it is
  built.** The rule that a role reading whole bodies also reads the summary is judged per role, so
  it reaches a user only while each identity is built from whole roles. Nothing checked that.
  `Identity.build` now refuses a set of that shape, which whole roles cannot produce, and a test
  pins its callers to whole roles. No built-in role and no role the engine mints has that shape.
  (vault `BACKLOG #3474`)
