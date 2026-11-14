- **A local sign-in whose account is deleted before its session is written is refused, not
  answered with a 500.**
  `create_session` now returns `False` for an account row it cannot find, on SQLite, PostgreSQL and
  SQL Server, guarded or not, instead of letting the session INSERT fail its foreign key. The
  password sign-in answers that as it answers an unknown account: `invalid credentials`, held to
  the same failure pad, with an `unknown_or_disabled` failure row. (`BACKLOG #2733`)
