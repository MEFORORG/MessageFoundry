- **A directory rename refresh no longer reports a record that fails its integrity check as gone,
  or as nobody holding the name.** When the renamed account's own record failed its seal, the
  refresh filed an `auth.ad_username_refresh_conflict` row saying the row was removed. It now
  writes nothing, files nothing more than the loader's own seal-failure report, and logs a warning
  that names the integrity failure. When the account that holds the new name fails its seal, the
  write path used to warn that no row held the name and that a later pass would retry, which is
  false while that holder stays refused. It now gives the lockout warning, and the conflict row
  carries `held_by_refused: true` in place of an unverified id. (`vault BACKLOG #3069`)
