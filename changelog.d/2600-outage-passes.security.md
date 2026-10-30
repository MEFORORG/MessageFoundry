- **A longer directory-outage run is now a named loosening.** While the directory session
  reconciler runs, `[auth].ad_reconcile_outage_passes` above its default of 3 is reported by the
  serve-time warning, `messagefoundry security show` and `GET /security/posture`: it delays the
  page about an outage during which no directory disable or deletion reaches a signed-in session.
  The entry gives the least delay at the configured interval, measured from the first outage pass,
  and the `ad_session_recheck_seconds` entry now says a longer interval delays that page too. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #2600`)
