- **The engine names directory reconciler settings that leave the mass-revoke breaker unable to
  trip.** The breaker trips only when a pass exceeds both thresholds. With AD on and a non-zero
  `[auth].ad_session_recheck_seconds`, the load now refuses an `ad_session_revoke_max_fraction`
  of `1.0`. An `ad_session_recheck_max_users` at or below `ad_session_revoke_max` still loads,
  and revocation still works, but the engine logs a WARNING at start that names both settings.
  Before, neither setting was refused or warned of. The validator message and
  [CONFIGURATION.md](../docs/CONFIGURATION.md) used to say `1.0` disabled only the proportional
  half. (`BACKLOG #3085`)
