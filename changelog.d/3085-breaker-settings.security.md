- **The engine refuses directory reconciler settings that leave the mass-revoke breaker unable
  to trip.** With AD on and a non-zero `[auth].ad_session_recheck_seconds`, the load now refuses
  an `ad_session_revoke_max_fraction` of `1.0`, and an `ad_session_recheck_max_users` at or below
  `ad_session_revoke_max`. The breaker trips only when a pass exceeds both thresholds, so either
  setting disabled it with no warning. The validator message and
  [CONFIGURATION.md](../docs/CONFIGURATION.md) used to say `1.0` disabled only the proportional
  half. (`BACKLOG #3085`)
