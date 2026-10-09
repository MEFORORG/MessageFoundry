- **Three numeric `[auth]` settings are now reported loosenings when set looser than they ship:**
  `step_up_max_age_seconds` above `300`, `totp_skew_steps` of `1` or `2`, and
  `initial_password_expiry_hours` above `72` or at `0` or less (no expiry). The serve-time warning,
  `messagefoundry security show` and `GET /security/posture` name them. Nothing refuses one. The
  last two entries do not repeat the configured value. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`vault BACKLOG #2600`)
