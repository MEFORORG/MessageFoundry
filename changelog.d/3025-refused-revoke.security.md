- **A refused TOTP enrolment confirm tries again to end the session it rotated.** When the
  conditional enable matches no row, the confirm revokes the session it just rotated, which is
  stamped MFA-verified on a factor that is not enabled. A store refusal of that revoke left the
  session live until its own timers ended it. The confirm now makes a second attempt, through the
  store's `supersede_session`, and the `auth.mfa_enroll_refused` row's `session_ended` records
  whether either landed. Only a store that refuses both still leaves the session live, and its
  token is never handed back. (`BACKLOG #3025`)
