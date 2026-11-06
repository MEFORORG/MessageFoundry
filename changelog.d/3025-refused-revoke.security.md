- **A refused TOTP enrolment confirm tries again to end the session it rotated.** A confirm whose
  conditional enable matches no row revokes the session it just rotated. That session is stamped
  MFA-verified on a factor that is not enabled. A store refusal of the revoke used to leave it live
  until its own timers ended it. The confirm now tries the revoke once more, whatever the first
  attempt raised. The `auth.mfa_enroll_refused` row's `session_ended` says whether either attempt
  landed. The retry helps only when the refusal has cleared. At least a closed store connection
  refuses both attempts, and the session may then stay live. Its token is never handed back.
  (`BACKLOG #3025`)
