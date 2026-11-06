- **A refused TOTP enrolment confirm retries its revoke of the rotated session once.** A confirm
  whose conditional enable matches no row revokes the session it just rotated. That session is
  stamped MFA-verified on a factor that is not enabled. A store refusal of the revoke used to leave
  it live until its own timers ended it. The confirm now retries a refused revoke once. A defect or
  a cancellation is not retried. The `auth.mfa_enroll_refused` row's `session_ended` says whether
  either attempt landed. At least a closed store connection refuses both attempts, and the session
  can then stay live, with its token never handed back. (`BACKLOG #3025`)
