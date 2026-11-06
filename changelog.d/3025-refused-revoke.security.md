- **A refused TOTP enrolment confirm retries its revoke of the rotated session once.** A confirm
  whose conditional enable matches no row revokes the session it just rotated. That session is
  stamped MFA-verified on a factor that is not enabled. A store refusal of the revoke used to leave
  it live until its own timers ended it. The confirm now retries a refused revoke once. A
  cancellation is not retried, and neither is a defect, at least a `NotImplementedError` or a
  `RecursionError`. The `auth.mfa_enroll_refused` row's `session_ended` says whether either
  attempt landed. The session can still stay live, with its token never handed back, at least when
  both attempts are refused, or when the first attempt is cancelled or raises a defect.
  (`BACKLOG #3025`)
