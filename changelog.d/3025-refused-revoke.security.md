- **A refused TOTP enrolment confirm tries again to end the session it rotated.** When the
  conditional enable matches no row, the confirm revokes the session it just rotated, which is
  stamped MFA-verified on a factor that is not enabled. A store refusal of that revoke left the
  session live until its own timers ended it. The confirm now tries the revoke once more when the
  first attempt does not land, whatever it raised, and the `auth.mfa_enroll_refused` row's
  `session_ended` records whether either attempt landed. The retry recovers only a refusal that
  has cleared by then; at least a closed store connection refuses both, and the session then
  stays live, though its token is never handed back. (`BACKLOG #3025`)
