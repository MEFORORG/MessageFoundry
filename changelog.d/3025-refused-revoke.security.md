- **A refused TOTP enrolment confirm retries its revoke of the rotated session once.** A confirm
  whose conditional enable matches no row revokes the session it just rotated, which is already
  stamped MFA-verified. A store refusal of the revoke used to leave it live until its own timers
  ended it. The confirm now tries the revoke once more. Which raises are retried, and when the
  session can still stay live, is in `docs/SECURITY.md` under the heading "Multi-factor
  authentication (TOTP, WP-14)". (`BACKLOG #3025`)
