- **A pending session on an account with no second factor no longer ends sessions.** Under
  `[security].require_mfa`, such a session is MFA-pending, and it is now treated like any other
  pending session: it reaches enrolment and sign-out, and the self-service terminate routes
  (`DELETE /me/sessions`, `DELETE /me/sessions/{session_id}` and their console twins) refuse it.
  No password re-proof mints it a `session_terminate`, `save_ends_own_sessions` or
  `revoke_all_sessions` grant, so none can be carried through its first enrolment. The JSON refusal
  keeps `403` + `X-MFA-Required` and its detail now names enrolment; the console sends the session
  to `/ui/account?m=enroll_first`. The enrolment that binds the first factor satisfies the session,
  and ending sessions then works as before. (`BACKLOG #1149`)
