- **A pending session on an account with no second factor no longer ends sessions.** Under
  `[security].require_mfa`, such a session is MFA-pending, and it is now treated like any other
  pending session: it reaches at least enrolment and sign-out, and the self-service terminate routes
  (`DELETE /me/sessions`, `DELETE /me/sessions/{session_id}` and their console twins) refuse it.
  No password re-proof mints it a `session_terminate`, `save_ends_own_sessions` or
  `revoke_all_sessions` grant, so none can be carried through its first enrolment. The terminate
  routes used to answer such a session `403` + `X-Step-Up-Required` until it re-proved its password;
  they now answer `403` + `X-MFA-Required` whatever it proves, with a detail that names enrolment,
  and the access gate's own refusal names enrolment to it too. A client that prompts for a code on
  `X-MFA-Required` will prompt for one this session does not have. The console sends the session to
  `/ui/account?m=enroll_first`, from the terminate POSTs and from `/ui/reauth`. The enrolment that
  binds the first factor satisfies the session, and ending sessions then works as before, so for a
  local account a password holder can still enrol a factor of its own and then end sessions: this
  adds a step, not a bar. (`BACKLOG #1149`)
