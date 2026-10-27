- **A session seal stops a forged or edited session row, not an older sealed copy put back.** The
  released entry for session-row seals did not say so, unlike the entries for user, role and
  approval seals. A writer who kept a sealed `sessions` row can restore it whole with its seal,
  and it verifies. That includes a copy kept from before that one session was signed out, or
  before its step-up or second-factor stamp was cleared. Ending every session of an account raises
  the account's session epoch, so a copy from an older epoch is still refused, unless the writer
  also puts back an older sealed copy of the account. Detecting a rollback is not built yet.
  (vault BACKLOG #2592)
