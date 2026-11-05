- **`EngineClient.change_password` waits as long as the sign-in for its reply, and a client built
  with a longer timeout keeps it on every queued call.** The current-password proof queues behind
  the account's re-proof lock, as `reauth` does, so it now gets the sign-in's 30 second read
  instead of the 5 second default. The sign-in read is now a floor, not a ceiling: a client built
  with a timeout above 30 seconds used to get a shorter read on `login`, `reauth`, `verify_mfa`
  and `confirm_mfa` than on any other request. (`BACKLOG #2950`)
