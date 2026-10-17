- **The API client waits longer for a sign-in's reply.** `EngineClient.login`, `reauth`,
  `verify_mfa` and `confirm_mfa` now wait up to 30 seconds for the engine's reply, matching the
  IDE's sign-in timeout, instead of the client's 5 second default. Each can wait in the engine's
  per-account queue, and a request the client gave up on could still end or rotate the session it
  held, leaving the client signed out (and, for `confirm_mfa`, without its recovery codes). Only the
  read phase is raised: an unreachable engine is still reported within the client's own timeout.
  The longer wait makes a lost reply rarer, not impossible, because the queue has no bound. Every
  other request keeps the client's timeout. (`vault BACKLOG #2950`)
