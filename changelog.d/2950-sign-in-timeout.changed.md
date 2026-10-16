- **The API client waits longer for a sign-in.** `EngineClient.login`, `reauth` and `verify_mfa`
  now wait up to 30 seconds per phase, matching the IDE's sign-in timeout, instead of the client's
  5 second default. Each can wait in the engine's per-account queue, and a sign-in the client gave
  up on could still end the session it replaced, leaving the client signed out. The longer wait
  makes that rarer, not impossible, because the queue has no bound. Every other request keeps the
  client's timeout. (`vault BACKLOG #2950`)
