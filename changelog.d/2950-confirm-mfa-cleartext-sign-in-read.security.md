- **`EngineClient.confirm_mfa` refuses, before sending, to put its code on a cleartext
  non-loopback hop, and the sign-in read now outlasts the engine's request deadline.**
  `confirm_mfa` had no entry-point refusal, so with no token held it would have sent the second
  factor over a permitted plaintext hop; it now refuses as `verify_mfa` does. The Python
  client's read on `login`, `reauth`, `verify_mfa` and `confirm_mfa`, and the IDE's sign-in
  timeout, go from 30 to 150 seconds, and the read on `change_password` from the client's 5 second
  default to 150 seconds, 30 seconds past the engine's default 120 second
  request deadline, so a sign-in waiting in the per-account queue no longer outlasts the client at
  that default. A lost reply is rarer, not impossible. Every other Python client request keeps its timeout.
  (`vault BACKLOG #2950`)
