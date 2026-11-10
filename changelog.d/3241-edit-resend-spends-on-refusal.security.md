- **Edit-resend spends its proof when the engine refuses it with a 403, 404 or 409.** These
  refusals used to give the action proof back when they came before the message-store write, so
  one proof could try any number of targets and learn from each answer whether the target was out
  of scope, unknown or unable to take the write. They now keep the spend, and the next request
  needs a new re-authentication. Any other refusal before the store write, such as a 400 or an
  ingress guard's 413, 415 or 422, still gives the proof back. In direct mode the guard now runs
  before the target's registry checks.
  [ADR 0197](../docs/adr/0197-cap-repeated-lock-cycles-on-one-account-without-making-malicious-lockout-cheaper.md)
  Amendment D records the owner's ruling and, under *The order of the checks*, the order of the
  checks in each mode. (vault `BACKLOG #3241`)
