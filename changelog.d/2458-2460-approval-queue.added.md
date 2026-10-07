- **The approver queue says what a release would run and whether it can.** Each row of
  `GET /approvals` now carries `params`, the parameters the hold captured, which a release
  re-runs (vault `BACKLOG #2458`). It also carries `caller_is_requester`, compared on the user id
  as the self-approval refusal is, and `gated`, which is false once dual control no longer gates
  the operation (vault `BACKLOG #2460`). A pending row whose stored params cannot be read as a
  JSON object lists `params` as null, and approving it answers 409 rather than 500. The engine
  still makes every refusal itself; the fields only let a page stop offering a release it would
  refuse. See [SECURITY.md](../docs/SECURITY.md).
