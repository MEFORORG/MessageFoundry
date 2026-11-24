- **Gate-only check routes, a read-only step-up status route, and two refusal headers on the JSON
  plane** (ADR 0215 slice 2, first half). `GET /auth/check` and one
  `GET /auth/check/<permission>` per permission answer 200 once the `require()` ladder admits the
  caller, and read nothing else. `GET /me/step-up` reports whether the session's step-up window is
  live and, with `?action=`, whether the caller holds a proof for that action, without spending it.
  It is a hint, not an authorization: the action's own gate decides. A must-change refusal now carries `X-Password-Change-Next` (`verify-factor`,
  `enrol-factor` or `change-password`), and every step-up refusal carries `X-Step-Up-Reason`
  (`new-address` or `reverify`). Detail strings are unchanged. See
  [SECURITY.md](../docs/SECURITY.md). (`BACKLOG #2603`)
