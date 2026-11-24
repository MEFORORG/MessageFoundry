- **Gate-only check routes, a read-only step-up status route, and two refusal headers on the JSON
  plane** (ADR 0215 slice 2, first half). `GET /auth/check` and one
  `GET /auth/check/<permission>` per permission answer 200 once the `require()` ladder admits the
  caller, and write the grant row wherever a grant of that permission is audited, the PHI views
  included. `GET /me/step-up` reports whether the session's step-up window is live and, with
  `?action=`, whether that action's step-up check would accept the caller's proof now, without
  spending it; it is paced, refused from a host the session has not verified from, and audited. It
  is a hint, not an authorization: the action's own gate decides. A must-change refusal now carries
  `X-Password-Change-Next` (`verify-factor`, `enrol-factor` or `change-password`), and its detail
  ends with the same step, which adds `; verify your second factor first` for a session that owes
  its factor. Every step-up refusal carries `X-Step-Up-Reason` (`new-address`, `verify-factor` or
  `reverify`). See [SECURITY.md](../docs/SECURITY.md). (`BACKLOG #2603`)
