- **A refusal a route body makes after its gate admitted the request now writes `auth.gate_refused`
  instead of following a grant row.** This covers the step-up proof a `proof_in_route` route spends
  itself (purge, reload, export, edit-resend and the four group-wide saves), the group-wide saves'
  session-window check, and a `reveal`'s new-address and PHI-budget refusals. In the shipped code
  each such refusal left an `auth.permission_granted` row and no refusal row. The route's gate now
  leaves its row to that check, so a refused request writes one `auth.gate_refused` row naming the
  gate's permission and a `reason` of `step_up` or `throttled`, and an admitted one writes the grant
  row. A request whose body never reaches the check still gets its grant row, after the endpoint.
  No request is allowed or refused differently. [SECURITY.md](../docs/SECURITY.md) says which
  refusals still follow a grant row. (`BACKLOG #1197`)
