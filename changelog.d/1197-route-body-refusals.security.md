- **A refusal a route body makes after its gate admitted the request now writes `auth.gate_refused`
  instead of following a grant row.** This covers at least the step-up proof a `proof_in_route`
  route spends itself (at least purge, reload, export, edit-resend and the four group-wide saves),
  the group-wide saves' session-window check, and a `reveal`'s new-address and PHI-budget
  refusals. In the shipped code such a refusal left an `auth.permission_granted` row and no refusal
  row wherever the grant row was written: on every one of them while `[diagnostics].audit_all_authz`
  is on, its default, and with it off on the non-GET routes only, so a GET reveal's refusal then
  wrote no row before this change and writes none after it. The route's gate now
  leaves its row to that check, so a refused request writes one `auth.gate_refused` row naming the
  gate's permission and a `reason` of `step_up` or `throttled`, and an admitted one writes the grant
  row. A store fault or plain refusal inside the check writes no decision row, as a gate that
  does not defer writes none for it. A request the check never decides, including one cancelled
  by the request deadline, still gets its grant row, after the endpoint; a cancellation that lands
  while a decision row is being written can lose that row. A reveal refused for want of `messages:view_summary` writes
  only its `auth.permission_denied` row, without the monitoring grant row it also had. No request
  is allowed or refused differently. [SECURITY.md](../docs/SECURITY.md) says which refusals still
  follow a grant row. (`BACKLOG #1197`)
