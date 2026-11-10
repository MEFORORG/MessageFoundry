- **A JSON gate that adds checks of its own now writes its `auth.permission_granted` row only once
  those checks pass, and writes `auth.gate_refused` when one refuses.** At least `require_paced`,
  `require_phi_read` and the four step-up gates checked the permission, wrote the grant row, and
  only then ran their pacing, new-address and step-up checks. So in the shipped code a request one
  of those checks refused would have left a grant row and no refusal row. The refusal row names the
  same permission and a `reason` of `throttled` or `step_up`, and is written only where the grant
  row would have been, so it adds no rows. A second-factor refusal in one of those gates writes
  `auth.mfa_denied`, as the base gate's does. No request is allowed or refused differently. A
  refusal a route body makes after its gate has passed, such as a step-up proof the route spends
  itself, still follows a grant row. [SECURITY.md](../docs/SECURITY.md) says which gates do this.
  (`BACKLOG #1197`)
