- **The approvals queue no longer offers Approve on a held reload that names no config digest.**
  Such a release could only be refused, since a reload bound to no digest matches no config, and
  it was refused only after the gate claimed it, so the request ended `failed`. A digest not of
  the form the engine writes now counts as none. `GET /approvals`
  now marks it `release_blocked: "params_no_fingerprint"`, and the gate refuses it before its claim
  with 409 and an `approval.params_no_fingerprint` row, so it stays pending for a reject. The web
  console's Approvals page offers it only Reject or Withdraw, with a note. A queue with no identity
  resolver already showed every request as `requester_not_authorized`; a test now pins it.
  `PendingApprovalInfo.gated` is removed: `release_blocked: "not_gated"` says the same, and the
  console never read it. The web console seam digest moved. (vault `BACKLOG #3192`, `#3193`)
