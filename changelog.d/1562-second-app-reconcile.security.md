- **A second app over the same engine no longer interrupts the first app's live releases.** No
  startup or put-off reconcile of `executing` approval rows moves, and `POST
  /approvals/{id}/interrupt` refuses with 409, a release any approval gate in the same process is
  running. (`BACKLOG #1562`)
