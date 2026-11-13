- **A second app over the same engine no longer interrupts the first app's releases.** The startup
  reconcile of `executing` approval rows moves only rows claimed before this process's first
  approval gate over that store was built. It also skips a release any gate in the process is
  running. `POST /approvals/{id}/interrupt` refuses such a release with 409. A row left over from
  an earlier life still moves to `interrupted`, with reason `engine_restart`. (`BACKLOG #1562`)
