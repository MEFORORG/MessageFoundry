- **A second app over the same engine no longer interrupts the first app's releases.** The startup
  reconcile of `executing` approval rows skips a release any gate in the process is running. A
  second app's reconcile also skips rows claimed since the process's first approval gate over that
  store was built. `POST /approvals/{id}/interrupt` refuses a running release with 409. A row left
  over from an earlier life still moves to `interrupted`, with reason `engine_restart`.
  (`BACKLOG #1562`)
