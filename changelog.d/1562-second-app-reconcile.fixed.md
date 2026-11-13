- **A second app over the same engine no longer interrupts the first app's releases.** The startup
  reconcile of `executing` approval rows never moves a row an approval gate in this process
  claimed over that store, whatever order the apps were built and started in. It reads no clock to
  decide this. `POST /approvals/{id}/interrupt` refuses, with 409, a release this process is
  running. A row this process never claimed still moves to `interrupted`, with reason
  `engine_restart`. (`BACKLOG #1562`)
