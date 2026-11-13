- **A second app over the same engine no longer interrupts the first app's releases.** The startup
  reconcile of `executing` approval rows never moves a row an approval gate in this process
  claimed over the same engine's store object, whatever order the apps were built and started in.
  It reads no clock to decide this. `POST /approvals/{id}/interrupt` refuses, with 409, a release
  this process is running, and moves with no attestation one whose claim this process holds
  under its own owner and no longer runs. (`BACKLOG #1562`)
