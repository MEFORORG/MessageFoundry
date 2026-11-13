- **A second app over the same engine no longer interrupts the first app's releases.** The startup
  reconcile of `executing` approval rows never moves a row an approval gate in this process
  claimed over the same engine's store object, whatever order the apps were built and started in.
  It reads no clock to decide this. `POST /approvals/{id}/interrupt` refuses, with 409, a release
  this process is running. For an unsettled claim of this life, one no gate is running, an
  operator can move it only with `interrupt_stranded`'s `attest_owner_stopped`, an attestation that
  is false while this process runs; otherwise it stays `executing` until the process restarts.
  (`BACKLOG #1562`)
