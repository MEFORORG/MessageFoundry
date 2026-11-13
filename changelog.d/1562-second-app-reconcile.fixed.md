- **A second app over the same engine no longer interrupts the first app's live releases.** The
  startup reconcile of `executing` approval rows skips a release any approval gate in the same
  process is still running. `POST /approvals/{id}/interrupt` refuses one with 409. A row left over
  from an earlier life still moves to `interrupted`. So does a row this process claimed but no
  longer runs and never settled, such as one whose settle writes both failed: a second app's start
  moves it with reason `engine_restart`, though the engine did not restart. (`BACKLOG #1562`)
