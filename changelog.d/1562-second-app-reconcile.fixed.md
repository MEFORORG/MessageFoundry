- **A second app over the same engine no longer interrupts the first app's live releases.** The
  startup reconcile of `executing` approval rows leaves alone a release any approval gate in the
  same process is still running, so a second `create_app` lifespan over one engine keeps the first
  app's release `executing`. A row left over from an earlier life still moves to `interrupted`.
  (`BACKLOG #1562`)
