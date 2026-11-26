- **A directory rename whose account record's seal is refused at the write no longer ends the
  reconcile pass.** The record verified when the refresh read it, then the store refused the write
  over its seal: the record no longer passed it, or Vault transit could not verify it or did not
  answer. That refusal ended the pass, so the renames after it were skipped and the pass's
  refused-row pages were lost. The reconciler now logs a seal failure or an unverifiable record at
  ERROR, reports it as an admin read reports the same answer, and goes on. A Vault transit outage,
  at the write or at one of the rename's reads, is paged once and stops the pass's renames; the
  rest of the pass still runs and returns its plan. An unverifiable record at one of the rename's
  reads skips that rename, logged at ERROR. A sign-in that meets the same refusal still fails.
  (`vault BACKLOG #3069`)
