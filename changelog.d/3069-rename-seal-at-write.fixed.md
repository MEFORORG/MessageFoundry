- **A directory rename whose account record fails its integrity check at the write no longer ends
  the reconcile pass.** The record verified when the refresh read it, then the store refused the
  write because the record no longer passed its seal, and that refusal ended the pass, so the
  renames after it were skipped and the pass's refused-row pages were lost. The reconciler now
  logs it at ERROR, reports the record as a seal failure, pages it with the pass's other refused
  rows, and goes on. A sign-in that meets the same refusal still fails. (`vault BACKLOG #3069`)
