- **A directory rename now commits with its audit row, or not at all.** The
  `auth.ad_username_refreshed` row used to be written after the rename had committed, so a refused
  write left the account under its new name with no row, and no later refresh wrote one. The row
  now commits in the rename's own transaction on all three store backends, and only when the rename
  lands. If the row is refused, the rename rolls back. On a sign-in that refusal still fails the
  sign-in. On a reconciler pass it is logged at ERROR and the pass goes on. A later pass that
  probes the account would apply the rename, with its row and its notice, unless it is refused
  again or the name is taken.
