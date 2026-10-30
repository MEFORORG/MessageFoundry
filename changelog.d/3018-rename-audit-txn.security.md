- **A directory rename now commits with its audit row, or not at all.** The
  `auth.ad_username_refreshed` row used to be written after the rename had committed, so a refused
  write left the account under its new name with no row, and no later refresh wrote one. The row
  now commits in the rename's own transaction on all three store backends, and only when the rename
  lands. If the row is refused, the rename rolls back. On a sign-in that refusal still fails the
  sign-in. On a reconciler pass it is logged at ERROR and the pass goes on. The engine would apply
  it on a pass or sign-in that reaches the rename and is not refused, with its row and its notice.
