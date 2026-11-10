- **An alert's auto-resolve no longer closes a newer raise of the same alert from another engine
  shard or node.** A resolve waits behind the earlier writes for its alert and its own retries, and
  a raise from another process on the same store in that window was closed by it, so a live
  condition would read as cleared until it fired again. The resolve now closes only the raises
  that had landed when it was emitted, and this process's own earlier raises, by the alert's
  occurrence count, with no clock compared, so clock skew between nodes cannot leave an alert open.
  (`BACKLOG #4916`)
