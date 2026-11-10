- **An alert's auto-resolve no longer closes a newer raise of the same alert from another engine
  shard or node.** A resolve waits behind the earlier writes for its alert and its own retries, and
  a raise from another process on the same store in that window was closed by it, so a live
  condition would read as cleared until it fired again. Each raise now records which process wrote
  it, and a resolve closes the alert only when its newest raise is this process's own or it has
  taken no raise since the resolve read it, which happens when the resolve's write task first runs.
  No clock is compared, so clock skew between nodes cannot leave an alert open, and when two
  processes raise and clear the same alert at once, the one that raised last clears it. A resolve
  a newer raise kept open is not reported as landed. The `alert_instance` table gains a nullable
  `raised_by` column on all three store backends, added in place at start. (`BACKLOG #4916`)
