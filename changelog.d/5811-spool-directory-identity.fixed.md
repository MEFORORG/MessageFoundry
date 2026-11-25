- **The log forwarder's spool no longer retires its segments when its path names another
  directory, and keeps a link segment whose target is out of reach.** An empty mountpoint left by a
  dropped mount, or a directory replaced at the spool's path, made every segment read as gone, so
  one read took every undelivered segment out of the replay order. The spool now compares the
  directory's device and inode with the ones it locked and reads a mismatch as a read fault that
  retires nothing. A segment that is a link to a target out of reach just now is passed over and
  kept, where it was unlinked, and a start indexes such a link rather than refusing the spool, so
  a later start replays it once the target is back. A DFS or share failover that briefly reports a
  live segment gone in the same directory can still take it out of the order; its file is kept,
  and the next start replays it. (`BACKLOG #5811`)
