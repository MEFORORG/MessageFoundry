- **A row that keeps killing its stage worker is now dead-lettered.** A `BaseException` that is not
  an `Exception` ends a router, transform, response or delivery worker, or a pooled serializer.
  Before this nothing counted it: the row stayed in flight, came back at the next start and killed
  the next worker too, without end. Each death is now counted in the row's `attempts`, in both
  claim modes, and a death that finds the count at its cap dead-letters the row through
  `mark_failed`, its message `ERROR`. The cap is 3 for an ingress, routed or response row. That
  count also holds other passes that never resolved the row, such as a crash or stop mid-row or a
  STOP-policy re-pend, so a row with such a history can be dead-lettered on its first death; a row
  with none survives one death. Below the cap nothing is written: the row stays in flight, paged by
  the in-flight watch, until the next start. An outbound row's cap is the lane's own
  `max_attempts`, since its count also holds failed sends, so a lane set to retry forever
  (`max_attempts = None`) never dead-letters on a death. A death on a lane a pooled dispatcher
  drains fires `connection_stopped`, since that serializer is not respawned and the lane waits for
  the next start. The worker still dies. A batching outbound lane is not covered, and cancellation
  is never counted. (`BACKLOG #4607` step 6; owner ruling 2026-11-04)
