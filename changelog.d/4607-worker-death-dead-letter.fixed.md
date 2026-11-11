- **A row that keeps killing its stage worker is now dead-lettered.** A `BaseException` that is not
  an `Exception` ends a router, transform, response or delivery worker, or a pooled serializer.
  Before this nothing counted it: the row stayed in flight, came back at the next start and killed
  the next worker too. The death is now counted against that row through `mark_failed`, in both
  claim modes, in the row's `attempts`. An ingress, routed or response row is dead-lettered, its
  message `ERROR`, once a death finds its `attempts` at 3. That count also holds other passes that
  never resolved the row, such as a crash or stop mid-row or a STOP-policy re-pend, so a row with
  such a history can be dead-lettered on its first death; a row with none survives one death.
  Below the cap, a per_lane worker's row is re-pended at its lane position; a pooled serializer's
  row stays in flight, where the in-flight watch pages its wedged lane, until the next start. An
  outbound row's death counts as one more failed send under the lane's own retry policy, so a lane
  set to retry forever (`max_attempts = None`) retries it forever. The worker still dies; respawning
  a pooled serializer and recovering a dead worker's other held rows are not in this change. A
  batching outbound lane is not covered, and cancellation is never counted. (`BACKLOG #4607` step 6;
  owner ruling 2026-11-04)
