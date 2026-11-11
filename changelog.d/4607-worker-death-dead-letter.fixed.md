- **A row that keeps killing its stage worker is now dead-lettered.** A `BaseException` that is not
  an `Exception` ends a router, transform, response or delivery worker, or a pooled serializer.
  Before this nothing counted it: the row stayed in flight, came back at the next start and killed
  the next worker too. The death is now counted against that row through `mark_failed`, in both
  claim modes. An ingress, routed or response row is re-pended at its lane position and
  dead-lettered, its message `ERROR`, on its third attempt. A one-off death is retried. An outbound
  row's death counts as one more failed send under the lane's own retry policy, so a lane set to
  retry forever (`max_attempts = None`) retries it forever. The worker still dies; respawning a
  pooled serializer and recovering a dead worker's other held rows are not in this change.
  Cancellation is never counted. (`BACKLOG #4607` step 6; owner ruling 2026-11-04)
