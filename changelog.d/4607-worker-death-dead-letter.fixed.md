- **A row that keeps killing its stage worker is now dead-lettered.** A custom `BaseException` that
  is not an `Exception` ends a router, transform, response or delivery worker, or a pooled
  serializer. Before this nothing counted it: the row stayed in flight, came back at the next start
  and killed the next worker too, without end. An ingress, routed or response row now counts each
  death in a new per-row `worker_deaths` column, and the third dead-letters it, its message
  `ERROR`. No claim raises that count, so a row claimed in the same batch as the dying one is never
  counted, and a crash or stop mid-row never adds to it. Below the cap the row stays in flight,
  paged by the in-flight watch, until the next start. "Every time" means across passes that each
  claim the row anew, after a restart or a Postgres lease reclaim: a respawned worker does not yet
  re-claim the row its predecessor died on. An outbound row counts a death as a failed send under its lane's
  retry policy, so a lane set to retry forever never dead-letters on a death; a batching outbound
  lane does not count deaths yet. A death on a lane a
  pooled dispatcher drains fires `connection_stopped`. `KeyboardInterrupt`, `SystemExit`,
  `CancelledError` and `GeneratorExit` are never counted, and the worker still dies. A replay resets
  the count with `attempts`. `mark_failed` at its cap now leaves a row already DONE, DEAD or
  CANCELLED as it is (ADR 0157 Amendment C). (`BACKLOG #4607` step 6; owner rulings 2026-11-04
  and 2026-11-11)
