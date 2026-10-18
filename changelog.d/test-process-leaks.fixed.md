- **Harness engine nodes and the durability-hook tests no longer leave processes behind.** An
  engine a load-harness node starts (`harness.load.failover.EngineNode`, which the connection-scale,
  shard and failover runners use) now sits in a kill-on-close job on Windows, so it and every
  process it starts end with the harness process however that ends, and `stop()`/`kill()` take
  the whole tree. POSIX is unchanged: there they still end only the engine's own process.
  `tests/test_durability_hook_push_bound.py` runs each hook-firing commit in such a job and fails a
  test that leaves a process running. Measured on a developer box before the fix: 54 connscale
  engines up to 16.5 hours old, and suspended `git` processes from the durability tests.
