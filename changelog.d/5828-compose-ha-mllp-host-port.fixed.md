- **`docker compose --profile ha up` no longer fails on a host port collision.** The default
  `engine`, which has no profile and so starts under `--profile ha` too, and `engine-ha` both
  published host port 2575. `engine-ha` now publishes its MLLP listener on host port 2578.
  (`BACKLOG #5828`)
