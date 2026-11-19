- **The container image has a Postgres variant.** `docker/Dockerfile` gains a `runtime-postgres`
  target that installs the new hash-locked `docker/locks/requirements-postgres.lock`, which carries
  `asyncpg`. The slim default carries none, so the `ha` compose profile and
  `docker/k8s/ha-postgres.yaml`, which run the Postgres store, could not open it. The `ha` profile now
  runs `messagefoundry:postgres`, the HA manifest names that base, and the DEP-1 export, the Dependabot
  resync and the Windows lock install cover the new lock. The `ha` profile still sets none of the
  alert, log-forwarding and retention inputs an enforcing start needs. (`BACKLOG #5933`)
