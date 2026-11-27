- **The compose `ha` engines now log in to Postgres with the password the Postgres service reads.**
  `docker/compose.yaml`'s `postgres` service read `POSTGRES_PASSWORD` by compose substitution of
  `MEFOR_STORE_PASSWORD`, while `engine-ha`, `engine-standby` and `schema-provision` took
  `MEFOR_STORE_PASSWORD` only from `env_file: ./secrets.env`, so the two could differ and the
  engines would then fail at store login. All four now alias one required substitution, the new
  `x-store-password` anchor, with no default, and a `MEFOR_STORE_PASSWORD` line in `secrets.env`
  feeds only the default `engine`. The `x-ha-engine-env` comment in `compose.yaml` names at least
  some of what can still split them. The `compose-ha-smoke` job now writes a different decoy password into
  `secrets.env`, so an `ha` engine that read it would fail the job. (BACKLOG #5400)
