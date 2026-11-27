- **`docker/secrets.env.example` now says the store password also goes where compose
  substitution reads.** It named only the SQL Server image for `MEFOR_STORE_PASSWORD`. It now
  names the Postgres image the `ha` engines run, and says that the local `postgres` service reads
  the same variable by compose substitution, which `secrets.env` does not feed, and that every
  `docker compose` command checks it, with or without `--profile ha`. Without that profile any
  non-empty value passes; under it the two values must match. It points at that variable's
  message in `compose.yaml` and at `docker/README.md`, and says Postgres reads the password only
  when it initialises an empty data directory. (BACKLOG #5400)
