- **`docker/secrets.env.example` now says the store password also goes where compose
  substitution reads.** It named only the SQL Server image for `MEFOR_STORE_PASSWORD`. It now
  names the Postgres image the `ha` engines run, says the local `postgres` service reads the same
  variable by compose substitution, which `secrets.env` does not feed, and points at that
  variable's message in `compose.yaml` and at `docker/README.md`. It also says Postgres takes the
  password only when it first creates its volume. (BACKLOG #5400)
