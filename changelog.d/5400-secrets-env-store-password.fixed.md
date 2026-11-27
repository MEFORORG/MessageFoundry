- **`docker/secrets.env.example` now says the store password also goes where compose
  substitution reads.** It named only the SQL Server image for `MEFOR_STORE_PASSWORD`. It now
  names the Postgres image the `ha` engines run, and says that the local `postgres` service reads
  the same variable by compose substitution, which `secrets.env` does not feed. Whenever a
  compose command interpolates the file, with or without `--profile ha`, that value must be the
  real store password and never a placeholder: Postgres takes it as its role's password when it
  initialises an empty data directory, which any command that starts `postgres` can trigger,
  including through `depends_on`. The database role's password must equal the value the `ha`
  engines read from `secrets.env`. It points at that variable's message in `compose.yaml` and at
  `docker/README.md`. (BACKLOG #5400)
