- **`docker/secrets.env.example` now says how to set the store password compose substitution
  checks.** It named only the SQL Server image for `MEFOR_STORE_PASSWORD`. It now says that
  `compose.yaml` checks that variable by substitution on every command that interpolates the
  file, with or without `--profile ha`, so every user must set it in the shell, the project
  `.env` or a file passed with `--env-file`; an `env_file:` entry does not feed it. That value is
  the local `ha` Postgres container's own password, never a reused store password. Under the
  `ha` profile it also goes in `secrets.env`, where the `ha` engines read it; otherwise it is a
  random value kept out of `secrets.env`. (BACKLOG #5400)
