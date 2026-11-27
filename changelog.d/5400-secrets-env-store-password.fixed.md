- **`docker/secrets.env.example` now says where the `ha` profile's store password must also go.**
  It named only the SQL Server image for `MEFOR_STORE_PASSWORD`. It now names the Postgres image
  the `ha` engines run, and says to put the same value in the shell environment or the `.env`
  beside `compose.yaml` too, because the local `postgres` service reads it by compose
  substitution, as `docker/README.md` says. (BACKLOG #5400)
