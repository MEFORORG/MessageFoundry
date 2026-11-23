- **The `ha` Postgres in `docker/compose.yaml` refuses a first start it would half-initialize,
  and its health check waits for the real server.** With `./pg-tls` empty, or a key Postgres
  would refuse, the first start used to initialize the `mefor-pg` volume without creating the
  `messagefoundry` database, and every later start skipped initialization. The service's
  entrypoint now checks the certificate and key its command names, their owner and mode, and
  that the postgres account can read them, and exits naming what is wrong before the image's
  entrypoint runs, so nothing is initialized. The health check now probes over TCP on
  127.0.0.1 and queries the `messagefoundry` database, where it used to probe the Unix socket,
  which the image's temporary initialization server answers on, and passed with the database
  missing. A key that does not match its certificate still passes the entrypoint check; that
  start leaves the volume half-initialized, and the health check now keeps every engine from
  starting against it. (`BACKLOG #8298`)
