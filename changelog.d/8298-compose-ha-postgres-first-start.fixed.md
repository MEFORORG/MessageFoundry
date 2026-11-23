- **The `ha` Postgres in `docker/compose.yaml` refuses a first start with `./pg-tls` empty,
  and its health check waits for the real server.** With `./pg-tls` empty, or a key Postgres
  would refuse, the first start used to initialize the `mefor-pg` volume without creating the
  `messagefoundry` database, and every later start skipped initialization. The service's
  entrypoint now checks that the certificate and key its command names exist, are not empty
  and are readable by the postgres account, and that the key is not encrypted and has an owner
  and mode Postgres accepts. It exits naming what is wrong before the image's entrypoint runs,
  so that start initializes nothing. A command that does not start the server passes straight
  through. The health check now probes over TCP on
  127.0.0.1 and queries the `messagefoundry` database, where it used to probe the Unix socket,
  which the image's temporary initialization server answers on, and passed with the database
  missing, and it has a start period for the first initialization. A fault the check does not
  catch still half-initializes the volume, and the health check then keeps every engine from
  starting against it; the postgres service's comment in `docker/compose.yaml` names at least
  those faults and the recovery. (`BACKLOG #8298`)
