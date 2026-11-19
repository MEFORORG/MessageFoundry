- **The HA Postgres Kubernetes manifest configures what an enforcing start needs.**
  `docker/k8s/ha-postgres.yaml` runs `serve --env prod` under the default `enforce`, and set none of
  the inputs at least six start gates read, so no replica would have started. It now takes the API
  revocation attestation from the required `tls-revocation-attested` Secret key, sets the alert
  channel, verified-TLS log forwarding with its egress entry, the store CRL and the two retention
  tiers that need a window or an acknowledgement, with `REPLACE` values for a site to fill in, and
  mounts a writable `log-spool` volume for the forwarder, since the pods have no PVC. (`BACKLOG #5934`)
