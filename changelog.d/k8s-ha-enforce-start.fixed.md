- **The HA Postgres Kubernetes manifest names what an enforcing start needs.**
  `docker/k8s/ha-postgres.yaml` runs `serve --env prod` under the default `enforce`, and set none of
  the inputs at least six start gates read, and named none of them. It now takes the API revocation
  attestation from the required `tls-revocation-attested` Secret key, names the alert channel,
  verified-TLS log forwarding with its egress entry, the store CRL and the two retention tiers that
  need a window or an acknowledgement as commented entries a site fills in, and mounts a writable
  `log-spool` volume for the forwarder, since the pods have no PVC. The entries ship commented, so an
  unedited manifest is still refused rather than started with placeholder channels. (`BACKLOG #5934`)
