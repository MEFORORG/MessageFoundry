- **The single-node Kubernetes manifest configures what an enforcing start needs.**
  `docker/k8s/statefulset.yaml` runs `serve --env prod` under the default `enforce`, and set none of
  the inputs at least five start gates read, so its pod would have been refused. It now takes the API
  revocation attestation from a required `tls-revocation-attested` Secret key, and sets the alert
  channel, verified-TLS log forwarding with its egress entry, and the two retention tiers that need a
  window or an acknowledgement, with `REPLACE` values for a site to fill in. (`BACKLOG #5935`)
