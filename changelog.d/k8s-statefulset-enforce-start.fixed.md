- **The single-node Kubernetes manifest names what an enforcing start needs.**
  `docker/k8s/statefulset.yaml` runs `serve --env prod` under the default `enforce`, and set none of
  the inputs at least five start gates read, and named none of them. It now takes the API revocation
  attestation from a required `tls-revocation-attested` Secret key, and names the alert channel,
  verified-TLS log forwarding with its egress entry, and the two retention tiers that need a window or
  an acknowledgement as commented entries a site fills in. They ship commented, so an unedited
  manifest is still refused rather than started with placeholder channels. (`BACKLOG #5935`)
