- **An ECH sidecar address must now be listed in `[egress].allowed_ech_sidecar`.** A REST
  connection that sets `ech_egress` sends every request, credential headers included, to its
  loopback sidecar, and the egress check judged only the upstream `url`. So any port on this host
  could have been named as the sidecar. The new list takes `host:port` entries, port required, and
  is deny-by-default even under `[security].block_unlisted_outbound = false`: an `ech_egress`
  connection whose sidecar is not on it is refused at config load. List the sidecar, for example
  `allowed_ech_sidecar = ["127.0.0.1:8123"]`. See the key's row under `[egress]` in
  [CONFIGURATION.md](../docs/CONFIGURATION.md#egress).
