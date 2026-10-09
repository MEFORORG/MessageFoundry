- **The off-box log collector is now an `[egress]` destination.** `[logging].forward_host` named an
  outbound destination that no `[egress]` list governed. The new `[egress].allowed_syslog` list
  takes `host` or `host:port` entries, like `allowed_tcp`, and follows the same empty-list rule:
  under the deny default a configured collector that is not listed is refused, and under
  `[security].block_unlisted_outbound = false` an empty list is unrestricted. `serve` and
  `supervise` check it at start, before the forwarder opens a socket, and exit 2 on a refusal.
  **Breaking:** an instance that forwards its logs must now list its collector, for example
  `allowed_syslog = ["siem.hospital.local:6514"]` or `MEFOR_EGRESS_ALLOWED_SYSLOG`. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md#egress). (`BACKLOG #2356`)
