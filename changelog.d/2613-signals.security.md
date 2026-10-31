- **Refused peers, a switched-off signal layer and a restored posture now reach the alert sink.**
  A new `peer_refused_burst` security signal fires when one inbound listener (at least MLLP, raw
  TCP, X12, HTTP and the DICOM server) refuses `[alerts].security_peer_refusals` connections
  (default `100`, at most `100000`) at its `source_ip_allowlist` or a connection cap inside the
  window, whether or not connection-event capture is on, and then stays quiet for that listener
  for the window, at most 300 s. It is keyed `inbound:<name>`, never the peer's address.
  `[alerts].security_signals = false`, a detector count of `0` or above its default, and a
  shorter `security_window_seconds` while any count is above `0`, are now loosenings that
  `GET /security/posture` names; with the layer off the posture detector still runs, so the start
  raises `posture_loosened` naming the switch. A start that records no loosening raises the new
  `posture_restored` inverse, which resolves the open `posture_loosened` alert for the same engine
  process; that alert's key now carries `@node:<id>` or `@shard:<id>` where several engine
  processes share the store, and an unpinned cluster node raises the inverse for its own as it
  shuts down. When that alert can still stay open, and how an operator resolves it, is in
  [SECURITY.md](../docs/SECURITY.md). See [CONFIGURATION.md](../docs/CONFIGURATION.md).
  (`BACKLOG #2613`)
