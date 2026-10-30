- **Refused peers, a switched-off signal layer and a restored posture now reach the alert sink.**
  A new `peer_refused_burst` security signal fires when one inbound listener (MLLP, raw TCP, X12,
  HTTP or the DICOM server) refuses `[alerts].security_peer_refusals` peers (default `100`) at its
  `source_ip_allowlist` or a connection cap inside the window, whether or not connection-event
  capture is on. It is keyed on the inbound's name, never the peer's address.
  `[alerts].security_signals = false`, and a detector count of `0`, are now loosenings that
  `GET /security/posture` names; with the layer off the posture detector still runs, so the start
  raises `posture_loosened` naming the switch. A start that records no loosening raises the new
  `posture_restored` inverse, which resolves the open `posture_loosened` alert for the same engine
  process; that alert's key now carries `@node:<id>` or `@shard:<id>` where several engine
  processes share the store. See [CONFIGURATION.md](../docs/CONFIGURATION.md). (`BACKLOG #2613`)
