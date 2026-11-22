- **The tee relay refuses a Corepoint attempt count or shadow-queue bound below one.**
  `--corepoint-attempts` and `--mefor-queue-max` (and the matching `RelayConfig` fields) now take
  only a positive integer, where one attempt means no retry, and a bad value stops the relay before
  any listener binds. Before, zero attempts would have let the relay ACK an Epic message and then
  fail without forwarding it or tripping fail-closed, and a bound of zero or less would have made
  the shadow queue unbounded. (`BACKLOG #5829`)
