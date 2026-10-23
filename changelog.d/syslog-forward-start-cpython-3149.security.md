- **From CPython 3.14.9, the off-box syslog forwarder again reports a failed start when the
  collector's name does not resolve.** That release made the standard library's syslog handler
  swallow the lookup error, so the forwarder read as started and the failure surfaced only at the
  first send. The engine now looks the name up again at start, on the UDP, TCP and TLS arms, so a
  name that does not exist is reported as a permanent failure at ERROR, as on earlier interpreters.
  The engine itself still starts, without the forwarder.
