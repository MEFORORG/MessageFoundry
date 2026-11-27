- **From CPython 3.14.9, the off-box syslog forwarder again reports a failed start when the
  collector's name does not resolve.** That release made the standard library's syslog handler
  swallow the lookup error, so the forwarder read as started and the failure surfaced only at the
  first send. The engine now connects once the handler is built, outside that swallow, on the UDP,
  TCP and TLS arms, with one lookup, so a name that does not exist is reported as a permanent
  failure at ERROR, as on earlier interpreters. A temporary lookup failure is deferred to the spool
  when one is configured and, as on earlier interpreters, skips the forwarder when none is. The
  engine itself still starts, without the forwarder.
