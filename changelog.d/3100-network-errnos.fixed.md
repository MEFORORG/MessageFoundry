- **A directory the network cannot reach reads as an outage, not a probe fault.** An
  operating-system error saying the network or host is unreachable or down has no
  `ConnectionError` subclass in Python, so the directory probe read it as an engine fault. That
  paged on `directory-reconciler-probe-fault` and opened an alert nothing resolved. It now reads
  as unreachable, like a connection or timeout error. Any other `OSError` is still a fault.
  (`BACKLOG #3100`)
