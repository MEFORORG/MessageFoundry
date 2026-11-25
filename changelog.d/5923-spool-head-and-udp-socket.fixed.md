- **A spooled log record a TCP or TLS collector refuses no longer holds every later one behind
  it, and a UDP forwarder's socket is rebuilt after a failed send.** A collector that closes the
  connection on one frame, one over its size limit for example, failed that send on every retry,
  so the record stayed at the spool head and nothing behind it was sent. After 5 failures in a
  row where the collector closed or reset a connection it had accepted, the record is now dropped
  as undeliverable, counted in `undeliverable` and reported in a throttled ERROR line with no
  record content; a failed connect, or a send that fails another way, a timeout included, between
  the tries starts the count over, so a collector that is down or not answering still keeps every
  record. A UDP socket was never rebuilt after a failed send, so one that went bad stayed bad;
  it is now rebuilt by the next send when it is at least 30 seconds old and the failure was not a
  name lookup. (`BACKLOG #5923`)
