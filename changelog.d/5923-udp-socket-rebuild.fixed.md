- **A UDP log forwarder's socket is rebuilt after a failed send.** A UDP socket was never rebuilt
  after a failed send, so one that went bad stayed bad. After a send that fails with a network
  error other than a failed name lookup, the next send now builds a new socket when the old one is
  at least 30 seconds old. (`BACKLOG #5923`)
