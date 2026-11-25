- **A UDP log forwarder's socket is rebuilt after a failed send.** A UDP socket was never rebuilt
  after a failed send, so one that went bad stayed bad; it is now rebuilt by the next send when it
  is at least 30 seconds old and the failure was not a name lookup. (`BACKLOG #5923`)
