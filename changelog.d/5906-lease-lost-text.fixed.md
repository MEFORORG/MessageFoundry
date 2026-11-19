- **A cluster node that lost its lease no longer says its graph is down, or points at a start it
  refuses.** On a node whose lease is gone while its graph still runs, an alert rule's restart is
  logged as not run because the node no longer holds the cluster lease, where it said the graph
  was not running. A resend into a stopped outbound is refused with a 409 that says to resend
  through the leader, where it said to start the connection first, a start that node refuses. An
  upload resend into a stopped inbound on such a node, or on one whose graph is down, is refused
  with a 409 saying that this node refuses the resend, where it said to start the inbound.
  (`BACKLOG #5906`)
