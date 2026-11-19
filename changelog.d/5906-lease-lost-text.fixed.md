- **A cluster node that lost its lease no longer says its graph is down, or points at a start it
  refuses.** On a node whose lease is gone while its graph still runs, an alert rule's restart is
  logged as not run because the node no longer holds the cluster lease, where it said the graph
  was not running. A resend into a stopped outbound, and an upload resend into a stopped inbound,
  is refused with a 409 that says to resend through the leader, where it said to start the
  connection first, a start that node refuses. The upload resend's 409 on a downed graph now says
  the graph is not running too. (`BACKLOG #5906`)
