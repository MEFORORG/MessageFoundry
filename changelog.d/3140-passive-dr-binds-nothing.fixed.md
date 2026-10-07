- **A passive DR box binds no inbound listener.** With `[dr].enabled = true` and the box not
  activated, at start or after `POST /dr/release`, no inbound listener binds, of any tier, and each
  reads `status: "filtered"`. It used to bind its whole graph, so the load balancer that ADR 0048
  relies on to move the VIP to the live node would have sent it traffic. `POST /dr/activate` binds
  the feeds at or above `[dr].priority_threshold`, as before. Outbounds are unchanged. A reload or
  dry run on a passive box checks the listeners an activation would bind. An operator start of an
  inbound still binds it; an alert rule's restart and the scheduler do not. (`vault BACKLOG #3140`)
