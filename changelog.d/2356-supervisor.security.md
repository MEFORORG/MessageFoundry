- **The engine-shard supervisor now forwards its own log lines off-box.** `supervise` used to log to
  stdout only, so a shard crash loop or a refused fleet start left no copy off the host. With
  `[logging].forward_host` set, the supervisor process now installs the same syslog forwarder each
  engine shard does. It passes the same start gates as `serve` and refuses to start the fleet on
  the same refusals, with the same messages. Its spool is a `supervisor` directory beside its
  shards' spool directories. With no collector configured, nothing changes.
  (`BACKLOG #2356`)
