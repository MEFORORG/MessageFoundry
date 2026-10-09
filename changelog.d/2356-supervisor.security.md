- **The engine-shard supervisor now forwards its own log records off-box.** `supervise` used to
  log to stdout only, so an engine shard crash loop left no copy off the host. With
  `[logging].forward_host` set, the supervisor process now installs the same syslog forwarder each
  engine shard does. It passes the same forwarding start gates as `serve` and refuses to start
  the fleet on those refusals, with the same messages. It does not run every `serve` gate, and a
  refusal it prints to stderr is still not forwarded. Its spool is a `supervisor` directory
  beside its engine shards' spool directories. With no collector configured it installs no
  forwarder. Under the default `enforce` it then refuses the fleet at once, where each engine
  shard used to refuse on its own; under `warn` it prints the warning and starts.
  (`BACKLOG #2356`)
