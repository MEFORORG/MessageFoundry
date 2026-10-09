- **The engine-shard supervisor now forwards its own log records off-box.** `supervise` used to
  log to stdout only, so an engine shard crash loop left no copy off the host. With
  `[logging].forward_host` set, the supervisor process now installs the same syslog forwarder each
  engine shard does. It passes the same forwarding start gates as `serve` and refuses to start
  the fleet on those refusals, with the same messages. It does not run every `serve` gate, and a
  refusal it prints to stderr is still not forwarded. Its spool is a `supervisor` directory
  beside its engine shards' spool directories. With no collector configured it installs no
  forwarder. Under the default `enforce` it then refuses the fleet at once, where each engine
  shard used to refuse on its own; under `warn` it prints the warning and starts.
  `supervise` now also runs, in `serve`'s words, settings checks each engine shard makes.
  At least these refuse the fleet: no environment named, an `--env` name the settings
  refuse, a custom environment with no production tier, the SQL Server backend without its
  driver, and `[logging].level = "DEBUG"` on a production instance. At least these refuse
  under `enforce` and warn under `warn`: `[store].require_managed_identity`, the
  service-settings half of `[security].require_nonstatic_credentials`, and the open-egress
  gate.
  (`BACKLOG #2356`)
