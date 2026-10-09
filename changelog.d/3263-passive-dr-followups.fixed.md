- **A passive DR box shows a broken critical feed at start, and an activation can fail one
  outbound without refusing the takeover.** At start a box with `[dr].enabled = true` that is
  not activated reads the `tls_ca_file` of each outbound and each FTPS poller an activation would start, except an outbound another engine shard owns. It does not read a listener's client-verification CA. A refused one
  reads `status: "failed"` and alerts. It builds, binds and dials nothing to do so. At
  `POST /dr/activate`, an outbound whose CA pin, ACL or path check or `validate_directory`
  check fails is failed on its own and keeps its rows queued, and the rest start. It stays
  parked, and still pages its buildup and stall checks, until a reload or an operator start
  builds it; neither the scheduler nor an alert rule's restart resumes it. Such a CA
  used to refuse the whole activation, and the `validate_directory` check never ran. At least a
  CA file that is missing or does not parse, a connector that does not build, and an unresolved `env()` value, still refuse the
  activation. A failed or cancelled activation now unbinds the listeners the attempt bound. A
  release cut short while it closed outbound sessions is still recorded as a release; the
  engine and the DR coordinator used to disagree about it. An activation while the application
  log is unwritable no longer leaves outbounds answering `409` "activate DR first" once the log
  is repaired. (`vault BACKLOG #3263`)
