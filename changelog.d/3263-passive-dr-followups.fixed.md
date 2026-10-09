- **A passive DR box shows a broken critical feed at start, and an activation fails one outbound
  for it, not the takeover.** At start a box with `[dr].enabled = true` that is not activated
  reads the CA file of each connection an activation would start. A refused one reads
  `status: "failed"` and alerts. It builds, binds and dials nothing to do so. At
  `POST /dr/activate`, an outbound whose CA, build or `validate_directory` check fails is failed
  on its own, and the rest start. Such a CA used to refuse the whole activation, and the
  `validate_directory` check never ran. A failed or cancelled activation now leaves no listener
  bound. A release cut short while it closed outbound sessions is still recorded as a release;
  the engine and the DR coordinator used to disagree about it. An activation while the
  application log is unwritable no longer leaves outbounds answering `409` "activate DR first"
  once the log is repaired. **Breaking:** `[dr].enabled` with `[cluster].enabled` is now refused
  at load, as `[dr].activate` already was. (`vault BACKLOG #3263`)
