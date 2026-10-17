- **`serve` and `supervise` refuse to start under `enforcement = enforce` when Python remote
  debugging is enabled in their process** (vault BACKLOG #2700, owner ruling 2026-10-16). The
  shipped service launches already pass `-X disable-remote-debug` and are unaffected. A
  console-script start such as `messagefoundry serve` would now refuse; the refusal names the fix,
  `python -P -X disable-remote-debug -m messagefoundry serve ...`, and the named acceptance for the
  developer loop, `[security].allow_remote_debugging = true`, which is reported as a loosening.
