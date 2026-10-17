- **A sandbox worker that loaded edited config code is refused.** The engine already refused a
  `[sandbox].mode = "subprocess"` worker whose graph had different names. It now also compares a
  digest of the bytes of every `*.py` in the config directory, as each side loaded it. So after a
  config file is edited on disk with no reload, the next worker that starts is refused, instead
  of running a Router or Handler body nobody reloaded. Under the default
  `internal_error = "continue"` each message on that inbound dead-letters with an error naming
  `config module content`; under `"stop"` the inbound stops. A load whose config modules change
  while it runs is refused too. Reload the config.
  [CONFIGURATION.md](../docs/CONFIGURATION.md) says, under `[sandbox]`, what an operator sees
  meanwhile: no alert fires under the default `internal_error = "continue"`. The spawn guard in
  `tests/test_child_process_environment.py` now also refuses an environment dict that is changed
  after a builder made it, and `worker_environment()` takes `defaults=` for the one value the
  sandbox used to set afterwards. (vault `BACKLOG #2724`)
