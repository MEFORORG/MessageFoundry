- **The dependency auditor's `pip` and `pip-audit` get an allowlist environment.**
  `messagefoundry.security.audit_all_platforms` used to hand them everything outside the engine's
  `MEFOR_*` namespace, so a CI token or a secret under any other name reached them. They now get
  what a Python child needs to start, pip's own `PIP_*` variables, and the proxy, certificate,
  `NETRC` and XDG folder variables pip and pip-audit read to reach an index. A variable a keyring
  backend or a cloud credential helper needs is named with `--pass-environment <name>`, given before
  the lock. The deny-list builder `non_engine_environment` is removed. (`BACKLOG #2587`)
- **`[sandbox].pass_environment` and `[dr].pass_environment` refuse `PYTHONINSPECT` at load**, as
  the auditor's `--pass-environment` does: a child started with it set waits at a prompt instead of
  exiting. `PYTHONBREAKPOINT` may still be named,
  so `PYTHONBREAKPOINT=0` reaches the child. (`BACKLOG #2587`)
- **The dependency auditor refuses a word after the lock that holds `=` and is not a pip-audit
  option given as `--option=value`**, naming its position rather than the word, so a
  `NAME=value` typed there never reaches pip-audit's usage error and the CI log. Give a value that
  holds `=` in the `=` form of its option, as `--index-url=URL`. What the auditor prints itself
  withholds what follows the first `=` of every word it was given. (`BACKLOG #2587`)
