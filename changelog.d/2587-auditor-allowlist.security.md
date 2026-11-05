- **The dependency auditor's `pip` and `pip-audit` get an allowlist environment.**
  `messagefoundry.security.audit_all_platforms` used to hand them everything outside the engine's
  `MEFOR_*` namespace, so a CI token or a secret under any other name reached them. They now get
  what a Python child needs to start, pip's own `PIP_*` variables, and the proxy, certificate,
  `NETRC` and XDG folder variables pip and pip-audit read to reach an index. The deny-list builder
  `non_engine_environment` is removed. (`BACKLOG #2587`)
