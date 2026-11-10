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
- **The dependency auditor refuses, without quoting it, a word that pip-audit's or its own usage
  error would print with a value typed into it.** After the lock: its own `--skip-private` and
  `--pass-environment`, in full or by an abbreviation that is not also one of a pip-audit option
  (`--pas` and `--skip-p` are refused; `--pa` and `--skip` reach pip-audit as `--path` and
  `--skip-editable`), with or without `=`, which go before the lock; and any other word holding `=`
  that is not a pip-audit option taking a value, named in full and given as `--option=value`.
  Before the lock: a lock path or `--skip-private` entry holding `=`. Once any word holds `=`, an
  argparse usage error prints no reason, since its reason can quote that word. A free-text value
  that holds `=`, such as `--index-url=URL` or `--ignore-vuln=ID`, still reaches pip-audit, which
  can print it in its own output, at least in its `--verbose` debug line of the arguments it
  parsed. (`BACKLOG #2587`)
- **The dependency auditor refuses, after the lock, a pip-audit option that would end it with
  exit 0 and no audit**: `--dry-run`, `-d`, `--fix`, `--help`, `-h`, `--version` and `-V`, in
  full, abbreviated, or inside a cluster of short flags. The refusal names the word's position.
  (`BACKLOG #2587`)
