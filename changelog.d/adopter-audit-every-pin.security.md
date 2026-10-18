- **The `audit-pin` job `messagefoundry init` generates now audits the Windows-only dependencies.**
  `pip-audit` skips a dependency whose environment marker does not match the runner, so on
  `ubuntu-latest` the job never audited the engine's Windows-only dependencies (at least `colorama`
  and `sspilib`) on the only supported deployment platform. The job now runs on `windows-latest`, one
  step per command. With a hashed `requirements.lock` it installs the lock under `--require-hashes`
  and runs the engine's own auditor, `python -P -m messagefoundry.security.audit_all_platforms`,
  which audits every pin whatever its marker. That module first ships in the release after 0.5.1,
  and it refuses a lock with pip option lines. See [ADOPTER-CI.md](../docs/ADOPTER-CI.md), Job 3.
