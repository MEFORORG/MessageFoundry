- **A warning logged before a `messagefoundry` subcommand's log handlers exist is now redacted.**
  The PHI-filtered stand-in for the standard library's `logging.lastResort` used to be installed
  near the start of `serve` only. The `main()` of `messagefoundry` and of `messagefoundry-toolkit`
  now installs it before it parses the arguments, so argument parsing and the start of `supervise`
  are covered too. A record logged while the modules import, before `main()` runs, still meets the
  standard library's own; `docs/PHI.md` section 7 row 1 lists what stays unfiltered. For a caller
  that runs `main()` in process on a root logger with no handler, the process-wide `lastResort`
  stays replaced after `main()` returns. Assigning a stream to the filtered one, as `setStream`
  does, now raises `AttributeError`, as it does on the standard library's, instead of being
  ignored.
