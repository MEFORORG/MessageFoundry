- **A DR takeover hook that runs past `[dr].takeover_timeout_seconds` is now killed, with the
  processes it started.** The timeout used to stop only the engine's wait. The
  shell and its children ran on, so a takeover hook could still take the address after the
  activation was recorded as aborted. The hook now starts as the root of a tree the engine can kill:
  a kill-on-close job object on Windows, which the hook joins before it runs, and its own process
  group elsewhere. The sandbox worker's tree kill moved into the same shared module. Some processes
  still escape; `[dr].takeover_timeout_seconds` in [CONFIGURATION.md](../docs/CONFIGURATION.md)
  names them. A release hook that overruns, and a hook that finishes on its own, are left
  alone, as before. (`BACKLOG #2622`)
