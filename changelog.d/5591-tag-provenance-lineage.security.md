- **The release tag gate no longer lets a green check run hide a red or still-running one of the
  same name.** It kept only the newest run per required check, so a green from another workflow or
  trigger, such as a dispatched run, would have cleared a red merge-queue or push run on the tagged
  commit. Now the latest run of every workflow and trigger that ran a required check must pass. A
  re-run of the failed jobs, or a later run of the same workflow on the same trigger, still clears
  a red. A fresh dispatch no longer does. GitHub re-runs a workflow run only within 30 days of it.
  The gate reads every run, not only the newest, and its job gains the `actions: read` scope. This
  supersedes the 0.5.2 note that each check is judged on its latest run.
  [SUPPLY-CHAIN.md](../docs/SUPPLY-CHAIN.md) says how to clear a refusal. (`BACKLOG #5591`)
