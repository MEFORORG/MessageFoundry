- **Every CLI subcommand but `serve` and `supervise` sends a `print()` in an author's config
  module, Router or Handler to stderr.** Before, only `dryrun`, `validate` and `graph` did, each
  by its own wrap, so a debugging print still came ahead of the JSON on stdout under at least
  `check` (its later loads, and the Router and Handlers its dry-run leg runs), `connection`,
  `impact` and `cert inventory`. The CLI shell now marks each subcommand it dispatches, and the
  config loader and the dry-run preview send a print to stderr while the mark is set, so a new
  subcommand is covered without a wrap of its own. Nothing redacts what an author's own print
  writes, so stderr is no safer than stdout. (vault `BACKLOG #3474`)
