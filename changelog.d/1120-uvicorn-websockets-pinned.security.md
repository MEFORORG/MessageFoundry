- **uvicorn and websockets are pinned exactly, to `uvicorn==0.54.0` and `websockets==17.2`.**
  Release 0.5.1 declared `uvicorn>=0.29,<0.50` and `websockets>=16.0`. The protocol header floor
  overrides internals of both. Its wire suite drives only these two versions, and a range let an
  install take a release nobody had read. A new test holds the pins equal to the versions the
  wire suite measured. The lock already resolved to both, so no locked package changes. The
  startup self-test still runs on whatever is installed.

  The pins have a cost. A site cannot take a newer uvicorn or websockets, a security fix
  included, without a new MessageFoundry release. Dependabot's ignore range for websockets moves
  to `>=17.3.0`, the next minor after the pin, so it opens no security PR for 17.3 or later.
  `pip-audit` over the lock still reports an advisory. (`BACKLOG #1120`)
