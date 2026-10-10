- **uvicorn and websockets are pinned exactly, to `uvicorn==0.54.0` and `websockets==17.2`.**
  Release 0.5.1 declared `uvicorn>=0.29,<0.50` and `websockets>=16.0`, and locked uvicorn 0.49.0
  and websockets 17.1. The protocol header floor overrides internals of both. Its wire suite
  drives only the pinned versions, and a range let an install take a release nobody had read. A
  new test holds the pins equal to the versions the wire suite measured. The startup self-test
  still runs on whatever is installed.

  The pins have a cost. A site cannot take a newer uvicorn or websockets, a security fix
  included, without a new MessageFoundry release. Since 0.5.1, Dependabot's ignore range for
  uvicorn has moved from `>=0.50.0` to `>=0.55.0`, and websockets gained one at `>=17.3.0`. Each
  starts at the next minor after its pin. Dependabot opens no security PR in either range.
  `pip-audit` over the lock still reports an advisory. (`BACKLOG #1120`)
