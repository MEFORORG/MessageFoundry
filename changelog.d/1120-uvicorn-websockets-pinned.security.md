- **uvicorn and websockets are pinned exactly, to `uvicorn==0.54.0` and `websockets==17.2`.** They
  were ranges, `>=0.29,<0.55` and `>=16.0,<18`. The protocol header floor overrides internals of
  both, and its wire suite drives only those two versions, so a range let an install take a
  release nobody had read. A new test holds the pins equal to the versions the wire suite
  measured. The lock already resolved to both versions, so no installed package changes. The
  Dependabot ignore range for websockets moves to `>=17.3.0`, the next minor after the pin, the
  same rule the other exact pins follow. The startup self-test still runs on whatever is installed.
  (`BACKLOG #1120`)
