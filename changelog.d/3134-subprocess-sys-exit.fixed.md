- **A `sys.exit()` in a Router, `accepts=` predicate or Handler no longer ends the sandbox worker.**
  At `[sandbox].mode = "subprocess"` or `"isolated"` the worker caught only `Exception`, so the
  `SystemExit` ended it. The message still dead-lettered, but its reason read as a worker crash, the
  next message waited for a fresh worker to start, and `sys.exit("...")` had the worker print the
  author's text to its stderr. The worker now reports it as a handler error in the words
  `mode = "off"` uses, naming an integer exit code and nothing else, and goes on serving.
  (`BACKLOG #3134`)
