- **A `sys.exit()` while a Router, `accepts=` predicate or Handler runs no longer ends the sandbox
  worker.** At `[sandbox].mode = "subprocess"` or `"isolated"` the worker caught only `Exception`,
  so the `SystemExit` ended it. The message still dead-lettered, but its reason read as a worker
  crash, the next message waited for a fresh worker to start, and `sys.exit("...")` had the worker
  print the author's text to its stderr. The worker now reports it as that Router's or Handler's
  error, in the words `mode = "off"` uses, naming an integer exit code and nothing else, and goes on
  serving. A generator Router's body is now run inside the same boundary, and so is the rendering
  of an exception whose `__str__` calls `sys.exit()`. (`BACKLOG #3134`)
