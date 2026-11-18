- **A copy-on-write copy no longer raises while another thread reads the shared message.** When a
  `Message` and its `copy()` were read on two threads, the first write copied the shared tree with
  `copy.deepcopy`. A lazy segment split on the other thread could change the map that copy was
  walking, and the write raised `RuntimeError`. The copy now takes that map in one call, so the
  split lands before or after it. (`BACKLOG #5801`)
