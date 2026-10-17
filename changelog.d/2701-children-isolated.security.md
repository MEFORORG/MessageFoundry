- **The engine's Python children repeat its isolation.** The sandbox worker, each engine shard
  under `supervise`, the config check `supervise` runs first and the tray's branded relaunch now
  start with their parent's own `-I`, or its `-E` and `-s`, ahead of `-P -X disable-remote-debug`.
  Under the shipped service launch they are isolated, so a `PYTHONPATH` or `PYTHONHOME` in the
  service's environment reaches no engine process. A `serve` from a prompt is not isolated, and
  its children read the same variables it does. The `python_variables_reach_children` loosening
  is gone, because no child can honour a variable its engine ignores, and the start-up code
  inventory searches the engine's own import path only. It now logs a site directory it cannot
  list and a `.pth` file it cannot read. See
  [SERVICE.md](../docs/SERVICE.md#the-service-launch). (vault `BACKLOG #2701`, `#2724`)
