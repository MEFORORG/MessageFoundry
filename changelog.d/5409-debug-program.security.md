- **The IDE Test Bench Debug launch no longer has the debugger itself put the workspace on the
  import path.** debugpy before 1.8.22 ignores `-P` when it runs a module. So the launch now runs a
  small program the extension writes into its own global storage folder, under `testbench-debug`.
  Under a debugpy before 1.8.22, that folder goes at `sys.path[0]` instead. It is not pruned, and
  nothing checks its contents. Not covered: the debuggee's environment. The Python Debugger loads
  an env file into it. That file is the workspace `.env` by default, or the file `python.envFile`
  names. The process environment applies too. A variable set in either can still put workspace
  code ahead of the installed package under Debug. At least `PYTHONPATH`, `PYTHONHOME` and
  `PYTHONUSERBASE` can do that. (`BACKLOG #5409`)
