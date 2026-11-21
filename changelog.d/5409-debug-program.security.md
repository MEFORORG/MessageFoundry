- **The IDE Test Bench Debug launch no longer has the debugger itself put the workspace on the
  import path.** debugpy before 1.8.22 ignores `-P` when it runs a module, so the launch now runs a
  small program the extension writes into its own global storage folder. Not covered: the
  debuggee's environment. The env file the Python Debugger loads (the workspace `.env` by default,
  or the file `python.envFile` names) and the process environment still apply, and a variable set
  there, at least `PYTHONPATH`, `PYTHONHOME` or `PYTHONUSERBASE`, can still put workspace code ahead
  of the installed package under Debug. (`BACKLOG #5409`)
