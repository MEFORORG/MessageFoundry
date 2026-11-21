- **The IDE Test Bench Debug launch no longer has the debugger itself put the workspace on the
  import path.** debugpy before 1.8.22 ignores `-P` when it runs a module, so the launch now runs a
  small program the extension writes into its own global storage folder. Not covered: a PYTHONPATH
  entry still applies, from the environment or from the env file the Python Debugger loads (the
  workspace `.env` by default, or the file `python.envFile` names). Where that entry names the
  workspace, a `messagefoundry.py` there can still shadow the installed package under Debug.
  (`BACKLOG #5409`)
