- **The IDE Test Bench Debug launch no longer lets debugpy put the workspace on the import path.**
  debugpy before 1.8.22 ignores `-P` when it runs a module, so the launch now runs a small program
  the extension writes into its own global storage folder. A `messagefoundry.py` in the workspace
  root no longer shadows the installed package under Debug. A PYTHONPATH entry from the environment
  or from the env file the Python Debugger loads still applies. (`BACKLOG #5409`)
