- **`install-service.ps1` refuses an engine install that anyone but administrators can write.** It
  checks the default root and a passed `-AppExe` or `-PythonExe` alike: the interpreter, the
  launcher, the package's `__init__.py` and a venv's `pyvenv.cfg`, each file and every folder above
  it. It also refuses an editable install. So a service can no longer run from a checkout. The
  service's working directory is now always the install root, and its project root is the folder
  above `-Config`. [SERVICE.md](../docs/SERVICE.md#install-the-engine-where-only-administrators-can-write)
  says how to build the install from the engine wheel. (`BACKLOG #2626`)
