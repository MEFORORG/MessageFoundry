- **The engine declares a `webconsole` extra.** `pip install "messagefoundry[webconsole]"` installs
  the web console, `messagefoundry-webconsole>=0.5.0`, as a floor with no ceiling
  ([WEBCONSOLE-PACKAGE.md](../docs/WEBCONSOLE-PACKAGE.md)); the startup handshake still refuses a
  console built for another engine seam. uv resolves the extra to the in-tree console, so
  `uv sync --extra webconsole` installs the console that matches the tree. The two `--all-extras`
  lock exports, `requirements.lock` and `constraints.lock`, leave that console out, as they leave
  out the engine. The release checklist and CONTRIBUTING.md now describe the engine and a
  seam-moving console released from one pull request, both floors raised in it, with the engine
  tagged first.
