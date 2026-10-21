- **The engine declares a `webconsole` extra.** `pip install "messagefoundry[webconsole]"` installs
  the web console, `messagefoundry-webconsole>=0.5.0`, as a floor with no ceiling
  ([WEBCONSOLE-PACKAGE.md](../docs/WEBCONSOLE-PACKAGE.md)). The two `--all-extras` lock exports,
  `requirements.lock` and `constraints.lock`, leave the first-party console out, as they leave out
  the engine. The release checklist and CONTRIBUTING.md now describe the engine and a seam-moving
  console released from one pull request, with the engine tagged first.
