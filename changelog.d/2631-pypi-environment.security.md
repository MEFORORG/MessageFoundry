- **Every PyPI publish now runs in a job that only publishes, and names the `pypi`
  environment.** The build jobs gate the files, record their SHA-256 digests and hand them over;
  each publish job checks every byte against those digests before it publishes. No publish job
  checks out the repository or builds anything, and none runs on a manual dry-run. This lets the
  owner bind each PyPI publisher to the environment and require an approval, without that approval
  gating the build. The build jobs that only published no longer hold the OIDC identity.
  (`vault BACKLOG #2631`)
