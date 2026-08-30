# cla-assistant-lite (vendored)

This directory vendors `contributor-assistant/github-action` at commit `ca4a40a7d1004f18d9960b404b97e5f30a505a08` (tag `v2.6.1`).

GitHub archived the upstream repository, and no maintained fork or successor exists. We vendor it instead, the same approach this project already takes for other unmaintained-but-needed third-party code (see `messagefoundry/anon/`, vendored to `tee/anon/`).

The action is Apache-2.0 licensed. The license text is in `LICENSE` in this directory.

We vendor only the compiled `dist/index.js`, not the TypeScript source. The source review happened once, against the upstream repository directly, and the compiled output is what actually runs.

Upstream source, for reference: https://github.com/contributor-assistant/github-action/tree/ca4a40a7d1004f18d9960b404b97e5f30a505a08
