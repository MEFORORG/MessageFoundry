- **Linux is not a supported v1 deployment target.** Windows is the only supported v1 deployment
  platform. Linux is not, on a host or in the container image. The engine drops the
  `Operating System :: POSIX :: Linux` classifier. The ruling is in
  [SYSTEM-REQUIREMENTS.md](../docs/SYSTEM-REQUIREMENTS.md#linux-is-not-a-supported-v1-deployment-target),
  and at least the install, deployment and container docs link to it. The code, the `docker/` tree
  and CI are unchanged.
