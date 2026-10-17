- **Linux is not a supported v1 deployment target.** Windows is the only supported v1 deployment
  platform. Linux is not, on a host or in the container image. The engine drops the
  `Operating System :: POSIX :: Linux` classifier. The ruling is in
  [SYSTEM-REQUIREMENTS.md](../docs/SYSTEM-REQUIREMENTS.md#linux-is-not-a-supported-v1-deployment-target),
  and at least the deployment, container and early-adopter docs link to it. ADRs 0017 and 0047 gain
  dated amendments. The code, the image and manifests under `docker/`, and CI are unchanged.
