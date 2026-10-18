- **Linux is not a supported v1 deployment target.** Windows is the only supported v1 deployment
  platform. Linux is not, on a host or in the container image. The engine drops the
  `Operating System :: POSIX :: Linux` classifier. The ruling is in
  [SYSTEM-REQUIREMENTS.md](../docs/SYSTEM-REQUIREMENTS.md#linux-is-not-a-supported-v1-deployment-target),
  and at least the deployment, install, container and early-adopter docs link to it. ADRs 0017, 0047
  and 0149 gain dated amendments. `docker/compose.yaml` and the two Kubernetes reference manifests
  gain a header line saying they are not a supported v1 deployment. The code, the image, what the manifests deploy, and CI are unchanged.
