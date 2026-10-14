- **An SVGZ attachment is checked by trial passes before the pass that keeps it.** The download
  route inflates a gzip attachment to vet any SVG inside. That inflate used to bound its output
  only as it kept it, so markup over the 32 MiB bound was refused after up to 32 MiB was held. Now
  the head sniff and the size check keep no output, through the shared bounded inflate loop the
  compression codec uses. Markup over the bound is refused before any of it is held, and only an
  admitted body is inflated again to be sanitized. The member cap and the size bound are
  unchanged. (`BACKLOG #1129`)
- **A File inbound with `decompress=` set warns when `max_decompressed_bytes` is off.** Turning the
  decompressed-byte ceiling off with `0` or `None` is still allowed, but the connection now logs one
  warning when it is built, naming the connection and the setting. Off without `decompress=` changes
  nothing and logs nothing. (`BACKLOG #1129`)
