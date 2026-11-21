- **An uploaded log's part swapped for a folder or a socket now answers as damaged, not as a server
  error.** A by-id read, download or delete of an upload whose sidecar or body was replaced by a
  folder or a socket after its check re-raised the open's `EISDIR` or `ENXIO`, so the route would
  have answered 500. It now answers as the other not-a-file cases do. (`BACKLOG #5388`)
