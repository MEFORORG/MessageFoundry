- **An uploaded log's part swapped for a folder or a socket now answers as damaged on a read, not
  as a server error.** A by-id metadata read or download of an upload whose sidecar or body was
  replaced by a folder or a socket after its check, or a delete of one whose sidecar was, re-raised
  the open's `EISDIR` or `ENXIO`, so the route would have answered 500. It now answers as the
  other not-a-file cases do. A delete of
  an upload whose body is swapped for a folder after its check still answers 500: the delete's
  unlink is not one of these reads. (`BACKLOG #5388`)
