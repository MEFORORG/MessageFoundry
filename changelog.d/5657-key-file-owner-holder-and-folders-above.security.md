- **The key-file access check now reads, on Windows, a key file's owner and the directory that
  holds it.** On every platform a junction or a link
  the walk of a key file's path finds is judged by who can change it, on POSIX by the owner and mode the file system reports, which a network file system
  such as CIFS or NFS may not enforce, as
  `_windows_link_problem` and `_posix_link_problem` in `messagefoundry/restricted_file.py` define. On Windows the TLS key the engine mints must be owned by the engine's own account,
  SYSTEM or Administrators, and a key file whose owner is a broad group or an application package, or cannot be read, is
  refused. On Windows the check also reads the owner and access list of the directory that holds
  the key file, and refuses the file when a broad group or an application package may delete a
  file in that directory, change its access list or take it over, or when its owner is such a
  group or cannot be read. This holds when that directory is an ordinary folder, not a junction, a symbolic link, or a
  folder a volume is mounted on. Treat anything else about that directory or the folders around it as not judged, and restrict the folder that holds each
  key file, the secrets directory and the folders above them yourself. Before, the Windows check read
  the key file's own access list alone, and the POSIX check followed a linked folder above the
  file whoever could re-point it. The check applies at least to the generated and the operator's
  API TLS key, the store key file and each connection's key file, and to the secrets directory,
  whose files are not walked again. This supersedes the 5636 entry's sentence about links above
  a key. (`BACKLOG #5657`, `BACKLOG #5656`)
