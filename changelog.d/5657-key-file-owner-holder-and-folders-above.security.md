- **The key-file access check now reads the folders above a key file, and on Windows its owner
  and the directory that holds it.** On every platform a junction or a link in the folders on a
  key file's path is judged by who can change it, with the trust-anchor rules: one only the
  engine's own account and the host's administrators can change passes (POSIX: root; Windows: at
  least SYSTEM, Administrators, TrustedInstaller and the local Administrators group's direct
  members, as [PHI.md](../docs/PHI.md) lists), such as macOS `/tmp` or `C:\Users\All Users`, and one
  another account can change, or that sits at any depth under a folder another account may
  rename or re-point it in, is refused. On Windows the TLS pair the engine mints must be owned by
  the engine's own account, SYSTEM or Administrators, so a pair another account planted in the
  store directory is refused. On Windows a key file, or the directory that holds it, whose owner is a broad group or
  an application package, or cannot be read, is refused, and so is a key file in a directory that
  lets a broad group delete a file in it or change its access list. On Windows, when the directory
  that holds the file is itself a junction, a symbolic link or a folder a volume is mounted on, at least, the owner and
  access list of its target are not read, nor those of the folders above the target, so a
  junction only the engine's account and the host's administrators can change, pointing to a
  folder that lets a broad group delete a file in it, passes. Before, the Windows check read
  the key file's own access list alone, and the POSIX check followed a linked folder above the
  file whoever could re-point it. A right to list a directory or add a file to it is not refused,
  so a store directory the engine makes under `C:\ProgramData` still passes. The check applies at
  least to the generated and the operator's API TLS key, the store key file and each connection's
  key file, and to the secrets directory, whose files are not walked again. What it does not read
  is in [PHI.md](../docs/PHI.md), *Key files*. This supersedes the 5636 entry's sentence about
  links above a key. (`BACKLOG #5657`, `BACKLOG #5656`)
