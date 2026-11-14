- **The key-file access check now judges a junction or link on a key file's path, and on Windows
  the key file's owner and the directory that holds it.** On every platform a junction or a link in the folders on a
  key file's path is judged by who can change it, with the trust-anchor rules: one only the
  engine's own account and the host's administrators can change passes (POSIX: root; Windows: at
  least SYSTEM, Administrators, TrustedInstaller and the local Administrators group's direct
  members, as [PHI.md](../docs/PHI.md) lists), such as macOS `/tmp` or `C:\Users\All Users`, and one
  another account can change, or that sits at any depth under a folder another account may
  rename or re-point it in, is refused. On Windows the TLS pair the engine mints must be owned by
  the engine's own account, SYSTEM or Administrators, so a pair another account planted in the
  store directory is refused. On Windows a key file, or the directory that holds it, whose owner is a broad group or
  an application package, or cannot be read, is refused, and so is a key file in a directory that
  lets a broad group delete a file in it or change its access list, that directory's owner and
  access list being read at the file's lexical path without following a link there. It does not
  judge everything around the file;
  [ADR 0214's amendment](../docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md#amendments)
  lists at least what it leaves out. Restrict the secrets directory, any link target and the
  folders above them yourself. Before, the Windows check read the key file's own access list
  alone, and the POSIX check followed a linked folder above the file whoever could re-point it. The check applies at
  least to the generated and the operator's API TLS key, the store key file and each connection's
  key file, and to the secrets directory, whose files are not walked again. This supersedes the 5636 entry's sentence about
  links above a key. (`BACKLOG #5657`, `BACKLOG #5656`)
