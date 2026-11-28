- **An empty engine-secret entry in the Windows service's environment refuses the start.** An
  entry in the service's NSSM or Service Control Manager environment that names a store key or
  another engine secret with nothing in it, set empty or blank or written as the name alone, now
  refuses `serve`, `supervise` and the API app factories, as a set one does. A secret can be
  written apart from its name, into the entry after it, and the reader cannot always tell that
  entry from an ordinary variable, so the empty entry was the one sign of it left and refused
  nothing. The refusal says to delete the empty entry, and the entry or line after it where that
  holds the secret. An empty entry for an ordinary variable, such as `HTTP_PROXY=`, still refuses
  nothing. (`BACKLOG #5394`)
