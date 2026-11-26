- **`restore` and `restore-verify` exit 2 on a hop refusal at the store key seam.** That refusal
  was a plain hop refusal, which neither command's key arm caught, so each reached the dispatch
  floor and exited 1. It is now also a key-provider refusal, with the same fixed text, so it takes
  the key arm, and `check-privileges` prints that fixed text rather than its type name.
  (`BACKLOG #3471`)
- **`check-privileges` reads a refusal's text without running the error's own code.** A class
  with its own `__str__`, or a refusal whose arguments are not one string, is named by its type.
  The AD bind probe gives the LDAPS revocation guard's fixed text only to a refusal raised by the
  guard's own call, so one raised while building the TLS context is named by its type.
  (`BACKLOG #3471`)
- **`[store].encryption_key` and `[store].encryption_keys_retired` are out of the store settings'
  printed form**, and the store cipher build keeps no key in its frame once it fails, so a
  renderer that prints a traceback's locals prints neither key. `[store].password` is still in
  that form. (`BACKLOG #3471`)
