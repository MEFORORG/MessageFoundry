- **The start check follows the links an open of a value file or settings file follows.** It
  vetted the file and its folder, and a reload also vetted the folder of each link along a chain of
  file links from the value file. Now each check vets each link, a folder link anywhere in the path
  included, the real folder holding each one, and the real file and folder they lead to, so a link
  in `environments/` no longer reads bytes from a folder nobody vetted. A reload vets the value
  file before it reads the config directory, so one in its `environments/` folder is vetted before
  its bytes are read. A file or folder the check cannot stat, or a link it cannot read, is refused
  rather than skipped. A folder holding a link is judged as the file's own folder is, so a link
  that sits directly in `C:\` or `C:\ProgramData`, as Windows ships them, is refused. (vault
  `BACKLOG #2596`, `#6654` items 2 and 5)
