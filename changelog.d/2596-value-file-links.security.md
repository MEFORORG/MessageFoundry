- **The start check follows the links an open of a value file or settings file follows**, with
  the exception below. It
  vetted the file and its folder, and a reload also vetted the folder of each link along a chain of
  file links from the value file. Now each check vets the real folder holding each link, a folder
  link anywhere in the path included, each link itself on Windows, and the real file and folder
  the links lead to, or the folder a dangling link leads into, except some relative links reached
  through a junction on Windows (`docs/SECURITY.md`). Where only one of the walk and the open
  reaches anything, or `os.path.samefile` says they reach two different ones, the check
  refuses the path. A reload vets the engine's own
  value file before it reads the config directory, so one in its `environments/` folder is vetted
  before its bytes are read; the other `environments/*.toml` files the snapshot reads are not. A
  file or folder the check cannot stat, or a link it cannot read, is refused rather than skipped.
  `docs/SECURITY.md` names what else the check refuses and misses. (vault `BACKLOG #2596`,
  `#6654` items 2 and 5)
