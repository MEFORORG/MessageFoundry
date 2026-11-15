- **The start check walks the links an open of a value file or settings file follows, as a model
  of the open; `docs/SECURITY.md` names where the model and the open can differ.** It
  vetted the file and its folder, and a reload also vetted the folder of each link along a chain of
  file links from the value file. Now each check vets, along a walk that models the open, the real
  folder holding each link, a folder link anywhere in the path included, each link itself on
  Windows, and the real file and folder the links lead to, or, for a dangling link, the last
  folder the walk reaches on the way to the missing name. On Windows a relative link target
  holding `..` met after a junction is refused, because the open can resolve that `..` against
  the path through the junction (measured); the refusal also catches some layouts the open would
  land on safely, such as one with an absolute link between the two, so it fails closed. A path
  is also refused where only one of the walk and the open reaches anything, such as one whose
  final link names a file with a trailing separator, or where `os.path.samefile` says they reach
  two different ones. A reload vets the engine's own value file before it reads the config
  directory, so one in its `environments/` folder is vetted before its bytes are read; the other
  `environments/*.toml` files the snapshot reads are not. A file or folder the check cannot stat,
  or a link it cannot read, is refused rather than skipped. `docs/SECURITY.md` names what else
  the check refuses and misses. (vault `BACKLOG #2596`, `#6654` items 2 and 5)
