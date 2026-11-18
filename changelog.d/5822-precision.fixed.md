- **`date_diff_field` reads a coarser degree-of-precision code and trailing empty parts.** A
  whole-field `TS` whose component 2 code is coarser than its time, such as `198807051200^D`, is
  read at that precision rather than refused, and trailing empty components and repetitions, as
  in `20260101^` and `20260101~`, are ignored. Once both fields are present, a component path now
  raises on more than one repetition, as a whole-field path does, so `20260101~~20270101` and
  `~20270101` raise there too. (`BACKLOG #5822`)
