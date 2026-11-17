- **`date_diff_field` reads a coarser degree-of-precision code and a trailing empty component.**
  A whole-field `TS` whose component 2 code is coarser than its time, such as `198807051200^D`, is
  read at that precision rather than refused, and a trailing empty component, as in `20260101^`,
  is ignored. A component path now raises on any second repetition, an empty one between them
  included, as a whole-field path does. (`BACKLOG #5822`)
