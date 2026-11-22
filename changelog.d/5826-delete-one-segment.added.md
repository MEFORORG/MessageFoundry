- **`Message.delete_segments` can remove one segment.** Pass `occurrence=i` to delete only the
  i-th segment of that id, numbered as `field()` and `count_segments()` number it; it returns 1, or 0
  when that occurrence is absent. The `results_relay` porting template now uses it to drop a
  cancelled OBX (with its NTE, PRT and Z rows) and edits the rest in place, so a feed copied from it keeps
  every OBX field, escape and the OBX-to-OBR grouping. Before, the template rebuilt each OBX from a
  fixed subset of fields joined by hand, and every OBX was re-inserted under the first OBR.
  (`BACKLOG #5826`)
