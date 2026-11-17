- **`SegmentGroup.set` writes a field within one order group.** Its `occurrence` counts within the
  group, as `SegmentGroup.field` does. A group's `ordinal` counts a fieldless bare boundary line
  and `Message.set` does not, so `Message.set(..., occurrence=group.ordinal)` after a bare `OBR`
  could write to another order. (`BACKLOG #5917`)
