- **The shutdown's upload straggler drain now waits for the `upload.create` rows still running
  before it looks.** An `upload.create` row that the long-operations drain cancelled could still
  be unwinding when that drain stopped waiting. Its removal of the stored file then started after
  the upload drain had returned, and only the event loop's final cancel ended it. The upload
  drain now spends its wait on those operations first, so a removal they start is held and
  drained. One whose operation is still running when that wait ends
  can still start late.
  Where the long-operations drain cancelled that operation, a WARNING named it and an ERROR
  counted it.
  (vault `BACKLOG #3740` item 6)
- **The upload straggler drain no longer waits for a reservation heartbeat's touch.** A touch only
  refreshes a reservation whose save does not outlive the shutdown, so the drain cancels it rather
  than spending its wait or its grace on it. (vault `BACKLOG #3740` item 14)
