- **The DICOM C-STORE SCP takes `min_message_bytes_per_second`, so a slow link can deliver a large
  object.** At the unchanged default of 64 KiB a second, a link slower than that would have an
  object over a size set by the link cut at the same point on every attempt. Set the rate at or
  under the link's. The least it takes is 8 KiB a second, and no value turns the per-message
  deadline off. It is refused on an outbound connection. The DICOM log filter also redacts more
  peer values, and the C-STORE client dead-letters an object it can never propose instead of
  retrying it. (`BACKLOG #6637`)
