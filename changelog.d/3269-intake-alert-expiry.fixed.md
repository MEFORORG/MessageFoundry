- **An intake-pause alert whose engine process never returns under its name now expires.** The
  subject is `intake:<reason>@<process>`, so at least an unpinned cluster node that crashed while
  paused, a lone engine that became several engine shards, a dropped engine shard, and a renamed
  `[cluster].node_id` left an alert nobody could clear. Every engine process with an alert sink now
  sweeps the open `intake_paused` alerts of other processes once a minute and resolves one whose
  occurrence count has not moved for four reminder intervals (20 minutes) of its own clock. The
  resolve is bounded by the count it read, so a paused process that is alive, and whose reminder
  every five minutes reaches the store, keeps its alert open, and no clock is compared across
  processes. A paused process cut off from the store has its alert expired while still paused. (`BACKLOG #3269`)
