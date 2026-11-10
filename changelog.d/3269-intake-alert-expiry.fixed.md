- **An intake-pause alert whose engine process never returns under its name now expires.** The
  subject is `intake:<reason>@<process>`, so an unpinned cluster node that crashed while paused, a
  lone engine that became several engine shards, a dropped engine shard, or a renamed
  `[cluster].node_id` left an alert nobody could clear. Every engine process with an alert sink now
  sweeps the open `intake_paused` alerts of other processes once a minute and resolves one whose
  occurrence count has not moved for three reminder intervals (15 minutes) of its own clock. The
  resolve is bounded by the count it read, so a paused process that is alive, and reminds every
  five minutes, keeps its alert open, and no clock is compared across processes. (`BACKLOG #3269`)
