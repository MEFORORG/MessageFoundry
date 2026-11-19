- **An alert rule's `control_action` restart runs on its own throttle.** It still fires at most
  once per cooldown per event type and connection, but that window is now kept apart from the
  notification's, and only a restart the sink actually schedules starts it. So a restart can fire
  on an alert whose page is throttled, when no earlier alert in the window ran a restart. See ADR
  0128 section 4 (owner ruling 2026-11-19, on PR 3069). (`BACKLOG #5910`)
