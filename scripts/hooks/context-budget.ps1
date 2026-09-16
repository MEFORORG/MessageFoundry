# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#
# DISABLED BY OWNER DECISION, 2026-09-16. This hook must emit nothing, ever.
#
# WHAT IT USED TO DO: report how much of the session's context window was spent and warn the seat
# "before it runs out of room", claiming a compaction "drops the seat, the goal and the brief, and
# nothing re-declares them for you".
#
# WHY IT IS OFF, in the owner's words: the desktop app COMPACTS AUTOMATICALLY when the context
# overflows. So the warning is not merely noisy, it is WRONG -- it advertises a failure mode that
# does not occur, and its central claim about losing the seat and the brief is false.
#
# It also cost real attention. A session receiving this on every prompt starts narrating its own
# context percentage back to the owner, curtails work it should have finished, and treats a normal
# condition as an emergency. That is the whole reason it is disabled rather than reworded.
#
# DO NOT RESTORE IT, AND DO NOT WRITE A REPLACEMENT THAT REPORTS CONTEXT FULLNESS. No session is to
# see a hook that mentions a context budget. If a future need arises, it is an owner decision.
exit 0
