# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Session mail, section 8: SHOWING IS NOT CONSUMING.

Split out of ``test_session_mail.py`` (see ``_session_mail_harness``) so the two halves schedule on
different xdist workers. This is a contiguous slice of that file, banner and all -- the section
comment below is the original and is the authority on why these tests exist.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from _session_mail_harness import (
    COORD,
    DRAIN,
    MAIL,
    MAIL_KEY,
    TIMEOUT,
    _const,
    box_files,
    injection,
    mail_root,
    receipts,
    repo,
    requires_pwsh_on_windows,
    run_drain,
    seed,
    tree,
)

__all__ = ["repo"]  # re-exported so pytest resolves the fixture in this module

pytestmark = requires_pwsh_on_windows


# --------------------------------------------------------------------------------------------------
# 8. SHOWING IS NOT CONSUMING.
#
# THE MEASURED DEFECT THESE EXIST FOR, and it is a measurement rather than a hypothesis. On
# 2026-08-05, against a throwaway repo carrying only project-level .claude/settings.json hooks, the VS
# Code extension fired SessionStart TWICE, 43 seconds apart, under two DIFFERENT session ids. A
# message queued beforehand was consumed by the FIRST -- rendered, receipt written, moved to seen/,
# box emptied -- while the operator's prompt came from the SECOND, so the operator saw nothing. The
# first session left no transcript and no session record under any config root; it never became a
# conversation.
#
# THE GENERAL FORM: A SessionStart HOOK THAT CONSUMES STATE CAN LOSE THAT STATE TO A SESSION THAT
# NEVER EXISTED. Gating on transcript_path cannot discriminate, because at SessionStart neither a
# phantom's nor a real session's transcript exists yet. The answer is therefore to stop CONSUMING at
# that event rather than to try to detect the phantom.
#
# THE ACCEPTED TRADEOFF IS ASSERTED HERE, NOT MERELY DOCUMENTED: if two real sessions start before
# either finishes a turn, BOTH display the message. ``test_a_phantom_session_start_cannot_swallow_the
# _mail_it_displayed`` asserts exactly that as a PASS condition, so a future edit that "fixes" the
# duplicate by consuming earlier turns this file red. Duplicate display is accepted; silent loss is
# not, and the trade never runs the other way.
#
# EVERY ARM HERE ASSERTS THE FILESYSTEM, not only the injection. "The message was shown" and "the
# message is still deliverable" are different facts, and it is the second one the measured defect
# destroyed while every instrument reported success.
# --------------------------------------------------------------------------------------------------

# Three distinct, well-formed session ids. Distinct from SELF_ID so a test that accidentally reused
# the module default would collide with another arm's marker rather than pass quietly.
SESSION_A = "aaaaaaaa-1111-2222-3333-444444444444"
SESSION_B = "bbbbbbbb-1111-2222-3333-444444444444"
SESSION_C = "cccccccc-1111-2222-3333-444444444444"

# Read from the drain for the same reason as the caps: a copy here would stop testing the shipped
# value the moment somebody tunes it.
RETAIN_DAYS = _const("RETAIN_DAYS")

# The two sentences that distinguish a HELD display from a CONSUMED one. Asserted by substring rather
# than reproduced whole: the drain wraps these across lines, and a test that pinned the wrapping would
# go red on a reflow that changed nothing.
HELD_NOTICE = "consumed at this session's next turn boundary"
CONSUMED_NOTICE = "delivered at"


def markers(repo: Path, key: str) -> list[str]:
    """Every file in ``shown/``, minted or not.

    A raw listing on purpose: an arm that asserts an unowned name was LEFT ALONE cannot use a filter
    that would hide it, and an arm that asserts cleanup has to see a leftover this channel would
    refuse to parse.
    """
    d = mail_root(repo) / "box" / key / "shown"
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def marker_name(stem: str, session_id: str) -> str:
    """The shown-marker name, spelled the way mail-claim.ps1's Split-ShownMarkerName parses it.

    Lowercased here because ConvertTo-SessionKey lowercases: VS Code and the Desktop app disagree on
    the case of a path, and the same normalisation argument was applied to the id. A test that minted
    an uppercase name would be minting a name this channel does NOT mint, and would then be measuring
    the unowned-name path while believing it measured the marker path.
    """
    return f"{stem}--{session_id.lower()}.marker"


def receipt_json(repo: Path, stem: str) -> dict[str, Any]:
    return dict(json.loads((mail_root(repo) / "receipts" / f"{stem}.json").read_text("ascii")))


def run_drain_raw(repo: Path, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    """``run_drain`` without its payload shape, for the arms that test a MALFORMED payload.

    ``run_drain`` always sends a ``hook_event_name``; the load-bearing question "what does the drain
    do when it cannot tell what woke it" can only be asked by omitting one.
    """
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(DRAIN)],
        cwd=str(repo),
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"drain exited {proc.returncode}: {proc.stderr}"
    assert not proc.stderr.strip(), f"drain wrote to stderr: {proc.stderr}"
    return proc


def mail_cmd(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(MAIL),
         "-MailRoot", str(mail_root(repo)), *args],
        cwd=str(repo), capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, f"mail.ps1 {args} failed: {proc.stdout}\n{proc.stderr}"
    return proc


# --- 8a. The phantom. --------------------------------------------------------------------------


def test_a_phantom_session_start_cannot_swallow_the_mail_it_displayed(
    repo: Path, tmp_path: Path
) -> None:
    """THE REGRESSION THAT WOULD HAVE CAUGHT THE MEASURED DEFECT.

    Two SessionStart drains under DIFFERENT session ids and no Stop between them -- the exact shape
    measured against the VS Code extension. Under the old behaviour the first consumed the message and
    the second saw an empty box; the operator's real session was the second.

    The third drain is the one that makes the assertion mean something. "Still in the inbox" is a
    statement about a directory; "still DELIVERABLE" is a statement about the channel, and only a
    session that actually receives the body proves it.
    """
    info = seed(repo, tmp_path, [{"body": "the phantom must not eat this"}])
    key = str(info["key"])
    stem = str(info["rows"][0]["stem"])

    first = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "the phantom must not eat this" in first
    assert HELD_NOTICE in first, "a held display did not tell the reader the mail is still queued"
    # THE FACT THE DEFECT DESTROYED. Nothing moved: not to claiming/, not to seen/.
    assert len(box_files(repo, key, "inbox")) == 1
    assert box_files(repo, key, "claiming") == []
    assert box_files(repo, key, "seen") == []
    assert markers(repo, key) == [marker_name(stem, SESSION_A)]
    # A receipt IS written at SessionStart, and it says what it can back: emitted, not consumed.
    held = receipt_json(repo, stem)
    assert held["disposition"] == "shown-held"
    assert held["consumedUtc"] == ""
    assert held["claimToken"] == "", (
        "a held message reported a claim token, but nothing was claimed"
    )

    # The second phantom, under a DIFFERENT id and with no Stop in between. It is shown the message
    # again, and THAT IS THE ACCEPTED TRADEOFF, asserted rather than tolerated.
    second = injection(run_drain(repo, event="SessionStart", session_id=SESSION_B))
    assert "the phantom must not eat this" in second, (
        "a second session was not shown mail the first had only DISPLAYED -- duplicate display is "
        "accepted, silent loss is not, and this is the trade running the wrong way"
    )
    assert len(box_files(repo, key, "inbox")) == 1
    assert box_files(repo, key, "seen") == []
    assert markers(repo, key) == sorted(
        [marker_name(stem, SESSION_A), marker_name(stem, SESSION_B)]
    )

    # A third session takes a turn. Still deliverable, and now consumed.
    third = injection(run_drain(repo, event="Stop", session_id=SESSION_C))
    assert "the phantom must not eat this" in third
    assert CONSUMED_NOTICE in third
    assert box_files(repo, key, "inbox") == []
    assert box_files(repo, key, "claiming") == []
    assert len(box_files(repo, key, "seen")) == 1
    done = receipt_json(repo, stem)
    assert done["disposition"] == "shown-consumed"
    assert done["consumedByHookEvent"] == "Stop"
    assert done["claimToken"], "a consumed message recorded no claim token"


def test_the_phantom_arm_can_see_the_defect_it_asserts_against(repo: Path, tmp_path: Path) -> None:
    """NEGATIVE CONTROL for the arm above, and it is not optional.

    "The next session still sees it" is only evidence if the same fixture can be shown to produce the
    opposite result. This drives the drain at the event that DOES consume and then asks the next
    session -- reproducing, deliberately, exactly what the measured defect looked like from the
    operator's chair: a queued message, a hook that ran and reported success, and a second session
    shown nothing.
    """
    info = seed(repo, tmp_path, [{"body": "consumed before the reader arrived"}])
    key = str(info["key"])
    assert "consumed before the reader arrived" in injection(
        run_drain(repo, event="Stop", session_id=SESSION_A)
    )
    assert box_files(repo, key, "inbox") == []
    second = injection(run_drain(repo, event="SessionStart", session_id=SESSION_B))
    assert "consumed before the reader arrived" not in second, (
        "a consuming drain left the message deliverable, so the phantom arm above proves nothing"
    )


# --- 8b. A real session, and the wired path. ----------------------------------------------------


def test_a_real_session_is_shown_mail_again_at_its_turn_boundary_and_consumes_it_there(
    repo: Path, tmp_path: Path
) -> None:
    """The half that makes SessionStart's non-consumption safe rather than merely deferred.

    THIS TEST USED TO ASSERT THE OPPOSITE -- shown once, not re-rendered at Stop -- and that behaviour
    was removed deliberately. Suppressing the second display required trusting a marker across
    invocations, and a marker is keyed by a session id that IS REUSED ACROSS LAUNCHES, so a session
    inheriting a phantom's marker consumed mail it had never been shown. Reproduced, then fixed by
    deleting the trust rather than hardening it.

    So the contract is now: shown at SessionStart, shown AGAIN at the first Stop, and consumed there.
    The duplicate display is the price, and it is the accepted side of this channel's one tradeoff --
    duplicate display is accepted, silent loss is not.

    ``observedUtc`` therefore records the STOP emit, because that is when the consuming drain actually
    put the text in front of a reader. It is no longer carried forward from an earlier display, since
    nothing may now assert that a previous invocation showed anything to this session.
    """
    info = seed(repo, tmp_path, [{"body": "shown twice, consumed once"}])
    key = str(info["key"])
    stem = str(info["rows"][0]["stem"])

    start_text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "shown twice, consumed once" in start_text
    assert box_files(repo, key, "inbox"), "a non-consuming event must not consume"
    assert receipt_json(repo, stem)["disposition"] == "shown-held"

    stop = injection(run_drain(repo, event="Stop", session_id=SESSION_A))
    # THE LOAD-BEARING ASSERTION: the consuming drain RENDERED what it consumed.
    assert "shown twice, consumed once" in stop, (
        "the consuming drain removed the message without rendering it -- that is the silent loss"
    )
    assert box_files(repo, key, "inbox") == []
    assert box_files(repo, key, "claiming") == []
    assert len(box_files(repo, key, "seen")) == 1

    final = receipt_json(repo, stem)
    assert final["disposition"] == "shown-consumed"
    assert final["observedUtc"], "a consumed receipt must record when it was emitted"


def test_stop_alone_shows_and_consumes_with_no_preceding_session_start(
    repo: Path, tmp_path: Path
) -> None:
    """THE WIRED PATH TODAY, and the one this change must not regress.

    The drain is registered Stop-only on the default config root, so most sessions never produce a
    SessionStart drain at all. A message must therefore be shown AND consumed by a Stop that stands
    alone -- and no marker should be minted on the way, because on the consuming path the claim is
    what excludes and the marker has no job.
    """
    info = seed(repo, tmp_path, [{"body": "the wired path"}])
    key = str(info["key"])
    stem = str(info["rows"][0]["stem"])

    text = injection(run_drain(repo, event="Stop", session_id=SESSION_A))
    assert "the wired path" in text
    assert CONSUMED_NOTICE in text
    assert HELD_NOTICE not in text, "a consuming drain told the reader the mail was merely held"
    assert box_files(repo, key, "inbox") == []
    assert len(box_files(repo, key, "seen")) == 1
    assert markers(repo, key) == [], "the consuming path minted a marker it has no use for"
    assert receipt_json(repo, stem)["disposition"] == "shown-consumed"


@pytest.mark.parametrize(
    "event", ["SessionStart", "UserPromptSubmit", "PreToolUse", "Notification"]
)
def test_only_stop_consumes_and_every_other_event_leaves_the_mail_where_it_is(
    repo: Path, tmp_path: Path, event: str
) -> None:
    """CONSUMING IS AN ALLOWLIST WITH ONE MEMBER, and this is the arm that holds it to one.

    The safety property is not "SessionStart is special"; it is that no event OTHER than Stop
    consumes. UserPromptSubmit is measured to fire in a real session and is still out, because it has
    not been measured against the phantom -- adding a member is a measurement, not an edit, and this
    test is what makes such an edit visible.
    """
    info = seed(repo, tmp_path, [{"body": f"not consumed by {event}"}])
    key = str(info["key"])
    text = injection(run_drain(repo, event=event, session_id=SESSION_A))
    assert f"not consumed by {event}" in text
    assert len(box_files(repo, key, "inbox")) == 1
    assert box_files(repo, key, "claiming") == []
    assert box_files(repo, key, "seen") == []


def test_a_payload_that_does_not_say_what_woke_the_drain_does_not_consume(
    repo: Path, tmp_path: Path
) -> None:
    """THE DEFAULT DECIDES WHAT HAPPENS TO MAIL WHEN THE DRAIN CANNOT TELL WHAT WOKE IT.

    A payload with no ``hook_event_name`` is not hypothetical -- a client version change, a truncated
    stdin or a JSON parse failure all produce one -- and a default of "consume" would put the measured
    defect back for every one of those cases at once. The failure direction has to be the safe one.
    """
    info = seed(repo, tmp_path, [{"body": "no event name in the payload"}])
    key = str(info["key"])
    proc = run_drain_raw(repo, {"cwd": str(repo), "session_id": SESSION_A})
    assert "no event name in the payload" in injection(proc)
    assert len(box_files(repo, key, "inbox")) == 1
    assert box_files(repo, key, "seen") == []


# --- 8c. The session id is untrusted input, and a path is built from it. -------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "..\\..\\..\\evil",
        "../../../evil",
        "x/../../../evil",
        "C:\\Windows\\Temp\\evil",
        "aaaaaaaa-1111-2222-3333-444444444444/../../evil",
        "aaaaaaaa-1111-2222-3333-444444444444\nevil",  # \z, not $: '$' matches before a trailing \n
        "a" * 4000,
        "",
    ],
)
def test_a_hostile_session_id_marks_nothing_and_never_falls_back_to_consuming(
    repo: Path, tmp_path: Path, hostile: str
) -> None:
    """A SHOWN-MARKER PATH IS BUILT OUT OF THE SESSION ID, so the id is exactly as untrusted as the
    message filename -- and this is the same CRITICAL the drain already fixed once for the filename.

    THE SECOND HALF IS THE ONE THAT IS EASY TO MISS. Refusing to build a path is necessary and not
    sufficient: an implementation that reacted to "I cannot mark this session" by consuming instead
    would pass a traversal assertion and reintroduce the measured defect for every session whose id
    it could not parse. Consuming is decided by the EVENT and by nothing else, and that is what this
    asserts on the filesystem.

    RENDERING IS UNAFFECTED TOO. Failing to record a display must never suppress one; the cost of an
    unmarkable session is a later duplicate, which is accepted.
    """
    info = seed(repo, tmp_path, [{"body": "hostile id must not change the outcome"}])
    key = str(info["key"])
    root = mail_root(repo)
    before = tree(repo)

    text = injection(run_drain(repo, event="SessionStart", session_id=hostile))

    new = tree(repo) - before
    outside = [p for p in new if not (repo / p).resolve().is_relative_to(root)]
    assert outside == [], f"the drain wrote outside the mail root: {sorted(outside)}"
    assert "evil" not in " ".join(new), sorted(new)
    # Shown -- an unmarkable session still gets its mail.
    assert "hostile id must not change the outcome" in text
    # And nothing was consumed, marked, or claimed.
    assert len(box_files(repo, key, "inbox")) == 1
    assert box_files(repo, key, "seen") == []
    assert box_files(repo, key, "claiming") == []
    assert markers(repo, key) == []
    assert "does not match the shape this channel validates" in text
    # THE FACT, NOT THE VALUE: the raw id is untrusted text and the injection is the one place
    # untrusted text is dangerous. It reaches the receipt JSON only.
    if hostile:
        assert hostile not in text


def test_an_unmarkable_session_still_consumes_at_its_turn_boundary(
    repo: Path, tmp_path: Path
) -> None:
    """DISCRIMINATOR for the arm above: "nothing was consumed" must not be true at Stop as well.

    If a missing marker could suppress a consume, an unmarkable session would show the same mail
    forever and the queue would never drain -- the opposite failure, and just as silent. Consuming is
    a function of the event, so it has to happen here with no marker anywhere in sight.
    """
    info = seed(repo, tmp_path, [{"body": "unmarkable but still consumable"}])
    key = str(info["key"])
    text = injection(run_drain(repo, event="Stop", session_id="not-a-session-id"))
    assert "unmarkable but still consumable" in text
    assert box_files(repo, key, "inbox") == []
    assert len(box_files(repo, key, "seen")) == 1
    assert markers(repo, key) == []


@pytest.mark.parametrize(
    "name",
    [
        "evil.marker",
        "20260101T000000001-aaaaaa--not-a-uuid.marker",
        "--aaaaaaaa-1111-2222-3333-444444444444.marker",  # empty stem
        "20260101T000000001-aaaaaa--aaaaaaaa-1111-2222-3333-444444444444.markerx",
        # DELIBERATELY ABSENT: the same name with the session half in UPPERCASE. Split-ShownMarkerName
        # rejects it as a name this channel did not mint, but NTFS is case-insensitive, so on the
        # platform this ships on it IS the path the drain mints for this session. It therefore does not
        # measure the unowned-name path at all; it measures the marker path under another spelling, and
        # it has its own arm below.
    ],
)
def test_a_marker_name_this_channel_did_not_mint_is_left_alone(
    repo: Path, tmp_path: Path, name: str
) -> None:
    """shown/ is a directory any local process can write to, so the sweeps have to refuse names they
    cannot account for -- the same contract claiming/ already carries, for the same reason: deleting a
    file whose name we cannot parse is not this channel's business, and building a path out of one is
    the traversal defect again.

    The ``.markerx`` case is here because ``-Filter '*.marker'`` is a WINDOWS WILDCARD, not a suffix
    test, and has been measured to surface names the caller did not expect.
    """
    info = seed(repo, tmp_path, [{"stem": "20260101T000000001-aaaaaa", "body": "unrelated mail"}])
    key = str(info["key"])
    shown = mail_root(repo) / "box" / key / "shown"
    shown.mkdir(parents=True, exist_ok=True)
    (shown / name).write_text("{}", encoding="ascii")

    text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "unrelated mail" in text, "an unowned marker suppressed an unrelated delivery"
    assert name in markers(repo, key), "a name this channel did not mint was deleted"
    # Counted, not silently ignored -- except for .markerx, which -Filter never surfaces.
    if name.endswith(".marker"):
        m = re.search(r"(\d+) file\(s\) in shown/ carry a name this channel did not mint", text)
        assert m, f"an unowned marker was not reported:\n{text}"
        assert int(m.group(1)) >= 1


# --- 8d. Marker lifecycle. ----------------------------------------------------------------------


def test_no_marker_outlives_the_message_it_marks(repo: Path, tmp_path: Path) -> None:
    """MARKERS ARE THE ONE THING THIS DESIGN ADDS THAT CAN ACCUMULATE, and the client misbehaviour it
    was built for is what would fill the directory: every discarded phantom leaves one marker per
    message it displayed, on every launch.

    The marker of the session that CONSUMES is dropped in the same step (asserted in the real-session
    arm above). The markers left by sessions that never took a turn outlive that consume by one drain
    and are then swept because their stem is no longer live anywhere -- neither in inbox/ nor in
    claiming/, so a message merely in flight does not look like an orphan.
    """
    info = seed(repo, tmp_path, [{"body": "two phantoms, one consumer"}])
    key = str(info["key"])
    stem = str(info["rows"][0]["stem"])

    run_drain(repo, event="SessionStart", session_id=SESSION_A)
    run_drain(repo, event="SessionStart", session_id=SESSION_B)
    assert len(markers(repo, key)) == 2
    run_drain(repo, event="Stop", session_id=SESSION_C)
    assert box_files(repo, key, "inbox") == []

    text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_C))
    assert markers(repo, key) == [], "markers survived the message they marked"
    assert re.search(r"(\d+) shown-marker\(s\)", text), f"the sweep was silent:\n{text}"
    assert marker_name(stem, SESSION_A) not in " ".join(markers(repo, key))


def test_the_orphan_sweep_does_not_take_a_marker_whose_message_is_still_live(
    repo: Path, tmp_path: Path
) -> None:
    """DISCRIMINATOR for the sweep above. A sweep that deleted every marker would pass it.

    The live message's marker must survive, because it is the only thing standing between its session
    and a second display of mail it has already been shown.
    """
    info = seed(
        repo,
        tmp_path,
        [
            {"stem": "20260101T000000001-aaaaaa", "body": "still in the inbox"},
            {"stem": "20260101T000000002-aaaaaa", "body": "also still in the inbox"},
        ],
    )
    key = str(info["key"])
    shown = mail_root(repo) / "box" / key / "shown"
    shown.mkdir(parents=True, exist_ok=True)
    orphan = marker_name("20260101T000000009-aaaaaa", SESSION_A)
    (shown / orphan).write_text("{}", encoding="ascii")

    run_drain(repo, event="SessionStart", session_id=SESSION_A)
    left = markers(repo, key)
    assert orphan not in left, "a marker for a message that does not exist was kept"
    assert marker_name("20260101T000000001-aaaaaa", SESSION_A) in left
    assert marker_name("20260101T000000002-aaaaaa", SESSION_A) in left


def test_a_marker_older_than_the_retention_window_is_swept(repo: Path, tmp_path: Path) -> None:
    """ONE OF THE TWO BOUNDS ON UNBOUNDED REDISPLAY.

    A session that opens, is shown mail and never takes a turn leaves that mail in the inbox, so every
    later session is shown it again. Two things bound that: the message's own expiry (asserted by the
    arm below, including the receiver-side floor for a message whose sender set no TTL), and this age
    sweep of the marker. Neither one loses the message -- an expired marker only costs a duplicate
    display, which is the direction this whole design chooses.

    Both artefacts are made by the REAL drain rather than written by hand, so this measures the
    marker/receipt pair the code actually mints.
    """
    info = seed(repo, tmp_path, [{"body": "held by a session that went away"}])
    key = str(info["key"])
    stem = str(info["rows"][0]["stem"])

    run_drain(repo, event="SessionStart", session_id=SESSION_A)
    marker = mail_root(repo) / "box" / key / "shown" / marker_name(stem, SESSION_A)
    assert marker.is_file()
    # Only the marker is aged. The message stays fresh, so the message-based orphan sweep cannot be
    # what removes it and the age path is what this measures.
    aged = marker.stat().st_mtime - (RETAIN_DAYS + 1) * 86400
    os.utime(marker, (aged, aged))

    text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert re.search(r"(\d+) shown-marker\(s\)", text), f"the age sweep was silent:\n{text}"
    assert "held by a session that went away" in text, (
        "the aged marker still suppressed the display, so the sweep did not run"
    )
    # MEASURED, NOT ASSUMED: the marker is back, because the same drain that swept it re-minted it on
    # the way to showing the message again. "The file is gone afterwards" would therefore be the wrong
    # assertion -- and asserting it would have this test pass only if the sweep BROKE the redisplay.
    # The discriminator is the timestamp: a marker that was never swept would still carry the aged one.
    assert marker.is_file()
    assert marker.stat().st_mtime > aged + 1, "the marker was not swept, only left in place"
    assert len(box_files(repo, key, "inbox")) == 1


def test_a_message_whose_sender_set_no_ttl_is_still_bounded_by_the_receiver(
    repo: Path, tmp_path: Path
) -> None:
    """THE OTHER BOUND, and it exists because the show/consume split extended a message's lifetime.

    ``expiresUtc`` is a field the WRITER chose, and the write side is unauthenticated by design, so the
    send-side TTL is a property of one writer rather than of the queue. That was survivable while the
    first display consumed the message. Under the split it is not: a message with no TTL, in a worktree
    whose sessions never reach a turn boundary, would be redisplayed to every future session forever.
    The receiver therefore applies its own ``RETAIN_DAYS`` floor when -- and only when -- the sender set
    no readable expiry.

    The second arm is the half that keeps the floor from overruling an explicit sender instruction.
    """
    info = seed(
        repo,
        tmp_path,
        [
            {"stem": "20260101T000000001-aaaaaa", "raw": json.dumps({"body": "no ttl, old"})},
            {
                "stem": "20260101T000000002-aaaaaa",
                "body": "a long ttl the sender meant",
                "expiresUtc": (
                    datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=RETAIN_DAYS + 30)
                ).isoformat(),
            },
        ],
    )
    key = str(info["key"])
    inbox = mail_root(repo) / "box" / key / "inbox"
    for row in info["rows"]:
        p = inbox / str(row["name"])
        aged = p.stat().st_mtime - (RETAIN_DAYS + 1) * 86400
        os.utime(p, (aged, aged))

    text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "no ttl, old" not in text, (
        "an undated message outlived the receiver's own retention floor"
    )
    assert "a long ttl the sender meant" in text, (
        "the floor overruled an explicit, longer TTL -- a worse failure than the one it closes"
    )
    assert len(box_files(repo, key, "expired")) == 1
    assert len(box_files(repo, key, "inbox")) == 1


# --- 8e. Fail open, on the paths this change added. ---------------------------------------------


def test_a_shown_directory_that_cannot_be_written_still_shows_the_mail(
    repo: Path, tmp_path: Path
) -> None:
    """shown/ REPLACED BY A FILE. Every listing and every create against it then fails.

    A hook that fails takes the turn with it, and a marker is bookkeeping: losing it must cost a
    duplicate display and nothing else. run_drain asserts exit 0 and a clean stderr; this adds the
    half that says the mail still arrived and was not consumed behind the reader's back.

    THE DUPLICATE IS ASSERTED RATHER THAN A COUNTER LINE, and that is not a weaker check. Marking now
    happens AFTER the emit, so a marking failure cannot be reported in the injection that carries the
    message -- the counter block was already built. The observable is the message arriving a second
    time, so that is what is measured.
    """
    info = seed(repo, tmp_path, [{"body": "delivered despite a broken shown dir"}])
    key = str(info["key"])
    box = mail_root(repo) / "box" / key
    box.mkdir(parents=True, exist_ok=True)
    (box / "shown").write_text("not a directory", encoding="ascii")

    text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "delivered despite a broken shown dir" in text
    assert len(box_files(repo, key, "inbox")) == 1
    assert box_files(repo, key, "seen") == []

    again = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "delivered despite a broken shown dir" in again, (
        "the display was suppressed by a mark that could not be written -- unmarked must resolve "
        "toward showing it again, never toward hiding it"
    )


def test_a_marker_path_occupied_by_a_directory_still_shows_the_mail(
    repo: Path, tmp_path: Path
) -> None:
    """The narrower shape: shown/ is fine, but this message's own marker path is a DIRECTORY, so the
    exclusive CreateNew can never win and the held probe can never prove a marker there either.

    That combination is exactly where an implementation could quietly decide the message had already
    been shown -- and the shipped drain did, in an earlier form, by re-probing after a failed create.
    It must resolve toward showing it, on every drain, for as long as the directory is in the way.
    """
    info = seed(
        repo, tmp_path, [{"stem": "20260101T000000001-aaaaaa", "body": "marker path taken"}]
    )
    key = str(info["key"])
    shown = mail_root(repo) / "box" / key / "shown"
    shown.mkdir(parents=True, exist_ok=True)
    (shown / marker_name("20260101T000000001-aaaaaa", SESSION_A)).mkdir()

    text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "marker path taken" in text
    assert len(box_files(repo, key, "inbox")) == 1

    again = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "marker path taken" in again
    assert len(box_files(repo, key, "inbox")) == 1


def test_a_receipt_that_cannot_be_written_costs_a_duplicate_display_not_the_message(
    repo: Path, tmp_path: Path
) -> None:
    """A MESSAGE WHOSE RECEIPT CANNOT BE WRITTEN MUST NOT BE MARKED, and this is the case that rule
    exists for.

    Marking is nested inside the receipt's own try. If a message were marked without a receipt, a later
    Stop would consume it on the strength of the mark alone and the delivery would be permanently
    unprovable -- a real display that no artefact records. Unmarked costs a duplicate display, which is
    this channel's accepted direction.

    Simulated by making the receipt path a DIRECTORY, which is what the existing unwritable-receipt arm
    uses: Set-Content cannot write it.
    """
    stem = "20260101T000000001-aaaaaa"
    info = seed(repo, tmp_path, [{"stem": stem, "body": "shown twice beats shown never"}])
    key = str(info["key"])
    rd = mail_root(repo) / "receipts"
    rd.mkdir(parents=True, exist_ok=True)
    (rd / f"{stem}.json").mkdir()

    first = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "shown twice beats shown never" in first
    assert marker_name(stem, SESSION_A) not in markers(repo, key), (
        "a message was marked as shown with no receipt on disk -- a later Stop would then consume it "
        "and nothing anywhere would record that it was ever displayed"
    )

    second = injection(run_drain(repo, event="Stop", session_id=SESSION_A))
    assert "shown twice beats shown never" in second, (
        "the message was consumed UNSEEN -- an unreceipted display must resolve to showing it again"
    )
    assert box_files(repo, key, "inbox") == []
    # IT LANDS IN claiming/, NOT seen/, AND THAT IS DELIBERATE. Write-MailReceipt uses -ErrorAction
    # Stop precisely so a receipt that cannot be written SKIPS the finalize move: without it the
    # Set-Content failure was non-terminating under the script's SilentlyContinue preference, and the
    # message reached seen/ with no receipt anywhere -- consumed, with delivery unprovable forever.
    # The residue is observable in mail.ps1 -Status, and the next drain's dead-owner sweep moves it to
    # stranded/. What matters here is that it left the inbox exactly once and was displayed both times.
    assert len(box_files(repo, key, "claiming")) == 1
    assert box_files(repo, key, "seen") == []


def test_a_receipt_written_by_another_session_does_not_consume_this_one_s_mail(
    repo: Path, tmp_path: Path
) -> None:
    """THE REGRESSION GUARD ON THE MEASURED CRITICAL, and the reason the receipt is not consulted.

    The receipt filename is ``<stem>.json`` -- ONE SLOT PER MESSAGE. An earlier form of this drain
    treated "a marker naming me plus a receipt for this message" as proof that I had been shown it, and
    a phantom session's receipt satisfied the second half for everybody. Measured against that code: the
    phantom displayed the mail, a second session acquired a marker without ever seeing it, and that
    session's Stop moved the message to ``seen/`` having rendered nothing. Nobody was shown it and the
    receipt asserted that somebody had been.

    Here the phantom's receipt exists and the surviving session has no marker. It must be SHOWN the
    mail, not have it consumed out from under it.
    """
    stem = "20260101T000000001-aaaaaa"
    info = seed(repo, tmp_path, [{"stem": stem, "body": "a receipt is not a per-session record"}])
    key = str(info["key"])

    # The phantom: it displays the mail and writes the only receipt this message will ever have.
    assert "a receipt is not a per-session record" in injection(
        run_drain(repo, event="SessionStart", session_id=SESSION_A)
    )
    assert receipts(repo) == [f"{stem}.json"]
    assert len(box_files(repo, key, "inbox")) == 1

    text = injection(run_drain(repo, event="Stop", session_id=SESSION_B))
    assert "a receipt is not a per-session record" in text, (
        "a session was denied a display it never had, on the strength of ANOTHER session's receipt -- "
        "and then consumed the message"
    )
    assert len(box_files(repo, key, "seen")) == 1


def test_a_planted_marker_suppresses_a_display_and_says_only_that(
    repo: Path, tmp_path: Path
) -> None:
    """A MARKER IS THE PER-SESSION RECORD OF A DISPLAY, so a file placed in ``shown/`` by anything else
    suppresses one and lets the next Stop consume the message. That is inside this channel's stated
    trust boundary -- the same writer could delete the message outright -- and the drain's header says
    so instead of claiming a defence it does not have.

    WHAT IS ASSERTED HERE IS THE REPORTING, because the earlier code got that wrong in a way no
    operator could have untangled: Pass 1 let the message through as a candidate and Pass 3 then
    silently dropped it, so ONE message produced both "HELD ... consumed at this session's next turn
    boundary" and "shown again rather than consumed unseen" in the same injection. Two sentences about
    one message, disagreeing, neither true.
    """
    stem = "20260101T000000001-aaaaaa"
    info = seed(repo, tmp_path, [{"stem": stem, "body": "a planted marker hides me"}])
    key = str(info["key"])
    shown = mail_root(repo) / "box" / key / "shown"
    shown.mkdir(parents=True, exist_ok=True)
    (shown / marker_name(stem, SESSION_A)).write_text("{}", encoding="ascii")

    text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "a planted marker hides me" not in text
    assert "have already been shown to this session and were NOT shown again" in text
    assert "no receipt to back it" not in text, "a retired counter is still being emitted"
    assert "shown again rather than consumed unseen" not in text, (
        "the injection claims the message was shown again; it was not"
    )
    assert len(box_files(repo, key, "inbox")) == 1


def test_a_case_variant_marker_is_one_file_and_is_reported_as_one(
    repo: Path, tmp_path: Path
) -> None:
    """THE TWO STATEMENTS MUST NOT BOTH BE TRUE OF ONE FILE.

    ``Split-ShownMarkerName`` used to decide ownership with a case-SENSITIVE compare while NTFS
    resolves both spellings to the SAME file. A ``shown/`` name differing from a minted one only in the
    case of its session half was therefore reported as "a name this channel did not mint and was left
    alone", exempted from both sweeps, and simultaneously used as this session's marker by CreateNew,
    Test-FilePresent and Remove-Item -- the drain suppressing a display on the strength of a file it had
    just told the reader it was ignoring.

    Accepting the variant is the side that makes the report true: it IS the file this channel would
    mint for that id, by path identity on this platform. So it acts as a marker AND the counter block
    stays silent about foreign names AND the sweeps can clean it up.
    """
    stem = "20260101T000000001-aaaaaa"
    info = seed(repo, tmp_path, [{"stem": stem, "body": "one file, one story"}])
    key = str(info["key"])
    shown = mail_root(repo) / "box" / key / "shown"
    shown.mkdir(parents=True, exist_ok=True)
    (shown / f"{stem}--{SESSION_A.upper()}.marker").write_text("{}", encoding="ascii")

    text = injection(run_drain(repo, event="SessionStart", session_id=SESSION_A))
    assert "file(s) in shown/ carry a name this channel did not mint" not in text
    assert "one file, one story" not in text

    injection(run_drain(repo, event="Stop", session_id=SESSION_A))
    assert box_files(repo, key, "inbox") == []
    assert len(box_files(repo, key, "seen")) == 1
    assert markers(repo, key) == [], "a case variant was consumed but never swept"


def test_a_receipt_never_pairs_one_sessions_id_with_anothers_emit_time(
    repo: Path, tmp_path: Path
) -> None:
    """The receipt is ONE SLOT PER MESSAGE, so its two identifying fields must describe ONE emit.

    Under the accepted duplicate, several sessions display the same message and each overwrites that
    slot. The failure to guard against is a receipt naming session A while carrying the timestamp of
    B's display -- a file asserting a display that did not happen at that time, by that session.

    This used to be enforced by sourcing ``observedUtc`` from the per-(message, session) MARKER. That
    is gone: markers may no longer be trusted across invocations, because a session id is REUSED
    ACROSS LAUNCHES and an inherited marker let a session consume mail it had never seen. The property
    is now structural instead -- a consuming drain RENDERS what it consumes, so the id and the stamp
    both come from the same emit and cannot disagree.
    """
    stem = "20260101T000000001-aaaaaa"
    seed(repo, tmp_path, [{"stem": stem, "body": "two sessions, one receipt slot"}])

    run_drain(repo, event="SessionStart", session_id=SESSION_A)
    shown_by_a = receipt_json(repo, stem)["observedUtc"]
    assert shown_by_a

    # B displays the same message and overwrites the single receipt slot with its own emit time.
    run_drain(repo, event="SessionStart", session_id=SESSION_B)
    shown_by_b = receipt_json(repo, stem)["observedUtc"]
    assert shown_by_b != shown_by_a

    text = injection(run_drain(repo, event="Stop", session_id=SESSION_A))
    assert "two sessions, one receipt slot" in text, (
        "the consuming drain must render what it consumes"
    )

    final = receipt_json(repo, stem)
    assert final["disposition"] == "shown-consumed"
    assert final["bySessionId"] == SESSION_A
    # The stamp belongs to A's OWN consuming emit -- later than B's display, and not B's.
    assert final["observedUtc"] != shown_by_b, (
        "the receipt names session A but carries B's emit time"
    )
    assert final["observedUtc"] > shown_by_b, (
        "the consuming receipt's stamp predates a display that happened before it"
    )


def test_the_off_switch_neither_shows_nor_consumes_held_mail(repo: Path, tmp_path: Path) -> None:
    """mail.ps1 -Status tells an operator that held mail is consumed at the first turn boundary AFTER
    the OFF switch is removed. That is a claim about behaviour, so it is asserted here rather than
    left as prose -- a compensating statement resting on an unverified premise is the shape CLAUDE.md
    section 11 forbids.
    """
    info = seed(repo, tmp_path, [{"body": "held while OFF goes up"}])
    key = str(info["key"])
    stem = str(info["rows"][0]["stem"])

    assert "held while OFF goes up" in injection(
        run_drain(repo, event="SessionStart", session_id=SESSION_A)
    )
    (mail_root(repo) / "OFF").write_text("", encoding="ascii")

    suppressed = injection(run_drain(repo, event="Stop", session_id=SESSION_A))
    assert "SUPPRESSED" in suppressed
    assert len(box_files(repo, key, "inbox")) == 1, "OFF did not stop the consume"
    assert box_files(repo, key, "seen") == []
    assert marker_name(stem, SESSION_A) in markers(repo, key)

    (mail_root(repo) / "OFF").unlink()
    run_drain(repo, event="Stop", session_id=SESSION_A)
    assert box_files(repo, key, "inbox") == []
    assert len(box_files(repo, key, "seen")) == 1


# --- 8f. What the operator is told. --------------------------------------------------------------


def test_status_reports_held_mail_as_held_rather_than_as_undelivered(
    repo: Path, tmp_path: Path
) -> None:
    """A RECEIPT NO LONGER IMPLIES FINALITY, so the reporting layer must not imply it either.

    Under the split a message can be emitted at SessionStart and still be sitting in the inbox.
    Reporting that as "Undelivered" would put the very defect this channel exists to make visible --
    queued is not delivered -- back one rung up, at the instrument an operator reaches for when they
    suspect the channel is broken.
    """
    info = seed(repo, tmp_path, [{"body": "held, not undelivered"}])
    key = str(info["key"])
    run_drain(repo, event="SessionStart", session_id=SESSION_A)

    held = json.loads(mail_cmd(repo, "-Status", "-Json").stdout)
    assert held["Inbox"] == 1
    assert held["ShownHeld"] == 1
    assert held["Seen"] == 0

    text = mail_cmd(repo, "-Status").stdout
    assert "Undelivered:" not in text, "held mail was reported as undelivered"
    assert "have already been shown to a session" in text
    assert f"shown={1}" in mail_cmd(repo, "-List").stdout

    run_drain(repo, event="Stop", session_id=SESSION_A)
    done = json.loads(mail_cmd(repo, "-Status", "-Json").stdout)
    assert done["Inbox"] == 0
    assert done["ShownHeld"] == 0
    assert done["Seen"] == 1
    assert markers(repo, key) == []


def test_the_held_count_only_counts_names_this_channel_minted(repo: Path, tmp_path: Path) -> None:
    """DISCRIMINATOR for the count above, and it is a real hardening rather than tidiness: shown/ is
    writable by anything running as this user, so a raw file count would let any local process inflate
    a number an operator reads as "mail already shown to somebody".
    """
    info = seed(repo, tmp_path, [{"body": "one real display"}])
    key = str(info["key"])
    run_drain(repo, event="SessionStart", session_id=SESSION_A)
    (mail_root(repo) / "box" / key / "shown" / "evil.marker").write_text("{}", encoding="ascii")
    assert json.loads(mail_cmd(repo, "-Status", "-Json").stdout)["ShownHeld"] == 1


# --- 8g. Retention reaches every box, and the receipt sweep is guarded. --------------------------
#
# THE DEFECT THESE EXIST FOR. The retention sweep read this worktree's box and nothing else, so a box
# whose worktree has been removed never drained, never swept, and kept everything forever. Measured
# read-only on the live spool 2026-09-17, over 188 boxes: 23,855 of 24,205 files in seen/ were already
# past a rule written to delete them. receipts/ is one flat directory for the whole queue, which no
# box-scoped loop could reach at all: 33,121 of its 33,474 files were past the same rule.
#
# WIDENING A DELETE IS NOT LIKE WIDENING A READ, which is why every arm below plants a SURVIVOR beside
# the file it expects to lose. A sweep that deletes everything and a guard that protects everything
# fail identically from the outside: both leave a drain that exits 0 and a counter line that reads as
# if it worked. The controls are therefore planted in both directions -- one file per guard that must
# survive, and files that must go, in the same tree and in the same pass.

DEAD_BOX = "gone-wt-deadbeef"
# Valid under Test-ClaimToken: four hex, three short hex groups, then eight hex.
PLANT_TOKEN = "abcd-1-1-1-deadbeef"

# One stem per plant, so a failure names the guard rather than a file. All are valid under
# Test-MailStem. Minted by hand rather than through New-MessageId deliberately: an arm that asserts a
# file SURVIVED has to be able to name it afterwards.
STEM_SWEPT = "20260101T000000101-aaaaaa"  # aged, in a dead box's seen/ -- must go
STEM_FRESH = "20260101T000000102-aaaaaa"  # inside the window -- must stay
STEM_FREE = "20260101T000000103-aaaaaa"  # aged receipt, no message, uncited -- must go
STEM_C5_INBOX = "20260101T000000104-aaaaaa"  # C5: its message is still undelivered
STEM_C5_CLAIMING = "20260101T000000105-aaaaaa"  # C5: its message is mid-claim
STEM_C5_STRANDED = "20260101T000000106-aaaaaa"  # C5: its message was left by a dead claimer
STEM_C8 = "20260101T000000107-aaaaaa"  # C8: quoted in a handoff outside mail/
STEM_C8_MAIL_ONLY = "20260101T000000108-aaaaaa"  # quoted only INSIDE mail/ -- must go
STEM_C8_RETIRED = "20260101T000000109-aaaaaa"  # quoted only in the frozen tree -- must go
STEM_BOTH_HALVES = "20260101T000000110-aaaaaa"  # receipt AND an aged seen/ twin
STEM_MAIL_CITER = "20260101T000000111-aaaaaa"  # the in-queue message that does the quoting
STEM_UNMINTED = "20260101T000000112-aaaaaa"  # a receipts/ name this channel does not mint

# The stems that must still have a receipt after a guarded pass, one per guard.
SURVIVORS = (STEM_C5_INBOX, STEM_C5_CLAIMING, STEM_C5_STRANDED, STEM_C8, STEM_BOTH_HALVES)


def coord_root(repo: Path) -> Path:
    """``.git/mefor-coord`` -- the tree the citation guard reads, of which ``mail/`` is one child."""
    return mail_root(repo).parent


def age_out(p: Path) -> None:
    """Put a file one day past the retention window, the way 8d already ages a marker."""
    aged = p.stat().st_mtime - (RETAIN_DAYS + 1) * 86400
    os.utime(p, (aged, aged))


def plant_message(
    repo: Path, box: str, state: str, stem: str, *, aged: bool = True, body: str = ""
) -> Path:
    """A message file under any box and any state, named the way this channel names one.

    Written by hand rather than through ``seed``: the seeder addresses the DRAIN's own box by
    construction, and the whole subject here is the boxes it does not address.
    """
    d = mail_root(repo) / "box" / box / state
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{stem}--{PLANT_TOKEN}.json"
    p.write_text(json.dumps({"v": 1, "id": stem, "body": body}), encoding="ascii")
    if aged:
        age_out(p)
    return p


def plant_receipt(repo: Path, stem: str, *, name: str | None = None) -> Path:
    """An aged receipt. ``name`` overrides the ``<stem>.json`` shape, for the unminted-name arm."""
    d = mail_root(repo) / "receipts"
    d.mkdir(parents=True, exist_ok=True)
    p = d / (name or f"{stem}.json")
    p.write_text(json.dumps({"v": 2, "messageId": stem}), encoding="ascii")
    age_out(p)
    return p


def plant(repo: Path, tmp_path: Path) -> dict[str, Any]:
    """ONE tree, planted identically for the guarded arms and for the unguarded control.

    Shared on purpose: a control that measures a different tree from the thing it controls proves
    nothing, and two copies would drift the first time an arm gained a plant of its own.
    """
    info = seed(repo, tmp_path, [{"body": "live mail, so the drain gets past its own box"}])

    # A box whose worktree is gone. Nothing will ever drain it again, which is the whole defect.
    plant_message(repo, DEAD_BOX, "seen", STEM_SWEPT)
    plant_message(repo, DEAD_BOX, "seen", STEM_FRESH, aged=False)
    plant_message(repo, DEAD_BOX, "seen", STEM_BOTH_HALVES)
    plant_message(repo, DEAD_BOX, "inbox", STEM_C5_INBOX)
    plant_message(repo, DEAD_BOX, "claiming", STEM_C5_CLAIMING)
    plant_message(repo, DEAD_BOX, "stranded", STEM_C5_STRANDED)
    # Inside the queue, quoting another message's id. The citation guard must NOT see this one, or
    # every receipt in the directory would read as cited and the sweep would delete nothing.
    plant_message(
        repo,
        DEAD_BOX,
        "seen",
        STEM_MAIL_CITER,
        aged=False,
        body=f"chasing {STEM_C8_MAIL_ONLY}, which never arrived",
    )

    for stem in (
        STEM_FREE,
        STEM_C5_INBOX,
        STEM_C5_CLAIMING,
        STEM_C5_STRANDED,
        STEM_C8,
        STEM_C8_MAIL_ONLY,
        STEM_C8_RETIRED,
        STEM_BOTH_HALVES,
    ):
        plant_receipt(repo, stem)
    plant_receipt(repo, STEM_UNMINTED, name=f"{STEM_UNMINTED}--{PLANT_TOKEN}.json")

    handoffs = coord_root(repo) / "handoffs"
    handoffs.mkdir(parents=True, exist_ok=True)
    (handoffs / "NOTE.md").write_text(
        f"Handed over mid-flight. The record of what happened is {STEM_C8}.\n", encoding="ascii"
    )
    frozen = coord_root(repo) / "_retired-2026-08-22"
    frozen.mkdir(parents=True, exist_ok=True)
    (frozen / "old-handoff.md").write_text(
        f"Frozen tree, read back by nobody: {STEM_C8_RETIRED}.\n", encoding="ascii"
    )
    return info


def run_script(
    script: Path, repo: Path, *, event: str = "Stop", session_id: str = SESSION_A
) -> subprocess.CompletedProcess[str]:
    """``run_drain`` against a drain that is not the shipped one, for the planted controls."""
    payload = {"hook_event_name": event, "cwd": str(repo), "session_id": session_id}
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=str(repo),
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"{script.name} exited {proc.returncode}: {proc.stderr}"
    assert not proc.stderr.strip(), f"{script.name} wrote to stderr: {proc.stderr}"
    return proc


def rewrite_drain(tmp_path: Path, filename: str, func: str, replacement: str) -> Path:
    """A copy of the shipped drain with ONE function replaced, dot-sourcing the REAL libraries.

    THE COPY IS THE CONTROL. Asserting that a guard protects a file proves nothing on its own -- a
    sweep that deletes nothing at all passes every such assertion -- so each guard is also run in a
    build where that guard is gone, against the same plants, and the plants must die there.

    Two assertions keep the instrument honest. The dot-source rewrite must find both library paths,
    because ``$PSScriptRoot`` points at ``tmp_path`` in the copy and an un-rewritten copy would load
    neither library. The function substitution must match exactly once. Without them a strip that
    silently matched nothing would leave a control agreeing with its subject for the wrong reason.
    """
    text = DRAIN.read_text(encoding="ascii")
    prefix = '"$PSScriptRoot\\..\\coord\\'
    assert text.count(prefix) == 2, "the drain no longer dot-sources its libraries the same way"
    dotted = text.replace(prefix, '"' + str(COORD) + "\\")
    pattern = re.compile(rf"(?ms)^function {re.escape(func)} \{{.*?^\}}")
    out, n = pattern.subn(lambda _m: replacement, dotted)
    assert n == 1, f"the {func} rewrite matched {n} times, so this control proves nothing"
    p = tmp_path / filename
    p.write_text(out, encoding="ascii")
    return p


# The guard, neutralised. Everything else about the drain is byte-identical.
NO_GUARD = """function Test-ReceiptProtected {
    param($Stem, $MessageStems, $CitedStems)
    return $false
}"""


def test_the_retention_sweep_reaches_a_box_whose_worktree_is_gone(
    repo: Path, tmp_path: Path
) -> None:
    """THE WIDENING, WITH ITS OWN DISCRIMINATOR BESIDE IT.

    A sweep that reached every box and deleted every file in it would pass the first assertion here,
    so the fresh plant in the same directory is what makes the aged one mean something. The three
    non-terminal states are the other half: the state list is the whole safety property of widening a
    delete, and on the live spool it is what stands between this loop and 285 undelivered messages
    plus 6 stranded records.
    """
    plant(repo, tmp_path)
    text = injection(run_drain(repo, event="Stop", session_id=SESSION_A))

    dead = mail_root(repo) / "box" / DEAD_BOX / "seen"
    assert not (dead / f"{STEM_SWEPT}--{PLANT_TOKEN}.json").exists(), (
        "a dead worktree's box was still not swept"
    )
    assert (dead / f"{STEM_FRESH}--{PLANT_TOKEN}.json").exists(), (
        "the sweep took a file inside the retention window"
    )
    for state, stem in (
        ("inbox", STEM_C5_INBOX),
        ("claiming", STEM_C5_CLAIMING),
        ("stranded", STEM_C5_STRANDED),
    ):
        p = mail_root(repo) / "box" / DEAD_BOX / state / f"{stem}--{PLANT_TOKEN}.json"
        assert p.exists(), f"the sweep reached {state}/, which is not a terminal directory"

    m = re.search(r"(\d+) message\(s\) older than \d+ days were removed .* across (\d+) box", text)
    assert m, f"the widened sweep was silent:\n{text}"
    assert int(m.group(2)) >= 2, "the sweep only ever saw this worktree's own box"


def test_a_receipt_is_kept_while_the_message_it_describes_is_still_in_play(
    repo: Path, tmp_path: Path
) -> None:
    """GUARD C5, over all three of its states.

    A receipt is the only record of what was observed about a message. While that message is still in
    inbox/, claiming/ or stranded/ -- undelivered, mid-claim, or left behind by a session that died --
    deleting its receipt makes ``mail.ps1 -Status`` report a file anyone can open as delivery
    UNPROVEN, which is a false statement rather than a missing one.
    """
    plant(repo, tmp_path)
    run_drain(repo, event="Stop", session_id=SESSION_A)
    left = receipts(repo)
    for stem in (STEM_C5_INBOX, STEM_C5_CLAIMING, STEM_C5_STRANDED):
        assert f"{stem}.json" in left, f"C5 did not hold for a message still in play: {stem}"
    # The discriminator: the sweep was running, and it did take the receipt beside them.
    assert f"{STEM_FREE}.json" not in left, "the sweep deleted nothing, so C5 proves nothing"


def test_a_receipt_is_kept_while_anything_outside_the_queue_quotes_it(
    repo: Path, tmp_path: Path
) -> None:
    """GUARD C8, AND THE TWO EXCLUSIONS THAT MAKE IT MEAN ANYTHING.

    Stems are quoted by hand into handoff notes and seat records, so a receipt is a citation target
    and deleting one turns a live citation into a dangling one. The exclusions are the other half.
    The queue is made of stems, so a scan that read ``mail/`` would report every receipt as cited and
    the sweep would delete nothing while looking exactly like a sweep that ran. The frozen tree is
    excluded for the opposite reason: a citation nobody reads back would pin receipts forever.
    """
    plant(repo, tmp_path)
    run_drain(repo, event="Stop", session_id=SESSION_A)
    left = receipts(repo)

    assert f"{STEM_C8}.json" in left, "a receipt quoted in a handoff was deleted"
    assert f"{STEM_C8_MAIL_ONLY}.json" not in left, (
        "a stem quoted only INSIDE the queue protected its receipt, so the scan reads mail/ and the"
        " sweep is a no-op wearing a counter line"
    )
    assert f"{STEM_C8_RETIRED}.json" not in left, (
        "a citation in the frozen tree protected its receipt"
    )
    # A name this channel does not mint for a receipt is left alone, exactly as an unowned file in
    # claiming/ or shown/ is. Test-MailStem is what refuses it; Split-MailFileName would have refused
    # every receipt in the directory instead, and the sweep would have done nothing at all.
    assert f"{STEM_UNMINTED}--{PLANT_TOKEN}.json" in left, (
        "the sweep deleted a receipts/ name this channel did not mint"
    )


def test_a_receipt_and_its_message_are_never_removed_by_the_same_pass(
    repo: Path, tmp_path: Path
) -> None:
    """THE BOTH-HALVES RULE, AND THE SECOND PASS THAT PROVES IT IS A DELAY AND NOT A PARDON.

    The keep set is read before anything is deleted, so a receipt whose message this same drain is
    about to remove from seen/ is still protected when its own turn comes. A reader who finds one
    half gone can therefore always still find the other. One drain later the message is gone from
    every box and the receipt follows it.
    """
    plant(repo, tmp_path)
    twin = mail_root(repo) / "box" / DEAD_BOX / "seen" / f"{STEM_BOTH_HALVES}--{PLANT_TOKEN}.json"

    run_drain(repo, event="Stop", session_id=SESSION_A)
    assert not twin.exists(), "the message half was not swept, so the rule was never exercised"
    assert f"{STEM_BOTH_HALVES}.json" in receipts(repo), (
        "a receipt and its message were removed by one pass"
    )

    run_drain(repo, event="Stop", session_id=SESSION_B)
    assert f"{STEM_BOTH_HALVES}.json" not in receipts(repo), (
        "the receipt is pardoned rather than delayed, so nothing ever bounds receipts/"
    )


def test_an_unguarded_sweep_takes_every_one_of_the_planted_survivors(
    repo: Path, tmp_path: Path
) -> None:
    """THE PLANTED CONTROL FOR ALL THREE GUARDS, and the reason the arms above are evidence.

    Same plants, same tree, one build in which ``Test-ReceiptProtected`` answers "not protected".
    Every survivor dies here. If one did not, the arms above would be passing because the sweep never
    reached that file, and no assertion inside them could tell the two apart.
    """
    plant(repo, tmp_path)
    unguarded = rewrite_drain(
        tmp_path, "mail-drain-unguarded.ps1", "Test-ReceiptProtected", NO_GUARD
    )
    run_script(unguarded, repo)

    left = receipts(repo)
    for stem in SURVIVORS:
        assert f"{stem}.json" not in left, (
            f"{stem} survived a build with no guard in it, so its guarded arm proves nothing"
        )
    assert f"{STEM_FREE}.json" not in left


@pytest.mark.parametrize("func", ["Get-LiveMessageStems", "Get-CitedStems"])
def test_the_receipt_sweep_keeps_everything_when_a_guard_cannot_be_built(
    repo: Path, tmp_path: Path, func: str
) -> None:
    """FAIL CLOSED, BY FAULT INJECTION, because the real condition is not reachable from a test.

    Either guard set can fail to build -- an unreadable directory, an I/O error part way through a
    walk -- and a half-built set is byte-identical to a complete one. The rule is that a guard which
    could not be evaluated keeps the file, and says so.

    THE WIRING IS WHAT IS TESTED HERE, NOT THE CONDITION. Making the real walk fail needs an ACL
    change or a cross-process file lock, so this arm proves that a throw out of either builder
    reaches the skip, that the drain still delivers, and that the reader is told.
    """
    plant(repo, tmp_path)
    stub = f"function {func} {{\n    param($A, $B, $C)\n    throw 'injected failure'\n}}"
    broken = rewrite_drain(tmp_path, f"mail-drain-{func}.ps1", func, stub)
    text = injection(run_script(broken, repo))

    left = receipts(repo)
    assert f"{STEM_FREE}.json" in left, "a guard could not be built and the sweep deleted anyway"
    for stem in SURVIVORS:
        assert f"{stem}.json" in left
    assert "The receipt sweep did not run" in text, f"the skip was silent:\n{text}"
    # Delivery is unaffected: housekeeping must never break the turn it precedes.
    assert "live mail, so the drain gets past its own box" in text


STEM_PROBE = r"""
. "__MAIL_KEY__"
$anchored = [regex]::new('\A' + (Get-MailStemPattern) + '\z')
$rows = @()
foreach ($i in 1..50) {
    $id = New-MessageId
    $rows += [pscustomobject]@{
        s = $id; v = (Test-MailStem -Stem $id); p = $anchored.IsMatch($id)
    }
}
$bads = @('', 'not-a-stem', '20260101T000000001-AAAAAA', '20260101T00000000-aaaaaa')
foreach ($bad in $bads) {
    $rows += [pscustomobject]@{
        s = $bad; v = (Test-MailStem -Stem $bad); p = $anchored.IsMatch($bad)
    }
}
$q = New-MessageId
$loose = [regex]::new((Get-MailStemPattern))
$found = @($loose.Matches("see message $q, which never arrived") | ForEach-Object { $_.Value })
([pscustomobject]@{ rows = @($rows); quoted = $q; found = @($found) } | ConvertTo-Json -Depth 5)
"""


def test_the_stem_search_pattern_and_the_stem_validator_agree(tmp_path: Path) -> None:
    """THE ONE DRIFT THAT WOULD LOSE DATA, PINNED.

    ``Get-MailStemPattern`` proposes citations and ``Test-MailStem`` decides them, so a pattern that
    is too loose costs a wasted comparison. A pattern that is too TIGHT misses a citation, and a
    missed citation deletes a receipt somebody is still pointing at. The two live beside each other
    in mail-key.ps1; this is what keeps them agreeing.
    """
    probe = tmp_path / "stem-probe.ps1"
    probe.write_text(STEM_PROBE.replace("__MAIL_KEY__", str(MAIL_KEY)), encoding="ascii")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    for row in out["rows"]:
        assert row["v"] == row["p"], f"validator and search pattern disagree on {row['s']!r}"
    # A control, so a pattern that rejects everything cannot pass by agreeing everywhere.
    assert sum(1 for row in out["rows"] if row["v"]) == 50
    assert out["found"] == [out["quoted"]], "the pattern cannot find a stem quoted in a sentence"
