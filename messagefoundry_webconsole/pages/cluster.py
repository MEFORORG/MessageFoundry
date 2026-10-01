# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The High Availability page for the /ui ops dashboard (ADR 0056, BACKLOG #1495).

One page renders the whole cluster from whichever node serves it, because every node reads the same
shared ``nodes`` and ``leader_lease`` rows. That is why there is no "Viewing: Primary / Backup" toggle,
which is the part of ADR 0056's retired desktop-console section that still holds. The page is
read-mostly, with one control: a planned stepdown of the node serving it, plus the forced variant that
drains the last promotable node on purpose.

**It renders no VIP owner, and that is deliberate.** ``ClusterStatus`` has no ``vip`` member and the
engine binds no address, so a VIP field here would render a field that does not exist. For the same
reason no sentence on these pages says an address moves.

Every value goes through the escaping ``el`` builder. Node ids and hosts are cluster metadata, never PHI.
"""

from __future__ import annotations

from typing import Literal

from messagefoundry.api.models import ClusterNode, ClusterNodeList, ClusterStatus

from .._html import Markup, el, page, register_nav, rows_table
from .monitoring import _opt, _post_button, _ts, _yn

__all__ = [
    "high_availability",
    "high_availability_fragment",
    "stepdown_confirm",
    "stepdown_refused",
]

_PAGE = "/ui/cluster"
_CONFIRM = "/ui/cluster/stepdown-confirm"
_FORCE_CONFIRM = "/ui/cluster/force-stepdown-confirm"

_INTRO = (
    "Every node reads the same shared membership and lease rows, so this page shows the whole cluster "
    "from whichever node serves it. Clustering itself is set in configuration and needs a coordinated "
    "restart; this page reports it and does not change it."
)

# The post-stepdown notices, keyed by the redirect's ?m= code. An allow-list, so the query string can
# select a sentence but never supply one.
_NOTICES: dict[str, str] = {
    # "Lease", not "leadership": a self-fenced node no longer led when it released (BACKLOG #1988).
    "released": (
        "Leadership lease released. A standby takes the lease on its next heartbeat, or after its "
        "acquire delay if it has one. Before you start maintenance, wait until the lease owner below "
        "has moved and this node's connections are quiet."
    ),
    "drained": (
        "Leadership lease released with force, and no other node could take over. Nothing does leader work "
        "until a node takes the lease, and that may be this node again: it takes the lease back after "
        "its stepdown pause if no other node does. To keep leader work stopped, stop the service."
    ),
}

_NO_SUCCESSOR = (
    "No other node is active, promotable and fresh right now, so the engine would refuse a planned "
    "stepdown and change nothing. Start a promotable node first, or use the forced drain if you mean "
    "to drain this node anyway."
)


def _when(value: float | None) -> str:
    """A UTC timestamp, or a dash where the engine reported none (the single-node self-entry)."""
    return "—" if value is None else _ts(value)


def _takeover_candidates(nodes: ClusterNodeList, *, excluding: str | None) -> list[ClusterNode]:
    """Nodes that could take the lease right now: ``active``, ``promotable`` and ``fresh``.

    The rule the engine's ``has_promotable_sibling`` applies for its stepdown check (BACKLOG #1509),
    re-applied to the fields the engine publishes, because the console never imports ``pipeline/``.
    ``test_ui_cluster.py`` pins the two against each other. Display only: the engine takes its own
    membership read when a stepdown runs, and that read decides."""
    return [
        n
        for n in nodes.nodes
        if n.node_id != excluding and n.status == "active" and n.promotable and n.fresh
    ]


def _signals_agree(cluster: ClusterStatus, nodes: ClusterNodeList) -> bool:
    """Whether this node's two leadership signals say the same thing about it.

    ``ClusterStatus.is_leader`` is the in-memory flag, which a stepdown clears and a claim sets at once.
    ``leader_node_id`` is the freshness-filtered heartbeat leader, which follows on the next tick. While
    they disagree, leadership is changing hands on this node."""
    return cluster.is_leader == (nodes.leader_node_id == cluster.node_id)


#: Where the lease stands for a node whose flag is clear while the engine would still send the
#: release write. ``holds``: the lease row names this node. ``moved``: it names another node, or no
#: row was read, so the owner-scoped write matches nothing and the engine refuses.
_FenceState = Literal["holds", "moved"]

#: The one sentence each state gets, so the page, the note and both confirm pages cannot drift.
#: ``{node}`` is the node serving the page. "Refuse", not a status: a planned stepdown with no fresh
#: promotable sibling answers 412 before the release would answer 409.
_FENCED: dict[_FenceState, str] = {
    "holds": "{node} no longer leads, but its lease row still names it.",
    "moved": (
        "{node} no longer leads, and the lease no longer names it. The engine has not seen the "
        "lease move yet, so a stepdown still sends the release. Expect the engine to refuse it "
        "and change nothing."
    ),
}


def _fence_state(cluster: ClusterStatus, nodes: ClusterNodeList) -> _FenceState | None:
    """``None`` unless this node's flag is clear and ``owns_lease_row`` is still True.

    The self-fence window is the case this exists for (BACKLOG #1508, #1988): the node stopped
    calling itself leader on its own clock while its lease row still names it on the database clock.
    The same two readings also hold while a stepdown's release write is owed or still in flight, so
    no sentence built on this names a cause. ``owns_lease_row`` is the engine's own drain test, so
    this reads no lease expiry, which the console has no database clock to judge."""
    if not (cluster.clustered and cluster.owns_lease_row and not cluster.is_leader):
        return None
    return "holds" if nodes.lease_owner == cluster.node_id else "moved"


def _fenced_note(node: str, state: _FenceState) -> str:
    """What a stepdown does on a node in a :data:`_FenceState`, shown beside the control. The
    ``holds`` state's description is the leadership banner above, so this does not repeat it."""
    if state == "holds":
        return (
            f"A stepdown releases the lease {node} no longer serves, so a standby can take over "
            "without waiting for it to expire."
        )
    return _FENCED["moved"].format(node=node)


def _control_blocker(
    cluster: ClusterStatus, nodes: ClusterNodeList, *, can_control: bool
) -> str | None:
    """Why the stepdown control is disabled, or ``None`` when it may be offered.

    A stepdown releases the lease of the node that SERVES the request. The control is offered only
    when the engine would send that release: ``ClusterStatus.owns_lease_row``, the coordinator's own
    ``may_own_lease_row()`` (BACKLOG #1988). That covers the leader and a self-fenced node alike, and
    it keeps a node that has just released its lease disabled. The console never works this out
    from ``lease_expires_at``: that is a database-clock time, and the console has no database clock
    to compare it with.

    So the control is NOT offered in every case the engine would drain. One wait is kept from
    before this change: a node whose flag is SET while its heartbeat does not name it. Usually it
    has just taken the lease, its page is still describing the failover that promoted it, and a
    stepdown would drain the new leader while the old one sits in its claim pause. The remaining
    checks only choose the sentence that explains a refusal."""
    if not cluster.clustered:
        return "Clustering is not enabled on this engine, so there is no leadership to release."
    if not can_control:
        return (
            "Stepping down needs the cluster:control permission, which only an Administrator holds."
        )
    if cluster.owns_lease_row:
        if cluster.is_leader and not _signals_agree(cluster, nodes):
            return (
                "Leadership is changing hands on this node: it holds the lease, but its heartbeat "
                "does not show it as leader yet. The control comes back once the heartbeat does."
            )
        return None
    leader = nodes.leader_node_id
    if leader == cluster.node_id:
        # The flag is clear and nothing is owed, yet the heartbeat still names this node: it has just
        # let go of its lease, and the heartbeat catches up on its next beat.
        return (
            "Leadership is changing hands on this node: it has let go of its lease, and its heartbeat "
            "still names it until the next beat. There is nothing left here to step down."
        )
    if leader is None:
        return (
            "No node holds live leadership right now, and this node has no lease left to release, "
            "so there is nothing here to step down. The control comes back if it takes the lease."
        )
    return (
        f"This console runs on {cluster.node_id}, which is not the leader. A stepdown acts only "
        f"on the node that serves it, so open the console on the leader, {leader}."
    )


def _leadership_state(cluster: ClusterStatus, nodes: ClusterNodeList) -> Markup:
    """One sentence about who leads, including the window a stepdown opens."""
    if not cluster.clustered:
        return el(
            "p", "Single node: this engine always leads, and it holds no lease.", class_="muted"
        )
    node = cluster.node_id
    state = _fence_state(cluster, nodes)
    leader = nodes.leader_node_id
    if state == "holds":
        # Not a failover in progress: no standby can take a lease row that still names this node
        # until it is released or expires, so the "next heartbeat" sentence below would be false.
        # Nor "no live leader": the heartbeat can still show this node as leader until one lands.
        return el(
            "p",
            _FENCED["holds"].format(node=node),
            " A standby can take the lease only once that row is released or expires. Until "
            f"{node}'s next heartbeat lands, the table can still show it as leader.",
            class_="banner",
        )
    if state == "moved" and nodes.lease_owner is not None and leader is None:
        # The lease owner here is the successor, not the node that let go, so the candidate list
        # below (which leaves the lease owner out) would name this node and hide the successor.
        return el(
            "p",
            f"Failover in progress: the lease names {nodes.lease_owner}, and its heartbeat shows "
            "it as leader on its next beat. This page refreshes every 5 seconds.",
            class_="banner",
        )
    if leader is not None and _signals_agree(cluster, nodes):
        line = f"Leader: {leader}."
        if nodes.lease_owner is not None and nodes.lease_owner != leader:
            line += (
                f" The lease names {nodes.lease_owner}. A short difference is normal during a "
                "failover, and the lease is the source of truth."
            )
        return el("p", line)
    # The window a stepdown opens (ADR 0056, step 4 of its console section, which outlives the console
    # it was written for). Say what is happening rather than only that no leader exists, so the operator
    # who just clicked does not read a normal failover as a broken cluster. The lease owner is left out
    # of the count: after a stepdown it is the node that just let go.
    candidates = _takeover_candidates(nodes, excluding=nodes.lease_owner)
    if candidates:
        names = ", ".join(n.node_id for n in candidates)
        return el(
            "p",
            "Failover in progress: no node holds live leadership yet. A standby takes the lease on "
            "its next heartbeat, or after its acquire delay if it has one. Nodes that can take it: "
            f"{names}. This page refreshes every 5 seconds.",
            class_="banner",
        )
    return el(
        "p",
        "No live leader, and no node other than the lease owner is active, promotable and fresh, so "
        "nothing else can take the lease. Leadership returns when a promotable node takes it, which "
        "can be the node that released it once its stepdown pause ends.",
        class_="banner",
    )


def _badge(label: str, tone: str) -> Markup:
    return el("span", label, class_=f"status status-{tone}")


def _node_state(cluster: ClusterStatus, n: ClusterNode) -> Markup:
    """The per-node state line, from the engine's own signals (``status``, ``fresh``, ``is_leader``,
    ``promotable``). Never a client-side ``last_seen`` threshold, which would drift from the engine's
    freshness window."""
    if not cluster.clustered:
        return _badge("Single node, no heartbeat", "ok")
    if n.status != "active":
        return _badge("Left the cluster" if n.status == "left" else n.status, "warn")
    if not n.fresh:
        return _badge("Stale: heartbeat missed", "error")
    if n.is_leader:
        return _badge("Leader, running the graph", "ok")
    if n.promotable:
        return _badge("Standby, can take over", "ok")
    return _badge("Standby, never takes over (promotable = false)", "warn")


def _nodes_table(cluster: ClusterStatus, nodes: ClusterNodeList) -> Markup:
    rows = [
        [
            f"{n.node_id} (this console)" if n.node_id == cluster.node_id else n.node_id,
            _opt(n.host),
            _opt(n.pid),
            ("Primary" if n.is_leader else "Standby") if cluster.clustered else "single-node",
            _node_state(cluster, n),
            _yn(n.promotable),
            _yn(n.fresh) if cluster.clustered else "—",
            f"{n.acquire_delay_seconds:g}s",
            _when(n.started_at),
            _when(n.last_seen),
        ]
        for n in nodes.nodes
    ]
    headers = [
        "Node",
        "Host",
        "PID",
        "Role",
        "State",
        "Promotable",
        "Heartbeat fresh",
        "Acquire delay",
        "Started (UTC)",
        "Last seen (UTC)",
    ]
    # Not adjustable: the fragment is swapped every few seconds, which would reset any sort state.
    return rows_table(headers, rows, adjustable=False)


def _controls(cluster: ClusterStatus, nodes: ClusterNodeList, *, can_control: bool) -> Markup:
    """The one control, as two deliberately separate actions. Force is its own section and its own
    confirm page, never a checkbox beside the planned stepdown."""
    blocker = _control_blocker(cluster, nodes, can_control=can_control)

    def _button(label: str, confirm_path: str) -> Markup:
        if blocker is not None:
            return el("button", label, type="button", disabled=True, title=blocker)
        return el(
            "form",
            el("button", label, type="submit"),
            method="get",
            action=confirm_path,
            class_="ctl",
        )

    parts: list[object] = [
        el("h2", "Planned failover"),
        el(
            "p",
            "A planned stepdown makes this node release its leadership lease. A standby takes the "
            "lease on its next heartbeat, or after its acquire delay if it has one, and starts the "
            "graph. This node keeps running as a standby; it is not a shutdown.",
            class_="muted",
        ),
    ]
    state = _fence_state(cluster, nodes)
    if blocker is not None:
        parts.append(el("p", blocker, class_="muted"))
    elif state is not None:
        parts.append(el("p", _fenced_note(cluster.node_id, state)))
    parts.append(_button("Step down this node", _CONFIRM))
    if blocker is None and not _takeover_candidates(nodes, excluding=cluster.node_id):
        parts.append(el("p", _NO_SUCCESSOR, class_="banner"))
    parts += [
        el("h3", "Forced drain"),
        el(
            "p",
            "For draining the last promotable node on purpose. It waives one refusal only: that no "
            "other node could take over.",
            class_="muted",
        ),
        _button("Force a drain of this node", _FORCE_CONFIRM),
    ]
    return el("div", *parts)


def _live_body(cluster: ClusterStatus, nodes: ClusterNodeList, *, can_control: bool) -> Markup:
    """The refreshed inner body: the poll target ``app.js`` swaps in, so a control disabled during a
    failover comes back on its own once a fresh leader appears."""
    summary = rows_table(
        ["Field", "Value"],
        [
            [
                "Clustering",
                "enabled (active-passive)" if cluster.clustered else "disabled (single-node)",
            ],
            ["This console runs on", f"{cluster.node_id} ({cluster.role})"],
            ["Live leader", nodes.leader_node_id or "none right now"],
            ["Lease owner", _opt(nodes.lease_owner)],
            ["Lease expires (UTC)", _when(nodes.lease_expires_at)],
            ["Config version", cluster.config_version],
        ],
        adjustable=False,
    )
    return el(
        "div",
        el("h2", "Cluster"),
        _leadership_state(cluster, nodes),
        summary,
        el("h2", "Nodes"),
        _nodes_table(cluster, nodes),
        _controls(cluster, nodes, can_control=can_control),
        id="ha-live",
    )


def high_availability_fragment(
    cluster: ClusterStatus, nodes: ClusterNodeList, *, can_control: bool
) -> Markup:
    """Just the live body, fetched by ``app.js`` from ``/ui/cluster/live`` on an interval."""
    return _live_body(cluster, nodes, can_control=can_control)


def high_availability(
    cluster: ClusterStatus, nodes: ClusterNodeList, *, can_control: bool, notice: str = ""
) -> Markup:
    """The High Availability page: cluster state, per-node state and the stepdown control."""
    message = _NOTICES.get(notice)
    live = el(
        "div",
        _live_body(cluster, nodes, can_control=can_control),
        data_mf_fragment=True,
        data_fragment_url="/ui/cluster/live",
        data_fragment_ms="5000",
    )
    return page(
        "High Availability",
        el("h1", "High Availability"),
        el("p", message, class_="banner") if message else Markup(""),
        el("p", _INTRO, class_="muted"),
        live,
        active="cluster",
    )


def _releases(node: str, *, holds: bool) -> str:
    """The first sentence of either confirm page. A node in the ``holds`` fence state no longer
    leads, so what a stepdown releases there is its lease row, not leadership."""
    if holds:
        return (
            f"This releases the lease {node} no longer serves. {_FENCED['holds'].format(node=node)} "
            "No standby can take that lease until it is released or expires."
        )
    return f"This releases leadership on {node}."


def _moved_confirm_text(node: str) -> list[Markup]:
    """Both confirm pages in the ``moved`` fence state. The rest of their text describes a release
    that happens, so none of it is shown here, and no other node is listed as a candidate: the node
    the lease names now is the successor."""
    return [
        el("p", _FENCED["moved"].format(node=node)),
        el(
            "p",
            "The node the lease names now is the successor. Do not step it down.",
            class_="muted",
        ),
    ]


def _planned_confirm_text(node: str, others: list[ClusterNode], *, holds: bool) -> list[Markup]:
    text = [
        el(
            "p",
            f"{_releases(node, holds=holds)} A standby takes the lease on its next heartbeat, or "
            "after its acquire delay if it has one, and starts the graph.",
        ),
        el(
            "p",
            f"{node} keeps running as a standby. It does not wait for queues to empty before it "
            "releases the lease, and it is not a shutdown.",
        ),
    ]
    if not others:
        text.append(
            el(
                "p",
                _NO_SUCCESSOR + " ",
                el("a", "Open the forced drain", href=_FORCE_CONFIRM),
                ".",
                class_="banner",
            )
        )
    else:
        names = ", ".join(n.node_id for n in others)
        text.append(el("p", f"Nodes that can take over now: {names}."))
    text.append(
        el(
            "p",
            "Before you start maintenance, confirm on the High Availability page that the lease owner "
            "has moved and that this node's connections are quiet.",
            class_="muted",
        )
    )
    return text


def _force_confirm_text(node: str, others: list[ClusterNode], *, holds: bool) -> list[Markup]:
    text = [
        el("p", _releases(node, holds=holds)),
        el("p", "A forced drain goes ahead even when no other node can take over."),
    ]
    if not others:
        text.append(
            el(
                "p",
                "No other node is active, promotable and fresh right now, so after this nothing does "
                "leader work until a node takes the lease.",
                class_="banner",
            )
        )
    else:
        names = ", ".join(n.node_id for n in others)
        text.append(
            el(
                "p",
                f"Other nodes can take over right now ({names}), so this behaves like a planned "
                "stepdown and the audit log records the override. Use the planned stepdown unless you "
                "mean to override.",
            )
        )
    text += [
        el(
            "p",
            f"A forced drain does not stay drained. If no other node takes the lease, {node} takes it "
            "back on its first heartbeat after the stepdown pause, which lasts two heartbeats (20 "
            "seconds at the shipped default) plus the longest acquire delay among the other "
            "promotable nodes. To keep leader work stopped for a maintenance window, stop the "
            "service instead.",
        ),
        el(
            "p",
            "Force waives only that one refusal. It does not release a lease this node does not "
            "hold.",
            class_="muted",
        ),
    ]
    return text


def stepdown_confirm(cluster: ClusterStatus, nodes: ClusterNodeList, *, force: bool) -> Markup:
    """The step-up-unlock confirm page for a planned stepdown, or for a forced drain.

    It re-reads cluster state rather than trusting the page the operator clicked from, so a control
    that went stale in between renders its reason and NO form. It says what will happen: leadership is
    released on this node and a standby promotes."""
    title = "Force a drain" if force else "Planned stepdown"
    blocker = _control_blocker(cluster, nodes, can_control=True)
    parts: list[Markup]
    if blocker is not None:
        parts = [el("p", blocker)]
    else:
        node = cluster.node_id
        others = _takeover_candidates(nodes, excluding=node)
        state = _fence_state(cluster, nodes)
        holds = state == "holds"
        if force:
            parts = [
                *(
                    _moved_confirm_text(node)
                    if state == "moved"
                    else _force_confirm_text(node, others, holds=holds)
                ),
                _post_button("/ui/cluster/force-stepdown", f"Force the drain of {node}"),
            ]
        else:
            parts = [
                *(
                    _moved_confirm_text(node)
                    if state == "moved"
                    else _planned_confirm_text(node, others, holds=holds)
                ),
                _post_button("/ui/cluster/stepdown", f"Step down {node}"),
            ]
    back = el("p", el("a", "Back to High Availability", href=_PAGE))
    body = el("div", el("h1", title), *parts, back, class_="card detail-card")
    return page(title, body, active="cluster")


# One entry per refusal the stepdown handler raises itself. The STATUS is the discriminator, because
# the remedies differ and one of them is dangerous to confuse: a 412 must never send the operator off
# to find another leader, and a 409 after an unconfirmed release can be the failover having worked.
# A 403 is absent on purpose: the /ui gate refuses before this page could render, and the High
# Availability page already disables the control with the permission reason.
_REFUSALS: dict[int, tuple[str, tuple[Markup, ...]]] = {
    400: (
        "This engine is not clustered",
        (
            el("p", "There is no leadership lease to release, so nothing changed."),
            el(
                "p",
                "Clustering is set in configuration and needs a coordinated restart. This page does "
                "not turn it on.",
            ),
        ),
    ),
    409: (
        "This node holds no lease to release",
        (
            el(
                "p",
                "Nothing was released here: this node neither leads nor owns the lease row. A "
                "stepdown acts only on the node this console runs on.",
            ),
            # The successor warning comes BEFORE the remedy, because the remedy names the node the
            # warning protects: an operator who stops reading after one paragraph must not drain it.
            el(
                "p",
                "First check whether failover already worked. Two things point to it: an earlier "
                "stepdown here could not confirm its lease was expired, or this node had stopped "
                "leading before this stepdown ran. If the lease owner has moved to another node, "
                "that node is the healthy successor: do not step it down.",
            ),
            el(
                "p",
                "Otherwise, to step down the current leader, find it on the High Availability page "
                "and open the console there.",
            ),
        ),
    ),
    412: (
        "No other node could take over",
        (
            el(
                "p",
                "No other promotable node has a fresh heartbeat, so stepping this node down would "
                "leave nothing able to take the lease. Nothing changed.",
            ),
            el(
                "p",
                "This is not a wrong-node answer. Start a promotable node, then try again once the "
                "High Availability page shows it fresh.",
            ),
            el(
                "p",
                "To drain this node anyway, use the ",
                el("a", "forced drain", href=_FORCE_CONFIRM),
                ".",
            ),
        ),
    ),
    503: (
        "The stepdown did not finish",
        (
            el(
                "p",
                "The engine could not complete the call. Its message below says which case this is, "
                "and the next step differs:",
            ),
            el(
                "ul",
                el(
                    "li",
                    "It could not read cluster membership, or its leadership lock was still held: "
                    "nothing changed. Retry, and if it repeats, check the store connection.",
                ),
                el(
                    "li",
                    "It cleared its leadership flag but could not confirm the lease was expired: this "
                    "node has already stood down. Once the store answers again, retry once: the retry "
                    "re-sends the write, and answers 409 if a standby has already taken the lease. "
                    "Then check the lease owner.",
                ),
            ),
            el(
                "p",
                "Either way, confirm on the High Availability page that the lease owner has moved and "
                "this node's connections are quiet before you start maintenance.",
            ),
        ),
    ),
}

_UNKNOWN_REFUSAL: tuple[str, tuple[Markup, ...]] = (
    "The engine refused the stepdown",
    (el("p", "The engine's message below is the only explanation available for this answer."),),
)


def stepdown_refused(status: int, detail: str) -> Markup:
    """The page for a stepdown the engine refused: guidance keyed by status, then the engine's own
    message verbatim. That message carries node ids only, and it is the one place the three
    different ``503`` causes are told apart."""
    headline, guidance = _REFUSALS.get(status, _UNKNOWN_REFUSAL)
    body = el(
        "div",
        el("h1", headline),
        *guidance,
        el("h2", f"Engine message (status {status})"),
        el("p", detail),
        el("p", el("a", "Back to High Availability", href=_PAGE)),
        class_="card detail-card",
    )
    return page("Stepdown refused", body, active="cluster")


# Nav registration, co-located with the builders (ADR 0065 §multi-session-build). ``_html._NAV_GROUPS``
# places the key under Monitoring, after Status.
register_nav("cluster", _PAGE, "High Availability")
