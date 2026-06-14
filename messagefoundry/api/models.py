"""Response schemas for the localhost API.

These are the wire contract the console (and any other client) sees — deliberately
separate from the internal SQLite rows and channel-config models so storage/runtime
changes don't leak into the API. Message *list* responses carry metadata only; the raw
body (PHI) appears only in the single-message detail view, which is audited.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from messagefoundry.config.ai_policy import AiDataScope, AiEnvironment, AiMode


class ChannelInfo(BaseModel):
    id: str
    name: str
    enabled: bool
    running: bool
    source_type: str
    destinations: list[str]


class MessageSummary(BaseModel):
    id: str
    channel_id: str
    received_at: float
    source_type: str | None
    control_id: str | None
    message_type: str | None
    status: str
    error: str | None
    event: str | None = None  # latest processing event (received/delivered/failed/dead/replayed)
    summary: str | None = None  # ingest-derived: MRN/name (+ order/accession for ORM/ORU)
    metadata: str | None = None  # code/operator-attached values (mechanism TBD)


class MessageList(BaseModel):
    total: int
    limit: int
    offset: int
    messages: list[MessageSummary]


class OutboxInfo(BaseModel):
    id: str
    destination_name: str
    status: str
    attempts: int
    next_attempt_at: float
    last_error: str | None


class EventInfo(BaseModel):
    ts: float
    event: str
    destination: str | None
    detail: str | None


class MessageDetail(MessageSummary):
    """Full single-message view, including the raw body and delivery/audit trail."""

    raw: str
    outbox: list[OutboxInfo]
    events: list[EventInfo]


class ReplayResult(BaseModel):
    message_id: str
    requeued: int


class PurgeResult(BaseModel):
    cancelled: int


class DeadLetterRow(BaseModel):
    """One dead-lettered delivery (a message→destination that exhausted its retries)."""

    outbox_id: str
    message_id: str
    channel_id: str
    destination_name: str
    attempts: int
    last_error: str | None
    failed_at: float  # when the delivery was dead-lettered (outbox.updated_at)
    control_id: str | None
    message_type: str | None
    received_at: float
    summary: str | None = None  # PHI-bearing (MRN/name); display is audited


class DeadLetterList(BaseModel):
    total: int
    limit: int
    offset: int
    dead_letters: list[DeadLetterRow]


class DeadLetterReplayRequest(BaseModel):
    # Connection names; bounded so an over-long value can't reach the store query (ASVS 1.3.3).
    channel_id: str | None = Field(None, max_length=256)  # scope replay to one inbound (None = all)
    destination_name: str | None = Field(None, max_length=256)  # scope to one outbound (None = all)


class DeadLetterReplayResult(BaseModel):
    requeued: int


class ReloadRequest(BaseModel):
    # Directory of code-first config modules to load + apply. Optional: omitted/None reloads the
    # server's startup --config dir. Any value must resolve within an allowed reload root (the
    # startup dir or [api].config_reload_roots) — the loader executes Python from it. Length-bounded
    # (ASVS 1.3.3); the allow-list confinement remains the real control.
    config_dir: str | None = Field(None, max_length=4096)
    # dry_run: validate the graph against THIS environment (loads + build-checks connectors, which
    # resolves env() values for the target) and report the result WITHOUT swapping the live graph.
    # The promote pre-flight: catch a missing env value / bad spec before it goes live.
    dry_run: bool = False


class ReloadResult(BaseModel):
    """Summary of the graph that is now live after a reload — or, for a dry run, the graph that
    *would* go live (``dry_run=True``; ``running`` then reflects the still-current graph)."""

    inbound: int
    outbound: int
    routers: int
    handlers: int
    running: bool
    dry_run: bool = False


class ConnectionRow(BaseModel):
    """One endpoint (a channel's source, or one of its destinations) for the connections
    dashboard. Fields are role-dependent: source rows carry read/inbound-errored/idle and the
    listen peer/port; destination rows carry queue/written/dead/backlog/delivered-age and the
    remote peer/port. Unused fields are None so the UI can render blanks."""

    role: str  # "source" | "destination"
    channel_id: str
    channel_name: str
    destination: str | None  # destination name; None for the source row
    name: str  # display name
    status: str  # "running" | "stopped"
    direction: str  # "in" (source) | "out" (destination)
    method: str  # connection method/protocol, e.g. MLLP / File / TCP / REST
    peer: str | None  # MLLP host or file directory
    port: int | None
    queue_depth: int | None
    idle_seconds: float | None
    alerts_active: int  # stubbed 0 until the alerts feature exists
    errored: int | None  # source: inbound errors; destination: dead-lettered
    read: int | None  # source only: inbound received
    written: int | None  # destination only: delivered
    backlog_seconds: float | None  # destination only; None = unknown/stalled
    delivered_age_seconds: float | None  # destination only; age of oldest queued item


class StatsResponse(BaseModel):
    outbox_by_status: dict[str, int]


class Health(BaseModel):
    status: str = "ok"
    version: str


class EngineInfo(BaseModel):
    version: str
    uptime_seconds: float
    pid: int
    channels_total: int
    channels_running: int
    channels_stopped: int
    outbox_by_status: dict[str, int]


class DbInfo(BaseModel):
    path: str
    size_bytes: int  # db file + -wal + -shm
    disk_free_bytes: int
    journal_mode: str
    messages: int
    events: int
    audit: int


class SystemStatus(BaseModel):
    engine: EngineInfo
    db: DbInfo


class IntegrityResult(BaseModel):
    ok: bool
    detail: str


class ClusterStatus(BaseModel):
    """This node's cluster posture (Track B Step 7), from the cheap in-memory coordinator gates — no DB
    round-trip. ``clustered`` is False on a single node (NullCoordinator), where ``is_leader`` is always
    True and ``config_version`` is 0."""

    node_id: str
    clustered: bool
    is_leader: bool
    config_version: int


class ClusterNode(BaseModel):
    """One node in the cluster (Track B Step 7). ``is_leader`` is the DERIVED live leader (the durable
    ``nodes.is_leader`` heartbeat flag filtered for freshness, so a crashed ex-leader's stale flag is not
    reported). ``started_at``/``last_seen`` are epoch seconds, ``None`` only for the single-node
    synthetic self-entry."""

    node_id: str
    host: str | None
    pid: int | None
    status: str
    started_at: float | None
    last_seen: float | None
    is_leader: bool


class ClusterNodeList(BaseModel):
    """Cluster membership (Track B Step 7). ``leader_node_id`` is the node_id of the single derived
    leader, or ``None`` if no fresh node currently holds leadership."""

    nodes: list[ClusterNode]
    leader_node_id: str | None


class AiPolicy(BaseModel):
    """The effective AI-assistance policy for the IDE gate. ``assist_permitted`` is the
    identity-dependent bit: ``True``/``False`` when the caller's RBAC can be evaluated, ``None`` when
    no/invalid token under enabled auth made it unknown (a tokenless read still gets mode/scope, so a
    central ``off`` is honored)."""

    mode: AiMode
    data_scope: AiDataScope
    environment: AiEnvironment
    assist_permitted: bool | None
    reason: str | None = None
