"""统一记录格式与跨模块共享的数据类型。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class IngestStatus(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


@dataclass(slots=True)
class NormalizedEvent:
    """对外一致的统一审计记录格式（v1）。"""

    event_id: str
    source: str
    source_version: str
    schema_version: str
    event_type: str
    actor: str
    action: str
    resource: str
    result: str
    occurred_at: datetime
    ingested_at: datetime
    sequence: int = 0
    approval_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RejectedEvent:
    """校验未通过、不允许入库的事件及其原因（进入死信可查询，而非静默丢弃）。"""

    raw: dict[str, Any]
    reason: str
    received_at: datetime


@dataclass(slots=True)
class IngestResult:
    status: IngestStatus
    event_id: str | None = None
    sequence: int | None = None
    reason: str | None = None


@dataclass(slots=True)
class RuleConfig:
    rule_id: str
    rule_type: Literal["failure_threshold", "approval_required"]
    description: str = ""
    severity: Severity = Severity.WARNING
    # failure_threshold
    window_seconds: int = 0
    threshold: int = 0
    match_action: str | None = None
    match_result: str | None = None
    match_source: str | None = None
    # approval_required
    actions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Alert:
    alert_id: str
    rule_id: str
    rule_type: str
    severity: Severity
    message: str
    created_at: datetime
    updated_at: datetime
    event_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    status: Literal["open", "closed"] = "open"


@dataclass(slots=True)
class VerificationIssue:
    kind: Literal["tampered", "missing", "reordered", "corrupt_file"]
    location: str
    detail: str
    expected: str | None = None
    actual: str | None = None


@dataclass(slots=True)
class VerificationResult:
    ok: bool
    complete: bool
    records_verified: int
    first_sequence: int | None
    last_sequence: int
    cuts: list[dict[str, Any]] = field(default_factory=list)
    issues: list[VerificationIssue] = field(default_factory=list)


@dataclass(slots=True)
class DeliveryStatus:
    delivered: int = 0
    pending: int = 0
    failed: int = 0
    dead_letter: int = 0
