"""核心数据模型：统一记录格式、留存记录、校验结论、告警、配置等。

时间一律使用带时区的 UTC（事件发生时间 event_time 保留来源原值信息，
规范化后统一为 epoch 毫秒整数 event_ts；ingest_ts 为接入时刻）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class VerifyStatus(str, Enum):
    """完整性校验总体结论。"""

    OK = "ok"                  # 链完整，且存储自初始化以来未发生过清理
    OK_AFTER_PRUNE = "ok_after_prune"  # 链完整，但存在过按策略的清理，非"完整无缺"
    TAMPERED = "tampered"      # 发现篡改/删除/乱序


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DeliveryState(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"         # 重试上限后仍失败，进入死信，可查询


@dataclass
class NormalizedEvent:
    """对外一致的统一审计记录格式。"""

    event_id: str                      # 来源 + 去重键归一得到的稳定标识
    source: str                        # 来源系统，如 "gitlab" / "jenkins"
    source_version: str               # 来源格式版本，如 "1.0"
    event_type: str                   # 统一动作类型，如 "login_failed" / "sensitive_op"
    actor: str                        # 操作主体
    target: str                        # 操作对象
    event_ts: int                      # 事件发生时间（epoch 毫秒）
    raw: dict[str, Any]               # 原始事件原文（留存）
    dedup_key: str                    # 幂等键
    approval_ref: str | None = None   # 审批记录引用
    severity: str = "info"
    extras: dict[str, Any] = field(default_factory=dict)
    ingest_ts: int = 0                # 接入时刻（epoch 毫秒）


@dataclass
class StoredEvent:
    """落库记录：在统一格式之外附加哈希链信息。"""

    seq: int                           # 单调递增序号，也是链上位置
    event_id: str
    source: str
    source_version: str
    event_type: str
    actor: str
    target: str
    event_ts: int
    ingest_ts: int
    dedup_key: str
    approval_ref: str | None
    severity: str
    extras_json: str
    raw_json: str
    record_hash: str                   # 本条记录哈希
    prev_hash: str                     # 前一条记录哈希（锚点之后）


@dataclass
class RejectedRecord:
    """未通过校验的事件：不丢弃，单独留痕可查询。"""

    reject_id: int | None
    source: str
    source_version: str
    reason: str                        # 拒收原因（字段缺失/时间异常/版本不兼容）
    raw_json: str
    ingest_ts: int
    dedup_hint: str | None


@dataclass
class IngestResult:
    status: EventStatus
    event_id: str | None
    deduped: bool                      # True 表示重复上报，未重复记账
    reason: str | None = None
    seq: int | None = None
    delivery_id: int | None = None
    backpressure: bool = False         # 投递队列已满，未入队（已明确告知，不静默丢）


@dataclass
class ChainIssue:
    index: int                         # 出问题的存储位置（seq）
    kind: str                          # hash_mismatch / broken_link / order / anchor_mismatch
    expected: str
    actual: str
    detail: str


@dataclass
class VerifyResult:
    status: VerifyStatus
    total_records: int
    issues: list[ChainIssue] = field(default_factory=list)
    pruned: bool = False
    head_seq: int | None = None       # 链头（最旧存活记录）序号
    tail_seq: int | None = None       # 链尾（最新记录）序号
    checked_at: int = 0


@dataclass
class RuleConfig:
    """单条合规规则的声明式配置。

    - failure_threshold: 时间窗 window_seconds 内同 actor 的
      event_type in match_event_types 的次数 >= threshold 即命中。
    - approval_required: event_type in match_event_types 且
      approval_ref 为空即命中。
    """

    rule_id: str
    kind: str                          # "failure_threshold" | "approval_required"
    description: str = ""
    match_event_types: list[str] = field(default_factory=list)
    match_sources: list[str] = field(default_factory=list)
    threshold: int = 0
    window_seconds: int = 0
    severity: AlertSeverity = AlertSeverity.MEDIUM
    enabled: bool = True


@dataclass
class PipelineConfig:
    rules: list[RuleConfig] = field(default_factory=list)
    max_queue_size: int = 1000         # 投递队列容量（背压阈值）
    max_retries: int = 3               # 投递重试上限
    retry_backoff_ms: int = 50
    retention_days: int = 90           # 保留期（天）
    retention_max_records: int = 0     # 容量上限，0 表示不限
    allowed_clock_skew_seconds: int = 300  # 允许的事件时间与接入时间偏差


@dataclass
class Alert:
    alert_id: int | None
    rule_id: str
    rule_kind: str
    severity: AlertSeverity
    message: str
    evidence: dict[str, Any]           # 判定依据：命中的事件 seq / 时间窗等
    created_ts: int
    delivered: bool = False


@dataclass
class DeliveryRecord:
    delivery_id: int
    seq: int
    event_id: str
    state: DeliveryState
    attempts: int
    last_error: str | None
    updated_ts: int
