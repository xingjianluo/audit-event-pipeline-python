"""服务编排：接入 -> 规范化 -> 幂等落链 -> 规则评估 -> 投递；留存清理。"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .delivery import DeliveryBus
from .errors import BackpressureError, ValidationError
from .integrity import verify_chain
from .models import (
    Alert,
    EventStatus,
    IngestResult,
    PipelineConfig,
    RejectedRecord,
)
from .normalize import normalize_event
from .rules import evaluate
from .storage import Storage


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)


class AuditService:
    def __init__(
        self,
        db_path: str = ":memory:",
        config: PipelineConfig | None = None,
        sink=None,
    ) -> None:
        self.db_path = db_path
        self.config = config or PipelineConfig()
        self.storage = Storage(db_path)
        self.bus = DeliveryBus(
            sink=sink,
            max_queue_size=self.config.max_queue_size,
            max_retries=self.config.max_retries,
            retry_backoff_ms=self.config.retry_backoff_ms,
            storage=self.storage,
        )

    def start(self) -> None:
        self.bus.start()

    def close(self) -> None:
        self.bus.stop(timeout=5.0)
        self.storage.close()

    # ------------------------------------------------------------------ ingest
    def ingest(
        self,
        raw: dict,
        *,
        source: str,
        source_version: str,
    ) -> IngestResult:
        now = _now_ms()
        # 1) 规范化/校验：异常不丢弃，落拒收表
        try:
            ev = normalize_event(
                raw,
                source=source,
                source_version=source_version,
                config=self.config,
                now_ms=now,
            )
        except ValidationError as exc:
            self.storage.insert_rejected(
                RejectedRecord(
                    reject_id=None,
                    source=source,
                    source_version=source_version,
                    reason=str(exc),
                    raw_json=_dumps(raw),
                    ingest_ts=now,
                    dedup_hint=None,
                )
            )
            return IngestResult(
                status=EventStatus.REJECTED,
                event_id=None,
                deduped=False,
                reason=str(exc),
            )

        # 2) 幂等落哈希链（原子事务；并发重复只记一条）
        stored, deduped = self.storage.append_chain(ev)
        result = IngestResult(
            status=EventStatus.ACCEPTED,
            event_id=stored.event_id,
            deduped=deduped,
            seq=stored.seq,
        )
        if deduped:
            return result

        # 3) 规则评估（对全量存活事件；告警按证据唯一去重）
        alerts = evaluate(self.config.rules, self.storage.list_events(limit=1_000_000))
        for alert in alerts:
            saved = self.storage.insert_alert(alert)
            if saved is not None:
                self._publish(
                    {
                        "kind": "alert",
                        "alert_id": saved.alert_id,
                        "rule_id": saved.rule_id,
                        "severity": saved.severity.value,
                        "message": saved.message,
                        "evidence": saved.evidence,
                        "created_ts": saved.created_ts,
                    },
                    seq=stored.seq,
                    event_id=stored.event_id,
                    result=result,
                )

        # 4) 事件本身投递到下游
        self._publish(
            {
                "kind": "event",
                "seq": stored.seq,
                "event_id": stored.event_id,
                "source": stored.source,
                "source_version": stored.source_version,
                "event_type": stored.event_type,
                "actor": stored.actor,
                "target": stored.target,
                "event_ts": stored.event_ts,
                "ingest_ts": stored.ingest_ts,
                "approval_ref": stored.approval_ref,
            },
            seq=stored.seq,
            event_id=stored.event_id,
            result=result,
        )
        return result

    def _publish(self, payload: dict, *, seq: int, event_id: str, result: IngestResult) -> None:
        try:
            did = self.bus.publish(payload, seq=seq, event_id=event_id)
            if result.delivery_id is None:
                result.delivery_id = did
        except BackpressureError as exc:
            # 不无限期拖住接入，也不静默：显式标记背压，调用方可见
            result.backpressure = True
            result.reason = (result.reason + "; " if result.reason else "") + str(exc)

    # ----------------------------------------------------------------- queries
    def list_events(self, after_seq: int = 0, limit: int = 100) -> list[dict]:
        out = []
        for e in self.storage.list_events(after_seq=after_seq, limit=limit):
            out.append(
                {
                    "seq": e.seq,
                    "event_id": e.event_id,
                    "source": e.source,
                    "source_version": e.source_version,
                    "event_type": e.event_type,
                    "actor": e.actor,
                    "target": e.target,
                    "event_ts": e.event_ts,
                    "ingest_ts": e.ingest_ts,
                    "dedup_key": e.dedup_key,
                    "approval_ref": e.approval_ref,
                    "severity": e.severity,
                    "extras": json.loads(e.extras_json),
                    "raw": json.loads(e.raw_json),
                    "record_hash": e.record_hash,
                    "prev_hash": e.prev_hash,
                }
            )
        return out

    def list_rejected(self, limit: int = 100) -> list[RejectedRecord]:
        return self.storage.list_rejected(limit=limit)

    def list_alerts(self, delivered: bool | None = None, limit: int = 100) -> list[Alert]:
        return self.storage.list_alerts(delivered=delivered, limit=limit)

    def list_delivery(self, state: str | None = None) -> list[dict]:
        return [
            {
                "delivery_id": d.delivery_id,
                "seq": d.seq,
                "event_id": d.event_id,
                "state": d.state.value,
                "attempts": d.attempts,
                "last_error": d.last_error,
                "updated_ts": d.updated_ts,
            }
            for d in self.storage.list_delivery(state=state)
        ]

    # ---------------------------------------------------------------- integrity
    def verify(self):
        events = self.storage.list_events(limit=1_000_000)
        anchor = self.storage.get_anchor()
        return verify_chain(events, anchor)

    # ------------------------------------------------------------------ prune
    def prune(self) -> dict:
        """按保留期/容量清理旧数据，并对被清理尾点做锚点封包。"""
        now = _now_ms()
        total = self.storage.count_events()

        cutoff: int | None = None  # 删除 seq < cutoff
        reasons: list[str] = []

        # 保留期
        if self.config.retention_days > 0:
            threshold_ts = now - self.config.retention_days * 86400 * 1000
            # 第一条 event_ts >= 阈值 的 seq，其之前的全部可删
            first_keep = self._first_seq_with_event_ts_gte(threshold_ts)
            if first_keep is not None and first_keep > 1:
                cutoff = first_keep if cutoff is None else min(cutoff, first_keep)
                reasons.append(f"retention_days={self.config.retention_days}")

        # 容量上限：只保留最新 N 条
        if self.config.retention_max_records > 0 and total > self.config.retention_max_records:
            overflow = total - self.config.retention_max_records
            min_seq = self.storage.min_event_seq()
            if min_seq is not None:
                cap_cutoff = min_seq + overflow  # 删除 seq < min_seq+overflow
                cutoff = cap_cutoff if cutoff is None else min(cutoff, cap_cutoff)
                reasons.append(f"retention_max_records={self.config.retention_max_records}")

        if cutoff is None or cutoff <= (self.storage.min_event_seq() or 1):
            return {"deleted": 0, "pruned": self.storage.get_anchor() is not None,
                    "remaining": total, "anchor": self.storage.get_anchor()}

        deleted, anchor = self.storage.prune_with_anchor(
            cutoff, reason="; ".join(reasons), now_ms=now
        )
        remaining = self.storage.count_events()
        return {
            "deleted": deleted,
            "remaining": remaining,
            "pruned": True,
            "anchor": anchor,
            "reasons": reasons,
        }

    def _first_seq_with_event_ts_gte(self, ts: int) -> int | None:
        with self.storage._lock:  # noqa: SLF001
            row = self.storage._conn.execute(  # noqa: SLF001
                "SELECT MIN(seq) s FROM events WHERE event_ts>=?", (ts,)
            ).fetchone()
            return row["s"] if row and row["s"] is not None else None
