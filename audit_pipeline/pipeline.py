"""管线门面：归一化 → 去重 → 哈希链入库 → 合规评估 → 告警留存 → 异步投递。

拒绝路径：归一化失败的事件写入 rejected.jsonl 并返回 REJECTED（带原因），不静默丢弃。
去重路径：重复 event_id 返回 DUPLICATE，不再记账、不重复触发规则与投递。
背压路径：下游队列满时事件已安全入库，投递返回 503 语义，事件不丢（仍在链上）。
"""
from __future__ import annotations

import threading
from pathlib import Path

from .alerts import AlertStore
from .config import PipelineConfig
from .dedup import Deduplicator
from .dispatcher import EventDispatcher
from .models import IngestResult, IngestStatus, VerificationResult
from .normalize import EventValidationError, normalize_event
from .rules import RulesEngine
from .storage import EventStore


class AuditPipeline:
    def __init__(self, config: PipelineConfig, start_dispatcher: bool = True) -> None:
        self.config = config
        base = Path(config.data_dir)
        base.mkdir(parents=True, exist_ok=True)
        self.store = EventStore(config.data_dir, segment_size=config.retention.segment_size)
        self.dedup = Deduplicator(str(base / "dedup-ids.txt"))
        self.rules_engine = RulesEngine(config.rules)
        self.alert_store = AlertStore(str(base / "alerts.jsonl"))
        self.dispatcher = EventDispatcher(config.dispatcher, str(base / "dispatch"))
        self._ingest_lock = threading.Lock()
        if start_dispatcher:
            self.dispatcher.start()

    def ingest(self, raw: dict) -> IngestResult:
        # 1) 归一化（失败显式拒绝，绝不静默丢弃）
        try:
            event = normalize_event(raw)
        except EventValidationError as exc:
            self.store.record_rejected(raw, exc.reason)
            return IngestResult(status=IngestStatus.REJECTED, reason=exc.reason)

        with self._ingest_lock:
            # 2) 幂等去重：同 event_id 只记账一次
            if self.dedup.seen(event.event_id):
                return IngestResult(
                    status=IngestStatus.DUPLICATE,
                    event_id=event.event_id,
                    reason="event already ingested",
                )
            # 3) 哈希链入库
            sequence = self.store.append(event)
            event.sequence = sequence
            self.dedup.save()

            # 4) 合规规则评估；告警持久化，可查询
            for alert in self.rules_engine.evaluate(event):
                self.alert_store.add(alert)

            # 5) 下游投递（有界背压）。失败入队仅影响投递状态，事件已在链上。
            enqueued = self.dispatcher.offer(event)

        result = IngestResult(
            status=IngestStatus.ACCEPTED,
            event_id=event.event_id,
            sequence=sequence,
        )
        if not enqueued:
            result.reason = "stored but downstream backlog full (delivery pending; check /dispatch/status)"
        return result

    def verify(self) -> VerificationResult:
        return self.store.verify()

    def enforce_retention(self) -> dict:
        r = self.config.retention
        return self.store.enforce_retention(r.max_age_days, r.max_records)

    def shutdown(self) -> None:
        self.dedup.save()
        self.dispatcher.stop()
