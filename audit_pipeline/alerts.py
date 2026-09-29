"""告警留存与查询：JSONL 只追加，updated 以更新记录形式留痕，查询时折叠为最新状态。"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .models import Alert, Severity


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _to_dict(alert: Alert) -> dict:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule_type": alert.rule_type,
        "severity": alert.severity.value,
        "message": alert.message,
        "created_at": _iso(alert.created_at),
        "updated_at": _iso(alert.updated_at),
        "event_ids": alert.event_ids,
        "details": alert.details,
        "status": alert.status,
    }


def _from_dict(obj: dict) -> Alert:
    return Alert(
        alert_id=obj["alert_id"],
        rule_id=obj["rule_id"],
        rule_type=obj["rule_type"],
        severity=Severity(obj["severity"]),
        message=obj["message"],
        created_at=datetime.fromisoformat(obj["created_at"]),
        updated_at=datetime.fromisoformat(obj["updated_at"]),
        event_ids=list(obj.get("event_ids", [])),
        details=dict(obj.get("details", {})),
        status=obj.get("status", "open"),
    )


class AlertStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def add(self, alert: Alert) -> None:
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(_to_dict(alert), sort_keys=True, ensure_ascii=False) + "\n")

    def list_all(self) -> list[Alert]:
        if not self.path.exists():
            return []
        folded: dict[str, Alert] = {}
        with self._lock:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                alert = _from_dict(json.loads(line))
                folded[alert.alert_id] = alert  # 后出现的更新覆盖旧版本
        return list(folded.values())
