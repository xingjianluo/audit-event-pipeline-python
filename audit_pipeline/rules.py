"""合规规则评估与告警管理。

支持两类声明式规则（JSON 可配置）：

1) failure_threshold
   固定时间窗（window_seconds）内，匹配条件（match_source/match_action/match_result）
   的事件计数达到 threshold 即告警。边界语义：事件恰好落在窗口边界（now - window）
   之上计入窗内（闭区间）；第一次“达到”阈值开告警，同窗口内继续命中追加 event_ids，
   窗口滑过阈值以下不再重复开新告警（去抖，直到再次从下向上穿越阈值）。

2) approval_required
   actions 中列出的敏感操作必须带非空 approval_id；缺失则对每条事件各产一条告警。
"""
from __future__ import annotations

import threading
from collections import defaultdict, deque
from datetime import timezone

from .models import Alert, NormalizedEvent, RuleConfig, Severity


def _matches(event: NormalizedEvent, rule: RuleConfig) -> bool:
    if rule.match_source is not None and event.source != rule.match_source:
        return False
    if rule.match_action is not None and event.action != rule.match_action:
        return False
    if rule.match_result is not None and event.result != rule.match_result:
        return False
    return True


class _FailureWindow:
    def __init__(self, window_seconds: int) -> None:
        self.window = window_seconds
        self.events: deque[tuple[float, str]] = deque()
        self.open = False

    def add(self, ts: float, event_id: str) -> tuple[bool, list[str]]:
        """返回 (是否跨越阈值触发, 当前窗口内全部 event_id)。"""
        return False, []


class RulesEngine:
    def __init__(self, rules: list[RuleConfig]) -> None:
        self._rules = rules
        self._lock = threading.Lock()
        # rule_id -> 窗口状态
        self._windows: dict[str, _FailureWindow] = {
            r.rule_id: _FailureWindow(max(1, r.window_seconds))
            for r in rules
            if r.rule_type == "failure_threshold"
        }
        self._alerts: list[Alert] = []

    def evaluate(self, event: NormalizedEvent) -> list[Alert]:
        """对一条新入库事件评估全部规则，返回本次新产生/更新的告警。"""
        out: list[Alert] = []
        with self._lock:
            for rule in self._rules:
                if rule.rule_type == "failure_threshold":
                    alert = self._eval_threshold(rule, event)
                    if alert is not None:
                        out.append(alert)
                elif rule.rule_type == "approval_required":
                    alert = self._eval_approval(rule, event)
                    if alert is not None:
                        out.append(alert)
        return out

    def _eval_threshold(self, rule: RuleConfig, event: NormalizedEvent) -> Alert | None:
        if not _matches(event, rule):
            return None
        win = self._windows[rule.rule_id]
        now = event.occurred_at.astimezone(timezone.utc).timestamp()
        cutoff = now - win.window  # 闭区间：== cutoff 仍算窗内
        while win.events and win.events[0][0] < cutoff:
            win.events.popleft()
        win.events.append((now, event.event_id))
        count = len(win.events)
        ids = [eid for _, eid in win.events]

        if count >= rule.threshold and not win.open:
            win.open = True
            alert = Alert(
                alert_id=f"{rule.rule_id}-{event.event_id}",
                rule_id=rule.rule_id,
                rule_type=rule.rule_type,
                severity=rule.severity,
                message=(
                    f"{rule.description or rule.rule_id}: {count} matching events within "
                    f"{rule.window_seconds}s reached threshold {rule.threshold}"
                ),
                created_at=event.ingested_at,
                updated_at=event.ingested_at,
                event_ids=ids,
                details={
                    "window_seconds": rule.window_seconds,
                    "threshold": rule.threshold,
                    "count": count,
                    "window_started_at": win.events[0][0],
                    "window_ended_at": win.events[-1][0],
                    "match_source": rule.match_source,
                    "match_action": rule.match_action,
                    "match_result": rule.match_result,
                },
            )
            self._alerts.append(alert)
            return alert
        if count >= rule.threshold and win.open:
            # 同窗口持续命中：更新最近一条 open 告警，供查询解释
            alert = next(
                (a for a in reversed(self._alerts) if a.rule_id == rule.rule_id and a.status == "open"),
                None,
            )
            if alert is not None:
                alert.event_ids = ids
                alert.details["count"] = count
                alert.updated_at = event.ingested_at
                return alert
        # 计数回落到阈值以下：解除去抖锁，允许下一次穿越再告警
        if count < rule.threshold:
            win.open = False
        return None

    def _eval_approval(self, rule: RuleConfig, event: NormalizedEvent) -> Alert | None:
        if event.action not in set(rule.actions):
            return None
        if event.approval_id:
            return None
        alert = Alert(
            alert_id=f"{rule.rule_id}-{event.event_id}",
            rule_id=rule.rule_id,
            rule_type=rule.rule_type,
            severity=rule.severity,
            message=(
                f"{rule.description or rule.rule_id}: sensitive action {event.action!r} "
                f"by {event.actor!r} on {event.resource!r} lacks approval_id"
            ),
            created_at=event.ingested_at,
            updated_at=event.ingested_at,
            event_ids=[event.event_id],
            details={
                "action": event.action,
                "actor": event.actor,
                "resource": event.resource,
                "approval_id": None,
            },
        )
        self._alerts.append(alert)
        return alert

    def list_alerts(self, rule_id: str | None = None) -> list[Alert]:
        with self._lock:
            if rule_id is None:
                return list(self._alerts)
            return [a for a in self._alerts if a.rule_id == rule_id]

    def snapshot(self) -> list[Alert]:
        return self.list_alerts()
