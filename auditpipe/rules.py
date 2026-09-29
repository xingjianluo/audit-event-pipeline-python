"""声明式合规规则引擎。

支持的规则类型
--------------
1. failure_threshold：在 window_seconds 时间窗内，同一 actor 命中
   match_event_types 的事件数达到 threshold（>=）即告警。
   - match_sources 非空时还要求来源在名单内。
   - 判定依据 evidence 固定为 {rule_id, actor, 起始seq, 结束seq}，
     重复评估不会产生重复告警（由存储层唯一约束保证）。
2. approval_required：命中 event_type（且 source 在名单内，若配置）
   且 approval_ref 为空的事件，逐条告警。

边界语义：计数达到 threshold 即命中（>=），事件时间按 event_ts。
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from .models import Alert, RuleConfig, StoredEvent


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _matches(ev: StoredEvent, rule: RuleConfig) -> bool:
    if rule.match_event_types and ev.event_type not in rule.match_event_types:
        return False
    if rule.match_sources and ev.source not in rule.match_sources:
        return False
    return True


def _eval_failure_threshold(
    rule: RuleConfig, events: list[StoredEvent]
) -> list[Alert]:
    if rule.threshold <= 0 or rule.window_seconds <= 0:
        return []
    window_ms = rule.window_seconds * 1000
    # 先按规则过滤（事件类型/来源），再按 actor 分组做滑窗
    matched = [ev for ev in events if _matches(ev, rule)]
    by_actor: dict[str, list[StoredEvent]] = defaultdict(list)
    for ev in matched:
        by_actor[ev.actor].append(ev)

    alerts: list[Alert] = []
    for actor, evs in by_actor.items():
        evs.sort(key=lambda e: e.event_ts)
        left = 0
        emitted_keys: set[tuple[int, int]] = set()
        for right in range(len(evs)):
            while evs[right].event_ts - evs[left].event_ts > window_ms:
                left += 1
            count = right - left + 1
            if count >= rule.threshold:
                window_events = evs[left:right + 1]
                start_seq = window_events[0].seq
                end_seq = window_events[-1].seq
                key = (start_seq, end_seq)
                if key in emitted_keys:
                    continue
                emitted_keys.add(key)
                alerts.append(
                    Alert(
                        alert_id=None,
                        rule_id=rule.rule_id,
                        rule_kind=rule.kind,
                        severity=rule.severity,
                        message=(
                            f"actor={actor} 在 {rule.window_seconds}s 窗口内 "
                            f"发生 {count} 次命中事件（阈值 {rule.threshold}）"
                        ),
                        evidence={
                            "rule_id": rule.rule_id,
                            "actor": actor,
                            "threshold": rule.threshold,
                            "window_seconds": rule.window_seconds,
                            "window_start_ts": window_events[0].event_ts,
                            "window_end_ts": window_events[-1].event_ts,
                            "count": count,
                            "matched_seqs": [e.seq for e in window_events],
                            "start_seq": start_seq,
                            "end_seq": end_seq,
                        },
                        created_ts=_now_ms(),
                    )
                )
    return alerts


def _eval_approval_required(
    rule: RuleConfig, events: list[StoredEvent]
) -> list[Alert]:
    alerts: list[Alert] = []
    for ev in events:
        if not _matches(ev, rule):
            continue
        if ev.approval_ref:
            continue
        alerts.append(
            Alert(
                alert_id=None,
                rule_id=rule.rule_id,
                rule_kind=rule.kind,
                severity=rule.severity,
                message=(
                    f"敏感操作 {ev.event_type}（actor={ev.actor}, target={ev.target}）"
                    f"缺少审批记录"
                ),
                evidence={
                    "rule_id": rule.rule_id,
                    "seq": ev.seq,
                    "event_id": ev.event_id,
                    "actor": ev.actor,
                    "target": ev.target,
                    "event_type": ev.event_type,
                },
                created_ts=_now_ms(),
            )
        )
    return alerts


_EVALUATORS = {
    "failure_threshold": _eval_failure_threshold,
    "approval_required": _eval_approval_required,
}


def evaluate(
    rules: list[RuleConfig],
    events: list[StoredEvent],
    *,
    now_ms: int | None = None,
) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        if not rule.enabled:
            continue
        fn = _EVALUATORS.get(rule.kind)
        if fn is None:
            continue
        alerts.extend(fn(rule, events))
    return alerts
