"""规则边界命中：阈值/窗口临界、审批缺失、结论稳定可复现。"""

import json
from datetime import datetime, timezone

from conftest import log_case
from auditpipe.models import AlertSeverity, PipelineConfig, RuleConfig
from auditpipe.normalize import normalize_event
from auditpipe.rules import evaluate
from auditpipe.service import AuditService
from auditpipe.storage import Storage


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_at(base_ms, offset_s, uuid, action="login_failed", approval=None, user="alice"):
    """以固定基准 base_ms 构造 gitlab 原始事件（毫秒时间戳），消除时钟漂移。"""
    ev = {
        "action": action, "user": user, "object": "web",
        "timestamp": base_ms + offset_s * 1000,
        "event_uuid": uuid,
    }
    if approval is not None:
        ev["approval"] = approval
    return ev


def _threshold_cfg(threshold, window):
    return PipelineConfig(
        rules=[RuleConfig(rule_id="burst", kind="failure_threshold",
                          match_event_types=["login_failed"], threshold=threshold,
                          window_seconds=window, severity=AlertSeverity.HIGH)],
        max_queue_size=100)


def test_threshold_exact_boundary_hits():
    cfg = _threshold_cfg(3, 60)
    svc = AuditService(":memory:", cfg)
    svc.start()
    base = _now_ms() - 60_000
    for i, off in enumerate((0, 30, 60)):
        svc.ingest(_event_at(base, off, f"b{i}"), source="gitlab", source_version="1.0")
    alerts = svc.list_alerts()
    log_case("阈值边界：60s 窗内恰好 3 次（含端点）",
             inputs={"offsets_s": [-60, -30, 0], "threshold": 3, "window_s": 60},
             basis="窗内 count>=threshold 命中；时间差 diff<=window 即同窗",
             result={"alerts": [(a.rule_id, a.evidence["matched_seqs"],
                                 a.evidence["count"]) for a in alerts]})
    assert len(alerts) == 1
    assert alerts[0].evidence["matched_seqs"] == [1, 2, 3]
    svc.close()


def test_just_below_threshold_no_alert():
    cfg = _threshold_cfg(3, 60)
    svc = AuditService(":memory:", cfg)
    svc.start()
    base = _now_ms() - 60_000
    for i, off in enumerate((0, 30)):
        svc.ingest(_event_at(base, off, f"u{i}"), source="gitlab", source_version="1.0")
    alerts = svc.list_alerts()
    log_case("阈值边界：仅 2 次不命中", inputs={"count": 2, "threshold": 3},
             basis="count<threshold", result={"alerts": len(alerts)})
    assert alerts == []
    svc.close()


def test_window_slides_out():
    cfg = _threshold_cfg(3, 60)
    svc = AuditService(":memory:", cfg)
    svc.start()
    base = _now_ms() - 61_000
    for i, off in enumerate((0, 31, 61)):
        svc.ingest(_event_at(base, off, f"s{i}"), source="gitlab", source_version="1.0")
    alerts = svc.list_alerts()
    log_case("窗口滑出：跨度 61s 不命中",
             inputs={"offsets_s": [-61, -30, 0], "window_s": 60},
             basis="最早事件滑出窗口，任意窗内最多 2 次",
             result={"alerts": len(alerts)})
    assert alerts == []
    svc.close()


def test_approval_required_boundary():
    cfg = PipelineConfig(
        rules=[RuleConfig(rule_id="appr", kind="approval_required",
                          match_event_types=["sensitive_op"],
                          severity=AlertSeverity.CRITICAL)],
        max_queue_size=100)
    svc = AuditService(":memory:", cfg)
    svc.start()
    base = _now_ms() - 60_000
    svc.ingest(_event_at(base, 50, "no", action="sensitive_op"),
               source="gitlab", source_version="1.0")
    svc.ingest(_event_at(base, 55, "yes", action="sensitive_op", approval="CHG-123"),
               source="gitlab", source_version="1.0")
    alerts = svc.list_alerts()
    log_case("敏感操作审批边界：无审批命中/有审批放行",
             inputs=[{"uuid": "no", "approval": None},
                     {"uuid": "yes", "approval": "CHG-123"}],
             basis="event_type 命中且 approval_ref 为空即告警",
             result={"alerts": [(a.evidence["event_id"][:8], a.evidence["seq"])
                                for a in alerts]})
    assert len(alerts) == 1
    assert alerts[0].evidence["seq"] == 1
    svc.close()


def test_deterministic_conclusion_same_inputs():
    cfg = _threshold_cfg(3, 300)
    store = Storage(":memory:")
    seqs = []
    base = _now_ms() - 200_000
    for i, off in enumerate((0, 50, 100, 150, 200)):
        ev = normalize_event(_event_at(base, off, f"d{i}"), source="gitlab",
                             source_version="1.0", config=cfg)
        stored, _ = store.append_chain(ev)
        seqs.append(stored.seq)

    def sig():
        return sorted(
            (a.rule_id, json.dumps(a.evidence, sort_keys=True, default=str))
            for a in evaluate(cfg.rules, store.list_events(limit=1000))
        )

    k1, k2 = sig(), sig()
    log_case("同一批输入两次评估结论一致", inputs={"seqs": seqs},
             basis="规则评估为纯函数；证据由命中事件的 seq 集合确定",
             result={"run1": k1, "run2": k2})
    assert k1 == k2
    assert len(k1) >= 1
    store.close()
