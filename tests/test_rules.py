"""场景三：合规规则边界命中——同一批输入得到稳定、可解释的告警结论。"""
from datetime import datetime, timedelta, timezone

from tests.conftest import default_rules

BASE = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)


def login_event(eid, offset_sec, ok=False):
    return {
        "source": "login", "version": "1.2", "id": eid,
        "username": "alice", "op": "login", "target": "console",
        "ok": ok, "ts": (BASE + timedelta(seconds=offset_sec)).timestamp(),
    }


def test_threshold_boundary_inclusive_and_no_dup_alerts(pipeline_factory):
    p = pipeline_factory(rules=default_rules())
    print("\n[输入] 失败事件发生在相对秒偏移 [0, 299, 300]，窗口=300s，阈值=3")
    rs = [p.ingest(login_event(f"L{i}", off)) for i, off in enumerate([0, 299, 300])]
    assert all(r.status.value == "accepted" for r in rs)

    alerts = p.alert_store.list_all()
    threshold_alerts = [a for a in alerts if a.rule_id == "LOGIN_FAILURE_3_5M"]
    print(f"[判定依据] 窗口闭区间 [now-300, now]：t=300 时 t=0 事件仍在窗内，计数=3")
    print(f"[结果] 阈值告警条数={len(threshold_alerts)}（必须恰好1条，不重复记账）")
    for a in threshold_alerts:
        print(f"  alert={a.alert_id} count={a.details['count']} events={a.event_ids}")
    assert len(threshold_alerts) == 1
    assert threshold_alerts[0].details["count"] == 3

    # 窗内再来一条：更新同一条告警而不是新开
    p.ingest(login_event("L3", 300))
    alerts2 = [a for a in p.alert_store.list_all() if a.rule_id == "LOGIN_FAILURE_3_5M"]
    print(f"[结果] 窗内第4次命中后告警条数仍={len(alerts2)}，折叠后 count={alerts2[0].details['count']}")
    assert len(alerts2) == 1 and alerts2[0].details["count"] == 4


def test_just_below_threshold_no_alert(pipeline_factory):
    p = pipeline_factory(rules=default_rules())
    print("\n[输入] 3600s 跨度内只有 2 次失败（窗口300s下从不同时满足>=3）")
    for i, off in enumerate([0, 301]):
        p.ingest(login_event(f"Q{i}", off))
    alerts = [a for a in p.alert_store.list_all() if a.rule_id == "LOGIN_FAILURE_3_5M"]
    print(f"[判定依据] 任一 300s 闭区间内计数最大为 2 < 3")
    print(f"[结果] 告警条数={len(alerts)}（必须为0）")
    assert alerts == []


def test_approval_required_rule(pipeline_factory):
    p = pipeline_factory(rules=default_rules())
    print("\n[输入] 三条 payment/2 事件：无审批删除、有审批删除、无审批普通查询")
    cases = [
        ("P1", "delete_user", None),
        ("P2", "delete_user", "AP-1001"),
        ("P3", "list_users", None),
    ]
    for eid, action, approval in cases:
        payload = {
            "source": "payment", "version": "2.0", "event_id": eid,
            "actor": {"id": "bob"}, "action": action, "resource": "user/7",
            "result": "success", "occurred_at": "2026-09-30T11:00:00Z",
        }
        if approval:
            payload["approval_ref"] = approval
        p.ingest(payload)

    alerts = [a for a in p.alert_store.list_all() if a.rule_id == "SENSITIVE_APPROVAL"]
    print(f"[判定依据] 仅 delete_user 且 approval_ref 缺失才命中；有审批/非敏感操作不命中")
    print(f"[结果] 审批告警={[(a.alert_id, a.details['action']) for a in alerts]}")
    assert len(alerts) == 1
    assert alerts[0].alert_id == "SENSITIVE_APPROVAL-P1"
    assert alerts[0].severity.value == "critical"
