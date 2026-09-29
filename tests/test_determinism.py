"""同一批输入跑两次，结论必须稳定一致、可解释。"""
import json


def test_same_batch_same_conclusion(pipeline_factory):
    batch = [
        {"source": "login", "version": "1.0", "id": "S1", "username": "a", "op": "login",
         "target": "c", "ok": False, "ts": 1780000000},
        {"source": "login", "version": "1.0", "id": "S2", "username": "a", "op": "login",
         "target": "c", "ok": False, "ts": 1780000005},
        {"source": "login", "version": "1.0", "id": "S3", "username": "a", "op": "login",
         "target": "c", "ok": False, "ts": 1780000010},
        {"source": "payment", "version": "2.0", "event_id": "S4", "actor": {"id": "b"},
         "action": "delete_user", "resource": "u/1", "result": "success",
         "occurred_at": "2026-09-30T03:00:00Z"},
        {"source": "payment", "version": "2.0", "event_id": "S5", "actor": {"id": "b"},
         "action": "delete_user", "resource": "u/1", "result": "success",
         "occurred_at": "2026-09-30T03:01:00Z", "approval_ref": "AP-7"},
        {"source": "audit", "version": "1", "event_id": "S6", "event_type": "x",
         "actor": "c", "action": "z", "resource": "r", "result": "weird",
         "occurred_at": "2026-09-30T03:02:00Z"},
    ]

    def run_once(name):
        p = pipeline_factory(rules=__import__("tests.conftest", fromlist=["default_rules"]).default_rules())
        statuses = [p.ingest(dict(e)).status.value for e in batch]
        # 重复整批
        dup_statuses = [p.ingest(dict(e)).status.value for e in batch]
        v = p.verify()
        alerts = sorted((a.rule_id, a.alert_id.split("-")[0]) for a in p.alert_store.list_all())
        return p, {"statuses": statuses, "dups": dup_statuses,
                   "verify": (v.ok, v.complete, v.records_verified), "alerts": alerts}

    p1, run1 = run_once("run1")
    p2, run2 = run_once("run2")
    print("\n[输入] 固定6条事件的批次，完整跑两遍（每遍含一次整批重复上报）")
    print(f"[结果1] {json.dumps(run1, ensure_ascii=False, default=str)[:300]}")
    print(f"[结果2] {json.dumps(run2, ensure_ascii=False, default=str)[:300]}")
    assert run1 == run2
    assert run1["statuses"] == ["accepted"] * 5 + ["rejected"]
    assert run1["dups"] == ["duplicate"] * 5 + ["rejected"]
    # S1,S2,S3 触发失败阈值；S4 无审批触发；S5 有审批不触发；S6 被拒绝
    rule_hits = sorted(rule for rule, _ in run1["alerts"])
    print(f"[判定依据] 规则命中集合={rule_hits}（LOGIN_FAILURE_3_5M + SENSITIVE_APPROVAL 各一）")
    assert rule_hits == ["LOGIN_FAILURE_3_5M", "SENSITIVE_APPROVAL"]
