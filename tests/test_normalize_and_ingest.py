"""多来源/多版本兼容、字段缺失与时间异常事件不得静默丢弃。"""


def test_three_source_versions_normalize_to_one_format(pipeline_factory):
    p = pipeline_factory()
    print("\n[输入] login/1.2、payment/2.0、audit/1 三种来源事件")
    r1 = p.ingest({"source": "login", "version": "1.2", "id": "L1",
                   "username": "alice", "op": "login", "target": "console",
                   "ok": True, "ts": 1780000000})
    r2 = p.ingest({"source": "payment", "version": "2.0", "event_id": "P1",
                   "actor": {"id": "bob"}, "action": "wire_transfer", "resource": "acct/1",
                   "result": "OK", "occurred_at": "2026-09-30T01:00:00Z",
                   "approval_ref": "AP-2"})
    r3 = p.ingest({"source": "audit", "version": "1", "event_id": "A1",
                   "event_type": "config_change", "actor": "carol", "action": "update_policy",
                   "resource": "policy/3", "result": "success",
                   "occurred_at": "2026-09-30T02:00:00Z"})
    print(f"[结果] {r1.status.value}/{r2.status.value}/{r3.status.value}")
    assert [r1.status.value, r2.status.value, r3.status.value] == ["accepted"] * 3
    events = {e.event_id: e for e in p.store.iter_events()}
    assert events["L1"].schema_version == "audit/1" and events["L1"].result == "success"
    assert events["P1"].actor == "bob" and events["P1"].result == "success"
    assert events["P1"].approval_id == "AP-2"
    assert events["A1"].event_type == "config_change"


def test_bad_events_rejected_not_dropped(pipeline_factory):
    p = pipeline_factory()
    bad_inputs = [
        ("不兼容主版本", {"source": "payment", "version": "3.0", "event_id": "X1"}),
        ("未知来源", {"source": "mystery", "version": "1.0", "event_id": "X2"}),
        ("时间无法解析", {"source": "login", "version": "1", "id": "X3", "username": "a",
                       "op": "login", "target": "t", "ok": True, "ts": "not-a-time"}),
        ("时间过早", {"source": "audit", "version": "1", "event_id": "X4", "event_type": "t",
                    "actor": "a", "action": "k", "resource": "r", "result": "success",
                    "occurred_at": "1990-01-01T00:00:00Z"}),
        ("时间远超未来", {"source": "audit", "version": "1", "event_id": "X5", "event_type": "t",
                       "actor": "a", "action": "k", "resource": "r", "result": "success",
                       "occurred_at": "2030-01-01T00:00:00Z"}),
        ("缺少必填字段", {"source": "audit", "version": "1", "event_type": "t", "actor": "a",
                       "action": "k", "resource": "r", "result": "success",
                       "occurred_at": "2026-09-01T00:00:00Z"}),
        ("结果值无法识别", {"source": "audit", "version": "1", "event_id": "X6", "event_type": "t",
                         "actor": "a", "action": "k", "resource": "r", "result": "banana",
                         "occurred_at": "2026-09-01T00:00:00Z"}),
    ]
    print("\n[输入] 7 类问题事件（不得被悄悄丢弃）")
    for label, payload in bad_inputs:
        r = p.ingest(payload)
        print(f"  {label}: status={r.status.value} reason={r.reason}")
        assert r.status.value == "rejected"
    rejected = p.store.list_rejected()
    print(f"[判定依据] 拒绝事件全部落 rejected.jsonl，可查询；数量={len(rejected)}")
    assert len(rejected) == 7
    assert p.verify().records_verified == 0
