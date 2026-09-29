"""HTTP 层回归：原有根路由不受影响；审计接口可查询、结论稳定。"""
from fastapi.testclient import TestClient

from audit_pipeline.api import create_app
from audit_pipeline.config import PipelineConfig, RetentionConfig, DispatcherConfig
from audit_pipeline.models import RuleConfig


def build_client(tmp_path):
    cfg = PipelineConfig(
        data_dir=str(tmp_path / "audit"),
        retention=RetentionConfig(segment_size=100),
        dispatcher=DispatcherConfig(sink_type="null"),
        rules=[RuleConfig(rule_id="R1", rule_type="failure_threshold",
                          window_seconds=3600, threshold=2,
                          match_source="login", match_result="failure")],
    )
    app = create_app(cfg)
    return TestClient(app), app


def test_root_route_still_works(tmp_path):
    client, app = build_client(tmp_path)
    resp = client.get("/")
    print("\n[输入] GET / （既有服务接口）")
    print(f"[结果] {resp.status_code} {resp.json()}（必须保持 Hello World 不变）")
    assert resp.status_code == 200
    assert resp.json() == {"Hello": "World"}
    app.state.pipeline.shutdown()


def test_api_ingest_verify_alerts_rejected(tmp_path):
    client, app = build_client(tmp_path)
    good = {"source": "login", "version": "1", "id": "W1",
            "username": "a", "op": "login", "target": "c", "ok": False, "ts": 1780000000}
    print("\n[输入] 两次失败登录 + 一次重复 + 一个坏事件")
    r1 = client.post("/audit/events", json=good)
    r2 = client.post("/audit/events", json={**good, "id": "W2", "ts": 1780000010})
    r3 = client.post("/audit/events", json={**good, "id": "W2", "ts": 1780000010})
    r4 = client.post("/audit/events", json={"source": "nope", "version": "1"})
    print(f"[结果] {r1.json()['status']} {r2.json()['status']} {r3.json()['status']} "
          f"{r4.status_code}:{r4.json()['status']}")
    assert r1.status_code == 200 and r2.status_code == 200
    assert r3.json()["status"] == "duplicate"
    assert r4.status_code == 422

    verify = client.get("/audit/verify").json()
    print(f"[结果] /audit/verify ok={verify['ok']} complete={verify['complete']} n={verify['records_verified']}")
    assert verify["ok"] and verify["complete"] and verify["records_verified"] == 2

    alerts = client.get("/audit/alerts").json()
    print(f"[结果] /audit/alerts 命中 {len(alerts)} 条: {[a['rule_id'] for a in alerts]}")
    assert len(alerts) == 1 and alerts[0]["rule_id"] == "R1"

    rejected = client.get("/audit/rejected").json()
    assert len(rejected) == 1
    status = client.get("/dispatch/status").json()
    print(f"[结果] /dispatch/status={status}")
    app.state.pipeline.shutdown()
