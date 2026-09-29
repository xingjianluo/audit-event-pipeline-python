"""HTTP 层：原有可用性保持，审计接口端到端可用。"""

import importlib
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from conftest import log_case


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.delenv("AUDIT_CONFIG_PATH", raising=False)
    import main
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def _raw(uuid, action="login_failed", approval=None):
    ev = {
        "action": action, "user": "alice", "object": "web",
        "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000) - 1000,
        "event_uuid": uuid,
    }
    if approval is not None:
        ev["approval"] = approval
    return ev


def test_original_root_still_works(client):
    r = client.get("/")
    body = r.json()
    log_case("原有健康端点保持可用", inputs={"GET": "/"},
             basis="不破坏已有可用性", result=body)
    assert r.status_code == 200
    assert body["Hello"] == "World"


def test_ingest_and_dedup_and_query(client):
    r1 = client.post("/api/v1/events?source=gitlab&source_version=1.0",
                     json=_raw("h1"))
    r2 = client.post("/api/v1/events?source=gitlab&source_version=1.0",
                     json=_raw("h1"))
    events = client.get("/api/v1/events").json()["events"]
    log_case("HTTP 接入 + 重复识别 + 查询",
             inputs={"POST": "/api/v1/events", "uuid": "h1", "times": 2},
             basis="第二次返回 deduped=true 且 seq 不变",
             result={"first": r1.json(), "second_deduped": r2.json()["deduped"],
                     "stored": len(events)})
    assert r1.json()["status"] == "accepted"
    assert r2.json()["deduped"] is True
    assert len(events) == 1


def test_rejected_is_queryable(client):
    r = client.post("/api/v1/events?source=gitlab&source_version=1.0",
                    json={"user": "x"})
    rejected = client.get("/api/v1/rejected").json()["rejected"]
    log_case("拒收事件可查询留痕", inputs={"raw": {"user": "x"}},
             basis="字段缺失 -> status=rejected 且落 rejected 表",
             result={"response": r.json(), "rejected_rows": len(rejected)})
    assert r.json()["status"] == "rejected"
    assert len(rejected) == 1


def test_verify_and_alert_endpoints(client):
    # 5 次窗内失败触发阈值（默认无配置 -> 通过 API 服务内置规则为空，
    # 这里直接验证 verify 端点；告警用带配置的 main 另测）
    for i in range(3):
        client.post("/api/v1/events?source=gitlab&source_version=1.0",
                    json=_raw(f"v{i}"))
    v = client.get("/api/v1/verify").json()
    log_case("完整性校验端点", inputs={"events": 3},
             basis="全链重算哈希", result=v)
    assert v["status"] == "ok" and v["total_records"] == 3

    p = client.post("/api/v1/prune").json()
    log_case("无清理条件时 prune 幂等", inputs={"retention": "默认"},
             basis="无过期/超量 -> deleted=0", result=p)
    assert p["deleted"] == 0


def test_missing_source_param_422(client):
    r = client.post("/api/v1/events", json=_raw("z"))
    log_case("缺 source 参数被拒", inputs={"query": {}},
             basis="source/source_version 必填",
             result={"status_code": r.status_code, "detail": r.json()["detail"]})
    assert r.status_code == 422


def test_alerts_with_config(monkeypatch, tmp_path):
    import json
    cfg = tmp_path / "rules.json"
    cfg.write_text(json.dumps({
        "rules": [{
            "rule_id": "burst", "kind": "failure_threshold",
            "match_event_types": ["login_failed"], "threshold": 3,
            "window_seconds": 300, "severity": "high"}]
    }), encoding="utf-8")
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "api2.db"))
    monkeypatch.setenv("AUDIT_CONFIG_PATH", str(cfg))
    import main
    importlib.reload(main)
    base = int(datetime.now(timezone.utc).timestamp() * 1000) - 60_000
    with TestClient(main.app) as c:
        for i in range(3):
            raw = _raw(f"c{i}")
            raw["timestamp"] = base + i * 1000
            c.post("/api/v1/events?source=gitlab&source_version=1.0", json=raw)
        alerts = c.get("/api/v1/alerts").json()["alerts"]
        log_case("配置规则经服务启动生效并产出可查询告警",
                 inputs={"threshold": 3, "events": 3, "span_ms": 2000},
                 basis="3 次失败均在 300s 窗内 -> 命中 burst",
                 result={"alerts": [(a["rule_id"], a["severity"],
                                     a["evidence"]["matched_seqs"]) for a in alerts]})
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "burst"
        assert alerts[0]["evidence"]["matched_seqs"] == [1, 2, 3]
        delivery = c.get("/api/v1/delivery").json()["delivery"]
        assert any(d["state"] == "delivered" for d in delivery)
