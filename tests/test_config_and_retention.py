"""配置声明校验，以及按保留期/容量清理的语义。"""

import json

import pytest

from auditpipe.config import load_config
from auditpipe.errors import ConfigError
from auditpipe.models import VerifyStatus

from conftest import log_case


def write_cfg(tmp_path, data):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_load_example_like_config(tmp_path):
    data = {
        "retention_days": 30,
        "rules": [
            {"rule_id": "rf", "kind": "failure_threshold",
             "match_event_types": ["login_failed"], "threshold": 5,
             "window_seconds": 300, "severity": "high"},
            {"rule_id": "ra", "kind": "approval_required",
             "match_event_types": ["sensitive_op"], "severity": "critical"},
        ],
    }
    cfg = load_config(write_cfg(tmp_path, data))
    log_case("加载合法声明式配置", inputs=data,
             basis="两规则字段完整、severity 合法",
             result={"rules": [r.rule_id for r in cfg.rules],
                     "retention_days": cfg.retention_days})
    assert [r.rule_id for r in cfg.rules] == ["rf", "ra"]


@pytest.mark.parametrize("data,label", [
    ({"rules": [{"kind": "failure_threshold"}]}, "缺 rule_id"),
    ({"rules": [{"rule_id": "x", "kind": "nope", "match_event_types": ["a"]}]}, "非法 kind"),
    ({"rules": [{"rule_id": "x", "kind": "failure_threshold",
                 "match_event_types": ["a"]}]}, "缺 threshold/window"),
    ({"rules": [{"rule_id": "x", "kind": "approval_required"}]}, "空 match_event_types"),
    ({"rules": [{"rule_id": "x", "kind": "approval_required",
                 "match_event_types": ["a"]},
                {"rule_id": "x", "kind": "approval_required",
                 "match_event_types": ["a"]}]}, "rule_id 重复"),
    ({"retention_days": -3}, "负保留期"),
    ({"max_retries": "many"}, "非数值"),
])
def test_invalid_config_rejected(tmp_path, data, label):
    with pytest.raises(ConfigError) as ei:
        load_config(write_cfg(tmp_path, data))
    log_case(f"非法配置被拒绝：{label}", inputs=data,
             basis="严格类型/取值校验", result={"error": str(ei.value)})


def test_capacity_retention_and_verify_status(service):
    service.config.retention_max_records = 4
    from datetime import datetime, timezone
    base = int(datetime.now(timezone.utc).timestamp() * 1000) - 100_000
    for i in range(10):
        raw = {"action": "login_ok", "user": f"u{i}", "object": "w",
               "timestamp": base + i * 1000, "event_uuid": f"e{i}"}
        service.ingest(raw, source="gitlab", source_version="1.0")
    assert service.verify().status == VerifyStatus.OK
    info = service.prune()
    r = service.verify()
    remaining = service.list_events(limit=100)
    log_case("容量保留：仅留最新 4 条，旧数据锚点封包",
             inputs={"total": 10, "retention_max_records": 4},
             basis="删除 seq<min+overflow，封锚 tail_seq/tail_hash",
             result={"deleted": info["deleted"], "remaining": info["remaining"],
                     "verify": r.status.value,
                     "remaining_seqs": [e["seq"] for e in remaining]})
    assert info["deleted"] == 6 and info["remaining"] == 4
    assert r.status == VerifyStatus.OK_AFTER_PRUNE
    assert [e["seq"] for e in remaining] == [7, 8, 9, 10]
    assert r.issues == []


def test_age_retention(service):
    """直接以不同 event_ts 落链，验证按保留期裁剪：超期删、近期留。"""
    from datetime import datetime, timezone
    from auditpipe.models import NormalizedEvent

    service.config.retention_days = 30
    now = int(datetime.now(timezone.utc).timestamp() * 1000)
    day = 86_400_000
    # 2 条超期（60/40 天前），2 条在保留期内（10/1 天前）
    spec = [("old1", now - 60 * day), ("old2", now - 40 * day),
            ("new1", now - 10 * day), ("new2", now - 1 * day)]
    for u, ts in spec:
        ev = NormalizedEvent(
            event_id=f"id-{u}", source="gitlab", source_version="1.0",
            event_type="login_ok", actor="u", target="w", event_ts=ts,
            raw={"event_uuid": u}, dedup_key=f"gitlab:{u}", ingest_ts=now,
            extras={})
        service.storage.append_chain(ev)

    assert service.verify().status == VerifyStatus.OK
    info = service.prune()
    r = service.verify()
    remaining = service.list_events(limit=100)
    log_case("保留期清理：删除 30 天前事件，近期保留",
             inputs={"ages_days": [60, 40, 10, 1], "retention_days": 30},
             basis="cutoff = 第一条 event_ts>=now-30d 的 seq；更早的删除并封锚",
             result={"deleted": info["deleted"], "remaining": info["remaining"],
                     "verify": r.status.value,
                     "remaining_ids": [e["event_id"] for e in remaining]})
    assert info["deleted"] == 2
    assert [e["event_id"] for e in remaining] == ["id-new1", "id-new2"]
    assert r.status == VerifyStatus.OK_AFTER_PRUNE
    assert r.issues == []
