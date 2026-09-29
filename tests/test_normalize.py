"""多来源/多版本接入：统一格式、字段缺失、时间异常、版本不兼容拒收。"""

import time

import pytest

from auditpipe.errors import ValidationError
from auditpipe.models import PipelineConfig
from auditpipe.normalize import normalize_event

from conftest import log_case

NOW = int(time.time() * 1000)


def _raw(minutes_ago=1.0):
    from conftest import gitlab_event
    return gitlab_event("u-1", minutes_ago=minutes_ago)


def test_unified_format_and_stable_id():
    cfg = PipelineConfig()
    raw = _raw()
    ev = normalize_event(raw, source="gitlab", source_version="1.0",
                         config=cfg, now_ms=NOW)
    expected_fields = {
        "event_id", "source", "source_version", "event_type", "actor",
        "target", "event_ts", "ingest_ts", "dedup_key", "approval_ref",
        "severity", "extras", "raw",
    }
    assert expected_fields <= set(vars(ev).keys())
    # 相同输入必须得到相同 event_id（幂等基础）
    ev2 = normalize_event(dict(raw), source="gitlab", source_version="1.0",
                          config=cfg, now_ms=NOW)
    log_case("统一格式与稳定ID", inputs=raw,
             basis="event_id = sha256(source|dedup_key)",
             result={"event_id": ev.event_id, "same_on_repeat": ev.event_id == ev2.event_id})
    assert ev.event_id == ev2.event_id


def test_missing_fields_rejected_and_recorded(service):
    raw = {"user": "alice"}  # 缺 action/object/timestamp/event_uuid
    result = service.ingest(raw, source="gitlab", source_version="1.0")
    rejected = service.list_rejected()
    log_case("字段缺失不得静默丢弃", inputs=raw,
             basis="必填字段 event_type/target/event_ts/dedup_raw 校验",
             result={"status": result.status.value, "reason": result.reason,
                     "rejected_rows": len(rejected)})
    assert result.status.value == "rejected"
    assert "必填字段缺失" in result.reason
    assert len(rejected) == 1
    assert rejected[0].raw_json  # 原文留存可查


@pytest.mark.parametrize("version,label", [("2.0", "主版本不兼容"), ("0.9", "主版本不兼容")])
def test_incompatible_version_rejected(version, label):
    cfg = PipelineConfig()
    with pytest.raises(ValidationError) as ei:
        normalize_event(_raw(), source="gitlab", source_version=version,
                        config=cfg, now_ms=NOW)
    log_case(f"版本不兼容：{label}", inputs={"source": "gitlab", "version": version},
             basis="主版本号必须与登记世代一致", result={"error": str(ei.value)})
    assert "版本不兼容" in str(ei.value)


def test_unknown_source_rejected():
    cfg = PipelineConfig()
    with pytest.raises(ValidationError) as ei:
        normalize_event(_raw(), source="ghost", source_version="1.0",
                        config=cfg, now_ms=NOW)
    log_case("来源未登记", inputs={"source": "ghost"},
             basis="SOURCE_ADAPTERS 白名单", result={"error": str(ei.value)})
    assert "不支持的事件来源" in str(ei.value)


def test_forward_compatible_minor_version():
    cfg = PipelineConfig()
    ev = normalize_event(_raw(), source="gitlab", source_version="1.7",
                         config=cfg, now_ms=NOW)
    log_case("同主版本更高次版本-前向兼容",
             inputs={"source": "gitlab", "version": "1.7"},
             basis="主版本一致即兼容，标记 forward_compat",
             result={"extras": ev.extras, "event_type": ev.event_type})
    assert ev.extras.get("forward_compat") is True


def test_second_source_jenkins_mapping():
    cfg = PipelineConfig()
    from datetime import datetime, timezone
    occurred = datetime.now(timezone.utc).isoformat()
    raw = {
        "eventType": "deploy", "userId": "ci-bot", "resource": "prod/cluster",
        "occurredAt": occurred, "id": "job-007", "ticket": "CHG-9",
    }
    ev = normalize_event(raw, source="jenkins", source_version="2.1",
                         config=cfg, now_ms=NOW)
    log_case("第二来源 jenkins v2.1 字段映射", inputs=raw,
             basis="jenkins_v2 适配器；同主版本更高次版本前向兼容",
             result={"event_type": ev.event_type, "actor": ev.actor,
                     "target": ev.target, "approval_ref": ev.approval_ref,
                     "dedup_key": ev.dedup_key, "extras": ev.extras})
    assert (ev.event_type, ev.actor, ev.target, ev.approval_ref) == (
        "deploy", "ci-bot", "prod/cluster", "CHG-9")
    assert ev.dedup_key == "jenkins:job-007"
    assert ev.extras.get("forward_compat") is True


def test_future_event_time_rejected():
    cfg = PipelineConfig(allowed_clock_skew_seconds=300)
    raw = {
        "action": "login_failed", "user": "a", "object": "w",
        "timestamp": "2099-01-01T00:00:00Z", "event_uuid": "future",
    }
    with pytest.raises(ValidationError) as ei:
        normalize_event(raw, source="gitlab", source_version="1.0",
                        config=cfg, now_ms=NOW)
    log_case("事件时间在遥远未来-时间异常", inputs=raw,
             basis="event_ts 不得超过 now+allowed_clock_skew",
             result={"error": str(ei.value)})
    assert "时间异常" in str(ei.value)


def test_unparseable_time_rejected():
    cfg = PipelineConfig()
    raw = {"action": "login_failed", "user": "a", "object": "w",
           "timestamp": "not-a-time", "event_uuid": "badtime"}
    with pytest.raises(ValidationError) as ei:
        normalize_event(raw, source="gitlab", source_version="1.0",
                        config=cfg, now_ms=NOW)
    log_case("无法解析的事件时间", inputs=raw, basis="parse_event_time 失败",
             result={"error": str(ei.value)})
    assert "时间无法解析" in str(ei.value)
