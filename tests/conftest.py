"""pytest 公共夹具与用例日志辅助。

每条用例都会打印：输入 -> 判定依据 -> 最终结果，保证结论稳定可解释。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta

import pytest

from auditpipe.models import PipelineConfig, RuleConfig, AlertSeverity
from auditpipe.service import AuditService


def log_case(title: str, inputs=None, basis=None, result=None) -> None:
    print("\n" + "=" * 72)
    print(f"用例: {title}")
    print("-" * 72)
    print("输入:")
    print(json.dumps(inputs, ensure_ascii=False, indent=2, default=str))
    if basis is not None:
        print("判定依据:")
        print(json.dumps(basis, ensure_ascii=False, indent=2, default=str))
    if result is not None:
        print("最终结果:")
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    print("=" * 72)


def iso(minutes_ago: float = 0, seconds_offset: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago,
                                                seconds=-seconds_offset)
    return dt.isoformat()


def make_config(**kwargs) -> PipelineConfig:
    rules = kwargs.pop("rules", None)
    if rules is None:
        rules = [
            RuleConfig(
                rule_id="login-burst",
                kind="failure_threshold",
                match_event_types=["login_failed"],
                threshold=5,
                window_seconds=300,
                severity=AlertSeverity.HIGH,
            ),
            RuleConfig(
                rule_id="need-approval",
                kind="approval_required",
                match_event_types=["sensitive_op"],
                severity=AlertSeverity.CRITICAL,
            ),
        ]
    return PipelineConfig(rules=rules, **kwargs)


@pytest.fixture()
def service():
    cfg = make_config(retention_max_records=1000, max_queue_size=100,
                      max_retries=2, retry_backoff_ms=1)
    svc = AuditService(":memory:", cfg)
    svc.start()
    yield svc
    svc.close()


def gitlab_event(uuid: str, *, action="login_failed", user="alice",
                 obj="web", minutes_ago=1.0, approval=None) -> dict:
    ev = {
        "action": action,
        "user": user,
        "object": obj,
        "timestamp": iso(minutes_ago),
        "event_uuid": uuid,
    }
    if approval is not None:
        ev["approval"] = approval
    return ev
