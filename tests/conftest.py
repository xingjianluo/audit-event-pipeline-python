import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit_pipeline.config import (  # noqa: E402
    DispatcherConfig,
    PipelineConfig,
    RetentionConfig,
)
from audit_pipeline.models import RuleConfig, Severity  # noqa: E402
from audit_pipeline.pipeline import AuditPipeline  # noqa: E402


def make_pipeline(tmp_path, *, sink_type="null", rules=None, segment_size=50,
                  queue_size=1000, max_retries=2, sink_path=None,
                  max_age_days=None, max_records=None, timeout_seconds=1.0):
    cfg = PipelineConfig(
        data_dir=str(tmp_path / "audit"),
        retention=RetentionConfig(max_age_days=max_age_days, max_records=max_records,
                                  segment_size=segment_size),
        dispatcher=DispatcherConfig(sink_type=sink_type, max_retries=max_retries,
                                    base_delay_seconds=0.01, queue_size=queue_size,
                                    timeout_seconds=timeout_seconds, sink_path=sink_path),
        rules=rules or [],
    )
    return AuditPipeline(cfg)


def default_rules():
    return [
        RuleConfig(rule_id="LOGIN_FAILURE_3_5M", rule_type="failure_threshold",
                   description="5分钟内登录失败>=3次",
                   window_seconds=300, threshold=3,
                   match_source="login", match_result="failure"),
        RuleConfig(rule_id="SENSITIVE_APPROVAL", rule_type="approval_required",
                   description="敏感操作必须有审批",
                   severity=Severity.CRITICAL,
                   actions=["delete_user", "wire_transfer"]),
    ]


@pytest.fixture
def pipeline_factory(tmp_path):
    created = []

    def _factory(**kw):
        p = make_pipeline(tmp_path / f"case{len(created)}", **kw)
        created.append(p)
        return p

    yield _factory

    for p in created:
        p.shutdown()
