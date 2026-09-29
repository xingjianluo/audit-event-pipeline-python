"""本地端到端演示：不依赖任何外部服务。

用法（在项目根目录执行）：
    uv run python scripts/local_demo.py
结束后可在 data/audit_demo/ 下查看链文件、拒绝清单、告警与下游投递文件。
"""
from __future__ import annotations

import json
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit_pipeline.config import DispatcherConfig, PipelineConfig, RetentionConfig  # noqa: E402
from audit_pipeline.models import RuleConfig, Severity  # noqa: E402
from audit_pipeline.pipeline import AuditPipeline  # noqa: E402

DATA_DIR = Path("data/audit_demo")


def main() -> None:
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    cfg = PipelineConfig(
        data_dir=str(DATA_DIR),
        retention=RetentionConfig(max_age_days=30, max_records=100, segment_size=5),
        dispatcher=DispatcherConfig(
            sink_type="file",
            sink_path=str(DATA_DIR / "dispatch" / "downstream.jsonl"),
            max_retries=2,
            queue_size=100,
        ),
        rules=[
            RuleConfig(rule_id="DEMO_FAIL_3", rule_type="failure_threshold",
                       description="演示窗口内3次失败", severity=Severity.WARNING,
                       window_seconds=3600, threshold=3, match_result="failure"),
            RuleConfig(rule_id="DEMO_APPROVAL", rule_type="approval_required",
                       description="演示敏感操作审批", severity=Severity.CRITICAL,
                       actions=["delete_user"]),
        ],
    )
    pipeline = AuditPipeline(cfg)

    events = [
        {"source": "login", "version": "1.0", "id": "EV-1", "username": "alice",
         "op": "login", "target": "console", "ok": False, "ts": 1780000000},
        {"source": "login", "version": "1.0", "id": "EV-2", "username": "alice",
         "op": "login", "target": "console", "ok": False, "ts": 1780000005},
        {"source": "login", "version": "1.0", "id": "EV-2", "username": "alice",
         "op": "login", "target": "console", "ok": False, "ts": 1780000005},  # 重复
        {"source": "login", "version": "1.0", "id": "EV-4", "username": "alice",
         "op": "login", "target": "console", "ok": False, "ts": 1780000009},
        {"source": "payment", "version": "2.1", "event_id": "EV-3", "actor": {"id": "bob"},
         "action": "delete_user", "resource": "user/42", "result": "success",
         "occurred_at": "2026-09-30T01:00:00Z"},  # 无审批
        {"source": "payment", "version": "9.0", "event_id": "EV-BAD", "actor": "x",
         "action": "noop", "resource": "r", "result": "success",
         "occurred_at": "2026-09-30T01:00:00Z"},  # 不兼容版本
    ]
    print("== 接入 ==")
    for raw in events:
        result = pipeline.ingest(raw)
        suffix = f" ({result.reason})" if result.reason else ""
        print(f"  {raw.get('id') or raw.get('event_id')}: {result.status.value}{suffix}")

    print("== 完整性校验 ==")
    v = pipeline.verify()
    print(json.dumps({"ok": v.ok, "complete": v.complete,
                      "records_verified": v.records_verified,
                      "issues": [asdict(i) for i in v.issues]},
                     ensure_ascii=False, indent=2))

    print("== 告警 ==")
    for alert in pipeline.alert_store.list_all():
        print(f"  [{alert.severity.value}] {alert.rule_id}: {alert.message} events={alert.event_ids}")

    print("== 演示：人为篡改一行后再校验 ==")
    seg = sorted((DATA_DIR / "segments").glob("*.jsonl"))[0]
    lines = seg.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    obj["actor"] = "intruder"
    lines[0] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    seg.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v2 = AuditPipeline(cfg).verify() if False else pipeline.verify()
    print(f"  ok={v2.ok}, 定位问题: {[(i.kind, i.location) for i in v2.issues]}")

    pipeline.shutdown()
    print("== 投递状态 ==", pipeline.dispatcher.status())
    print("== 被拒事件 ==")
    for rejected in pipeline.store.list_rejected():
        print(f"  {rejected.reason}")


if __name__ == "__main__":
    main()
