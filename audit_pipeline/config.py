"""管线配置：存储路径、保留策略、合规规则、下游投递。

配置可从 JSON 文件加载（见 scripts/config.example.json），也可用代码直接构造。
JSON 字段名与 dataclass 字段一一对应；未知字段会报错，避免写错配置被静默忽略。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import RuleConfig, Severity


@dataclass(slots=True)
class RetentionConfig:
    """保留策略：超过保留天数或超过容量上限的旧记录将被清理。"""

    max_age_days: int | None = None
    max_records: int | None = None
    segment_size: int = 1000


@dataclass(slots=True)
class DispatcherConfig:
    """下游投递配置。

    sink_type: null（丢弃/排空用）| file（本地文件，sink_path）| fail（总是失败，测试用）
    """

    sink_type: str = "null"
    max_retries: int = 3
    base_delay_seconds: float = 0.05
    queue_size: int = 1000
    timeout_seconds: float = 2.0
    sink_path: str | None = None


@dataclass(slots=True)
class PipelineConfig:
    data_dir: str = "data/audit"
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    dispatcher: DispatcherConfig = field(default_factory=DispatcherConfig)
    rules: list[RuleConfig] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | None = None) -> "PipelineConfig":
        if path is None:
            return cls()
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))

        retention_raw = data.get("retention", {})
        retention = RetentionConfig(**retention_raw)

        dispatcher_raw = data.get("dispatcher", {})
        dispatcher = DispatcherConfig(**dispatcher_raw)

        rules: list[RuleConfig] = []
        for item in data.get("rules", []):
            item = dict(item)
            if "severity" in item:
                item["severity"] = Severity(item["severity"])
            rules.append(RuleConfig(**item))

        return cls(
            data_dir=data.get("data_dir", "data/audit"),
            retention=retention,
            dispatcher=dispatcher,
            rules=rules,
        )
