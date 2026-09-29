"""规则/管道配置的声明式加载（JSON）。

配置文件示例见 README。顶层键全部可选；rules 为规则数组。
"""

from __future__ import annotations

import json

from .errors import ConfigError
from .models import AlertSeverity, PipelineConfig, RuleConfig

_VALID_RULE_KINDS = {"failure_threshold", "approval_required"}
_VALID_SEVERITIES = {s.value for s in AlertSeverity}

_DEFAULTS = {
    "max_queue_size": 1000,
    "max_retries": 3,
    "retry_backoff_ms": 50,
    "retention_days": 90,
    "retention_max_records": 0,
    "allowed_clock_skew_seconds": 300,
}


def _require_nonneg_int(d: dict, key: str) -> int:
    val = d.get(key, _DEFAULTS[key])
    if not isinstance(val, int) or isinstance(val, bool) or val < 0:
        raise ConfigError(f"配置项 {key} 必须是非负整数，实际为 {val!r}")
    return val


def _parse_rule(raw: dict, index: int) -> RuleConfig:
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} 必须是对象")
    rule_id = raw.get("rule_id")
    if not rule_id or not isinstance(rule_id, str):
        raise ConfigError(f"{where}.rule_id 必须是非空字符串")
    kind = raw.get("kind")
    if kind not in _VALID_RULE_KINDS:
        raise ConfigError(
            f"{where}.kind 必须是 {sorted(_VALID_RULE_KINDS)} 之一，实际为 {kind!r}"
        )
    sev_raw = raw.get("severity", "medium")
    if sev_raw not in _VALID_SEVERITIES:
        raise ConfigError(f"{where}.severity 非法: {sev_raw!r}")

    def _str_list(key: str) -> list[str]:
        val = raw.get(key, [])
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise ConfigError(f"{where}.{key} 必须是字符串数组")
        return list(val)

    match_event_types = _str_list("match_event_types")
    match_sources = _str_list("match_sources")
    if not match_event_types:
        raise ConfigError(f"{where}.match_event_types 不能为空")

    threshold = raw.get("threshold", 0)
    window_seconds = raw.get("window_seconds", 0)
    if kind == "failure_threshold":
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
            raise ConfigError(f"{where}.threshold 必须是 >=1 的整数")
        if not isinstance(window_seconds, int) or isinstance(window_seconds, bool) or window_seconds < 1:
            raise ConfigError(f"{where}.window_seconds 必须是 >=1 的整数")

    return RuleConfig(
        rule_id=rule_id,
        kind=kind,
        description=str(raw.get("description", "")),
        match_event_types=match_event_types,
        match_sources=match_sources,
        threshold=threshold if isinstance(threshold, int) else 0,
        window_seconds=window_seconds if isinstance(window_seconds, int) else 0,
        severity=AlertSeverity(sev_raw),
        enabled=bool(raw.get("enabled", True)),
    )


def load_config(path: str) -> PipelineConfig:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise ConfigError(f"配置文件不存在: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置文件不是合法 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("配置文件顶层必须是 JSON 对象")

    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        raise ConfigError("rules 必须是数组")
    rules = [_parse_rule(r, i) for i, r in enumerate(rules_raw)]
    ids = [r.rule_id for r in rules]
    if len(ids) != len(set(ids)):
        raise ConfigError("rules.rule_id 必须唯一")

    return PipelineConfig(
        rules=rules,
        max_queue_size=_require_nonneg_int(data, "max_queue_size"),
        max_retries=_require_nonneg_int(data, "max_retries"),
        retry_backoff_ms=_require_nonneg_int(data, "retry_backoff_ms"),
        retention_days=_require_nonneg_int(data, "retention_days"),
        retention_max_records=_require_nonneg_int(data, "retention_max_records"),
        allowed_clock_skew_seconds=_require_nonneg_int(data, "allowed_clock_skew_seconds"),
    )


def config_to_dict(cfg: PipelineConfig) -> dict:
    return {
        "max_queue_size": cfg.max_queue_size,
        "max_retries": cfg.max_retries,
        "retry_backoff_ms": cfg.retry_backoff_ms,
        "retention_days": cfg.retention_days,
        "retention_max_records": cfg.retention_max_records,
        "allowed_clock_skew_seconds": cfg.allowed_clock_skew_seconds,
        "rules": [
            {
                "rule_id": r.rule_id,
                "kind": r.kind,
                "description": r.description,
                "match_event_types": r.match_event_types,
                "match_sources": r.match_sources,
                "threshold": r.threshold,
                "window_seconds": r.window_seconds,
                "severity": r.severity.value,
                "enabled": r.enabled,
            }
            for r in cfg.rules
        ],
    }
