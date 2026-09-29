"""多来源/多版本事件的规范化（适配 + 校验）。

设计要点
--------
1. 每个 (source, version) 注册一个适配器：负责把来源私有字段映射到统一字段。
2. 版本兼容：
   - source 未登记           -> 拒绝（版本不兼容）
   - version 主版本号不同     -> 拒绝（不兼容）
   - 同主版本、更低次版本     -> 兼容（按登记适配器解析）
   - 同主版本、更高次版本     -> 兼容但 extras["forward_compat"]=True
3. 缺必填字段 / 时间无法解析或异常 -> ValidationError，由上层留痕，绝不静默丢弃。
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Callable

from .errors import ValidationError
from .models import NormalizedEvent, PipelineConfig

# 统一记录的必填字段（适配器必须全部给出非空值）
REQUIRED_FIELDS = ("event_type", "actor", "target", "event_ts", "dedup_raw")

# 早于该时间的事件时间视为异常（2000-01-01T00:00:00Z, epoch ms）
MIN_VALID_TS_MS = 946684800000

Adapter = Callable[[dict[str, Any]], dict[str, Any]]


def _ms_epoch(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def parse_event_time(value: Any) -> int:
    """把多种形态的事件时间解析为 epoch 毫秒；无法解析时抛 ValidationError。"""
    if isinstance(value, bool):
        raise ValidationError(f"事件时间字段类型非法: {value!r}")
    if isinstance(value, (int, float)):
        f = float(value)
        # 启发式：秒级时间戳（10 位量级）换算为毫秒
        if abs(f) < 1e11:
            f *= 1000.0
        return int(f)
    if isinstance(value, str):
        s = value.strip()
        if re.fullmatch(r"-?\d+(\.\d+)?", s):
            return parse_event_time(float(s))
        txt = s
        if txt.endswith("Z"):
            txt = txt[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(txt)
        except ValueError as exc:
            raise ValidationError(f"事件时间无法解析: {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return _ms_epoch(dt.astimezone(timezone.utc))
    raise ValidationError(f"事件时间字段类型非法: {value!r}")


# ---------------------------------------------------------------------------
# 各来源适配器：返回统一字段的中间映射
# 统一字段: event_type, actor, target, event_ts(原始时间值), dedup_raw,
#           approval_ref, severity, extras(剩余字段)
# ---------------------------------------------------------------------------
def _adapter_gitlab_v1(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_type": raw.get("action"),
        "actor": raw.get("user"),
        "target": raw.get("object"),
        "event_ts": raw.get("timestamp"),
        "dedup_raw": raw.get("event_uuid"),
        "approval_ref": raw.get("approval"),
        "severity": raw.get("level", "info"),
    }


def _adapter_jenkins_v2(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_type": raw.get("eventType"),
        "actor": raw.get("userId"),
        "target": raw.get("resource"),
        "event_ts": raw.get("occurredAt"),
        "dedup_raw": raw.get("id"),
        "approval_ref": raw.get("ticket"),
        "severity": raw.get("severity", "info"),
    }


# source -> 适配器登记。键为"最低兼容版本"，主版本相同即视为同一 schema 世代。
SOURCE_ADAPTERS: dict[str, dict[str, str]] = {
    "gitlab": {"1.0": "gitlab_v1"},
    "jenkins": {"2.0": "jenkins_v2"},
}

_ADAPTER_TABLE: dict[str, Adapter] = {
    "gitlab_v1": _adapter_gitlab_v1,
    "jenkins_v2": _adapter_jenkins_v2,
}


def _parse_semver(v: str) -> tuple[int, int]:
    m = re.fullmatch(r"(\d+)\.(\d+)", str(v).strip())
    if not m:
        raise ValidationError(f"来源版本号格式无法识别: {v!r}")
    return int(m.group(1)), int(m.group(2))


def _resolve_adapter(source: str, version: str) -> tuple[Adapter, str, bool]:
    """返回 (适配器, 登记基准版本, 是否为更新的次版本[前向兼容])。"""
    if source not in SOURCE_ADAPTERS:
        raise ValidationError(f"不支持的事件来源（版本不兼容）: source={source!r}")
    versions = SOURCE_ADAPTERS[source]
    req_major, req_minor = _parse_semver(version)
    chosen_base: str | None = None
    for base in versions:
        b_major, _ = _parse_semver(base)
        if b_major != req_major:
            continue
        # 同主版本：登记版本即该世代的适配器
        chosen_base = base
    if chosen_base is None:
        supported = ", ".join(sorted(versions))
        raise ValidationError(
            f"事件版本不兼容: source={source!r} version={version!r}，"
            f"已登记兼容版本: [{supported}]（主版本必须一致）"
        )
    _, base_minor = _parse_semver(chosen_base)
    forward = req_minor > base_minor
    return _ADAPTER_TABLE[versions[chosen_base]], chosen_base, forward


def _stable_event_id(source: str, dedup_key: str) -> str:
    h = hashlib.sha256(f"{source}|{dedup_key}".encode("utf-8")).hexdigest()
    return h[:32]


def normalize_event(
    raw: dict[str, Any],
    *,
    source: str,
    source_version: str,
    config: PipelineConfig,
    now_ms: int | None = None,
) -> NormalizedEvent:
    """把一条来源事件转换成统一记录。异常时抛 ValidationError。"""
    if not isinstance(raw, dict):
        raise ValidationError("事件体必须是 JSON 对象")

    adapter, base_version, forward = _resolve_adapter(source, source_version)
    mapped = adapter(raw)

    # 必填字段检查（不得静默缺失）
    missing = [f for f in REQUIRED_FIELDS if mapped.get(f) in (None, "")]
    if missing:
        raise ValidationError(
            f"必填字段缺失: {', '.join(missing)}（source={source} v{source_version}）"
        )

    event_ts = parse_event_time(mapped["event_ts"])
    if event_ts < MIN_VALID_TS_MS:
        raise ValidationError(f"事件时间异常（早于 2000-01-01）: {mapped['event_ts']!r}")

    now = now_ms if now_ms is not None else _ms_epoch(datetime.now(timezone.utc))
    skew = config.allowed_clock_skew_seconds * 1000
    if event_ts > now + skew:
        raise ValidationError(
            f"事件时间异常（超出允许的未来时钟偏差 {config.allowed_clock_skew_seconds}s）: "
            f"event_ts={event_ts} now={now}"
        )

    dedup_raw = str(mapped["dedup_raw"]).strip()
    if not dedup_raw:
        raise ValidationError("幂等键为空")
    dedup_key = f"{source}:{dedup_raw}"
    event_id = _stable_event_id(source, dedup_key)

    extras: dict[str, Any] = {"schema_base_version": base_version}
    if forward:
        extras["forward_compat"] = True
        extras["reported_version"] = source_version
    if mapped.get("severity") and mapped["severity"] != "info":
        extras["source_severity"] = mapped["severity"]

    return NormalizedEvent(
        event_id=event_id,
        source=source,
        source_version=source_version,
        event_type=str(mapped["event_type"]),
        actor=str(mapped["actor"]),
        target=str(mapped["target"]),
        event_ts=event_ts,
        raw=raw,
        dedup_key=dedup_key,
        approval_ref=(str(mapped["approval_ref"]).strip()
                      if mapped.get("approval_ref") not in (None, "") else None),
        severity=str(mapped.get("severity") or "info"),
        extras=extras,
        ingest_ts=now,
    )
