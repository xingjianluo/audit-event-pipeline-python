"""多来源/多版本审计事件的适配与归一化。

支持的来源与兼容范围（主版本号兼容，主版本不同视为不兼容）：
- audit/1.x   规范格式（字段名与 NormalizedEvent 一致，occurred_at 为 ISO8601）
- login/1.x   登录服务：id/username/op/target/ok(bool)/ts(Unix 秒)
- payment/2.x 支付服务：event_id/actor/action/resource/result/occurred_at(ISO8601 Z)/approval_ref

校验失败（必填字段缺失、时间无法解析或明显异常、来源版本不兼容、结果值无法识别）
一律抛 EventValidationError，由上层记录到拒绝清单，绝不静默丢弃。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from .models import NormalizedEvent

SCHEMA_VERSION = "audit/1"
MIN_YEAR = 2000
MAX_FUTURE_SKEW_SECONDS = 24 * 3600

_RESULT_ALIASES = {
    "success": "success",
    "succeeded": "success",
    "ok": "success",
    "passed": "success",
    "failure": "failure",
    "failed": "failure",
    "fail": "failure",
    "error": "failure",
    "denied": "denied",
    "rejected": "denied",
}
_CANONICAL_RESULTS = {"success", "failure", "denied"}


class EventValidationError(ValueError):
    """事件无法归一化；reason 面向调用方，说明具体判定依据。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: Any, field: str = "occurred_at") -> datetime:
    """容忍三种时间表达：ISO8601（含结尾 Z）、Unix 秒、Unix 毫秒。"""
    if isinstance(value, bool):
        raise EventValidationError(f"invalid timestamp for {field}: {value!r}")
    if isinstance(value, (int, float)):
        seconds = float(value)
        # 毫秒启发：2286 年以后的秒级时间戳显然不合理，按毫秒处理
        if seconds > 1e11:
            seconds /= 1000.0
        try:
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise EventValidationError(f"invalid timestamp for {field}: {value!r} ({exc})") from exc
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            # 纯数字字符串按 Unix 秒处理
            try:
                return parse_timestamp(float(value), field)
            except ValueError as exc:
                raise EventValidationError(f"unparseable timestamp for {field}: {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    else:
        raise EventValidationError(f"missing or invalid timestamp for {field}: {value!r}")

    now = utcnow()
    if dt.year < MIN_YEAR:
        raise EventValidationError(f"anomalous timestamp for {field}: {dt.isoformat()} before year {MIN_YEAR}")
    if (dt - now).total_seconds() > MAX_FUTURE_SKEW_SECONDS:
        raise EventValidationError(
            f"anomalous timestamp for {field}: {dt.isoformat()} more than "
            f"{MAX_FUTURE_SKEW_SECONDS}s in the future"
        )
    return dt


def _require(raw: dict, key: str) -> Any:
    if key not in raw or raw[key] is None or (isinstance(raw[key], str) and not raw[key].strip()):
        raise EventValidationError(f"missing required field: {key}")
    return raw[key]


def _normalize_result(value: Any) -> str:
    if not isinstance(value, str):
        raise EventValidationError(f"unrecognized result value: {value!r}")
    mapped = _RESULT_ALIASES.get(value.strip().lower())
    if mapped is None:
        raise EventValidationError(f"unrecognized result value: {value!r}")
    return mapped


def _event_id_str(value: Any) -> str:
    if isinstance(value, str):
        v = value.strip()
        if v:
            return v
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise EventValidationError(f"invalid event_id: {value!r}")


def _major_version(version: str) -> str:
    return version.strip().split(".")[0]


def _adapt_audit_1(raw: dict) -> NormalizedEvent:
    event_id = _event_id_str(_require(raw, "event_id"))
    event_type = str(_require(raw, "event_type")).strip()
    actor = str(_require(raw, "actor")).strip()
    action = str(_require(raw, "action")).strip()
    resource = str(_require(raw, "resource")).strip()
    result = _normalize_result(_require(raw, "result"))
    occurred_at = parse_timestamp(_require(raw, "occurred_at"))
    metadata = raw.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise EventValidationError("metadata must be an object")
    approval_id = raw.get("approval_id")
    if approval_id is not None and not str(approval_id).strip():
        approval_id = None
    return NormalizedEvent(
        event_id=event_id,
        source="audit",
        source_version=f"audit/{_major_version(str(raw.get('version', '1')))}",
        schema_version=SCHEMA_VERSION,
        event_type=event_type,
        actor=actor,
        action=action,
        resource=resource,
        result=result,
        occurred_at=occurred_at,
        ingested_at=utcnow(),
        approval_id=(str(approval_id).strip() if approval_id is not None else None),
        metadata=metadata,
    )


def _adapt_login_1(raw: dict) -> NormalizedEvent:
    event_id = _event_id_str(_require(raw, "id"))
    username = str(_require(raw, "username")).strip()
    action = str(_require(raw, "op")).strip()
    target = str(_require(raw, "target")).strip()
    ok = _require(raw, "ok")
    if not isinstance(ok, bool):
        raise EventValidationError(f"login 'ok' must be boolean, got {ok!r}")
    occurred_at = parse_timestamp(_require(raw, "ts"), field="ts")
    metadata = raw.get("metadata")
    metadata = dict(metadata) if isinstance(metadata, dict) else {}
    return NormalizedEvent(
        event_id=event_id,
        source="login",
        source_version=f"login/{_major_version(str(raw.get('version', '1')))}",
        schema_version=SCHEMA_VERSION,
        event_type="authentication",
        actor=username,
        action=action,
        resource=target,
        result="success" if ok else "failure",
        occurred_at=occurred_at,
        ingested_at=utcnow(),
        approval_id=None,
        metadata=metadata,
    )


def _adapt_payment_2(raw: dict) -> NormalizedEvent:
    event_id = _event_id_str(_require(raw, "event_id"))
    actor_field = _require(raw, "actor")
    if isinstance(actor_field, dict):
        actor = str(_require(actor_field, "id")).strip()
    else:
        actor = str(actor_field).strip()
    action = str(_require(raw, "action")).strip()
    resource = str(_require(raw, "resource")).strip()
    result = _normalize_result(_require(raw, "result"))
    occurred_at = parse_timestamp(_require(raw, "occurred_at"))
    approval_ref = raw.get("approval_ref")
    if approval_ref is not None and not str(approval_ref).strip():
        approval_ref = None
    metadata = raw.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise EventValidationError("metadata must be an object")
    return NormalizedEvent(
        event_id=event_id,
        source="payment",
        source_version=f"payment/{_major_version(str(raw.get('version', '2')))}",
        schema_version=SCHEMA_VERSION,
        event_type=str(raw.get("event_type", "transaction")).strip(),
        actor=actor,
        action=action,
        resource=resource,
        result=result,
        occurred_at=occurred_at,
        ingested_at=utcnow(),
        approval_id=(str(approval_ref).strip() if approval_ref is not None else None),
        metadata=metadata,
    )


# (source, 主版本) -> 适配器
_ADAPTERS: dict[tuple[str, str], Callable[[dict], NormalizedEvent]] = {
    ("audit", "1"): _adapt_audit_1,
    ("login", "1"): _adapt_login_1,
    ("payment", "2"): _adapt_payment_2,
}
_KNOWN_SOURCES = {s for s, _ in _ADAPTERS}


def normalize_event(raw: dict) -> NormalizedEvent:
    """把来源事件归一化为统一格式；任何无法可靠解释的输入都会显式报错。"""
    if not isinstance(raw, dict):
        raise EventValidationError("event payload must be an object")
    source = raw.get("source")
    version = raw.get("version")
    if not source or not isinstance(source, str):
        raise EventValidationError("missing required field: source")
    if not version or not isinstance(version, str):
        # 规范格式也可能直接写成 schema=audit/1
        schema = raw.get("schema")
        if isinstance(schema, str) and "/" in schema:
            source, version = schema.split("/", 1)
            raw = dict(raw)
            raw["source"], raw["version"] = source, version
        else:
            raise EventValidationError("missing required field: version")
    major = _major_version(version)
    adapter = _ADAPTERS.get((source, major))
    if adapter is None:
        if source in _KNOWN_SOURCES:
            raise EventValidationError(
                f"incompatible version: source={source!r} version={version!r} is not supported "
                f"(known major versions for this source: "
                f"{sorted(v for s, v in _ADAPTERS if s == source)})"
            )
        raise EventValidationError(f"unknown event source: {source!r}")
    return adapter(raw)
