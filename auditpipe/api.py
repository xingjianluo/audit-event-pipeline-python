"""HTTP API：在不破坏原有可用性的前提下新增审计能力。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

_SERVICE: Any = None


def set_service(service: Any) -> None:
    global _SERVICE
    _SERVICE = service


def get_service():
    if _SERVICE is None:
        raise HTTPException(status_code=503, detail="审计服务尚未初始化")
    return _SERVICE


def _alert_to_dict(a) -> dict:
    return {
        "alert_id": a.alert_id,
        "rule_id": a.rule_id,
        "rule_kind": a.rule_kind,
        "severity": a.severity.value,
        "message": a.message,
        "evidence": a.evidence,
        "created_ts": a.created_ts,
        "delivered": a.delivered,
    }


@router.post("/api/v1/events")
async def ingest_event(request: Request) -> dict:
    """接入一条审计事件。

    通过查询参数或请求体顶层指定 source / source_version；
    请求体其余部分为来源原始事件。
    """
    body = await request.json()
    source = request.query_params.get("source") or body.pop("source", None)
    source_version = (
        request.query_params.get("source_version") or body.pop("source_version", None)
    )
    if not source or not source_version:
        raise HTTPException(status_code=422, detail="必须提供 source 与 source_version")

    svc = get_service()
    result = svc.ingest(body, source=source, source_version=source_version)
    return {
        "status": result.status.value,
        "event_id": result.event_id,
        "deduped": result.deduped,
        "seq": result.seq,
        "delivery_id": result.delivery_id,
        "backpressure": result.backpressure,
        "reason": result.reason,
    }


@router.get("/api/v1/events")
def list_events(after_seq: int = 0, limit: int = 100) -> dict:
    svc = get_service()
    return {"events": svc.list_events(after_seq=after_seq, limit=limit)}


@router.get("/api/v1/rejected")
def list_rejected(limit: int = 100) -> dict:
    svc = get_service()
    return {
        "rejected": [
            {
                "reject_id": r.reject_id,
                "source": r.source,
                "source_version": r.source_version,
                "reason": r.reason,
                "raw": _safe_json(r.raw_json),
                "ingest_ts": r.ingest_ts,
                "dedup_hint": r.dedup_hint,
            }
            for r in svc.list_rejected(limit=limit)
        ]
    }


@router.get("/api/v1/alerts")
def list_alerts(delivered: bool | None = None, limit: int = 100) -> dict:
    svc = get_service()
    return {"alerts": [_alert_to_dict(a) for a in svc.list_alerts(delivered, limit)]}


@router.get("/api/v1/delivery")
def list_delivery(state: str | None = None) -> dict:
    svc = get_service()
    return {"delivery": svc.list_delivery(state)}


@router.get("/api/v1/verify")
def verify() -> dict:
    svc = get_service()
    r = svc.verify()
    return {
        "status": r.status.value,
        "pruned": r.pruned,
        "total_records": r.total_records,
        "head_seq": r.head_seq,
        "tail_seq": r.tail_seq,
        "checked_at": r.checked_at,
        "issues": [
            {
                "index": i.index,
                "kind": i.kind,
                "expected": i.expected,
                "actual": i.actual,
                "detail": i.detail,
            }
            for i in r.issues
        ],
    }


@router.post("/api/v1/prune")
def prune() -> dict:
    svc = get_service()
    return svc.prune()


def _safe_json(text: str):
    import json

    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return text
