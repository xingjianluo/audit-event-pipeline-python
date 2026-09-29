"""HTTP API。

register_audit_routes(app) 把审计管线挂到既有 FastAPI 应用上，不改动原有路由。
create_app() 则构造一个自带审计能力、同时保留 {"Hello": "World"} 根路由的应用。
"""
from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .config import PipelineConfig
from .models import IngestStatus
from .pipeline import AuditPipeline


def _config_path() -> str | None:
    return os.environ.get("AUDIT_CONFIG")


def create_pipeline() -> AuditPipeline:
    config = PipelineConfig.load(_config_path())
    return AuditPipeline(config)


def _verification_dict(result) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "complete": result.complete,
        "records_verified": result.records_verified,
        "first_sequence": result.first_sequence,
        "last_sequence": result.last_sequence,
        "cuts": result.cuts,
        "issues": [asdict(i) for i in result.issues],
    }


def _alert_dict(alert) -> dict[str, Any]:
    d = asdict(alert)
    d["severity"] = alert.severity.value
    d["created_at"] = alert.created_at.isoformat()
    d["updated_at"] = alert.updated_at.isoformat()
    return d


def create_app(config: PipelineConfig | None = None) -> FastAPI:
    app = FastAPI(title="audit-event-pipeline")
    app.state.pipeline = AuditPipeline(config or PipelineConfig.load(_config_path()))

    @app.get("/")
    def read_root():
        # 保持既有服务可用性：原根路由行为不变
        return {"Hello": "World"}

    register_audit_routes(app)
    return app


def register_audit_routes(app: FastAPI) -> FastAPI:
    def _get_pipeline() -> AuditPipeline:
        if not getattr(app.state, "pipeline", None):
            app.state.pipeline = create_pipeline()
        return app.state.pipeline

    @app.on_event("shutdown")
    def _shutdown() -> None:  # pragma: no cover - 生命周期
        if pipeline := getattr(app.state, "pipeline", None):
            pipeline.shutdown()

    @app.post("/audit/events")
    def ingest_event(payload: dict[str, Any]):
        pipeline = _get_pipeline()
        result = pipeline.ingest(payload)
        body = {
            "status": result.status.value,
            "event_id": result.event_id,
            "sequence": result.sequence,
            "reason": result.reason,
        }
        if result.status is IngestStatus.REJECTED:
            return JSONResponse(status_code=422, content=body)
        if result.status is IngestStatus.ACCEPTED and result.reason:
            # 已入库但下游背压：明确告知，而不是默默不投递
            return JSONResponse(status_code=503, content=body)
        return body

    @app.get("/audit/verify")
    def verify_chain():
        return _verification_dict(_get_pipeline().verify())

    @app.post("/audit/retention/run")
    def run_retention():
        return _get_pipeline().enforce_retention()

    @app.get("/audit/alerts")
    def list_alerts(rule_id: str | None = None):
        alerts = _get_pipeline().rules_engine.list_alerts(rule_id)
        return [_alert_dict(a) for a in alerts]

    @app.get("/audit/rejected")
    def list_rejected():
        return [
            {"raw": r.raw, "reason": r.reason, "received_at": r.received_at.isoformat()}
            for r in _get_pipeline().store.list_rejected()
        ]

    @app.get("/dispatch/status")
    def dispatch_status():
        return asdict(_get_pipeline().dispatcher.status())

    @app.get("/dispatch/dead-letter")
    def dispatch_dead_letter():
        return _get_pipeline().dispatcher.list_dead_letter()

    return app
