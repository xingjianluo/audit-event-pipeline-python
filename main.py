"""服务入口。

- 保留原有的 GET / 健康端点（不破坏已有可用性）。
- 新增 /api/v1/* 审计事件管道能力，全部本地运行（SQLite + 内存队列），
  不依赖任何外部服务。

环境变量：
  AUDIT_DB_PATH     SQLite 文件路径（默认 ./data/audit.db，目录自动创建）
  AUDIT_CONFIG_PATH 合规规则 JSON 配置（可选；缺省仅使用内建默认参数）
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from auditpipe.api import router as audit_router, set_service
from auditpipe.config import load_config
from auditpipe.models import PipelineConfig
from auditpipe.service import AuditService


def _build_service() -> AuditService:
    db_path = os.environ.get("AUDIT_DB_PATH", os.path.join("data", "audit.db"))
    if db_path != ":memory:":
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
    cfg_path = os.environ.get("AUDIT_CONFIG_PATH")
    if cfg_path:
        config = load_config(cfg_path)
    else:
        config = PipelineConfig()
    return AuditService(db_path=db_path, config=config)


@asynccontextmanager
async def lifespan(app: FastAPI):
    service = _build_service()
    service.start()
    set_service(service)
    try:
        yield
    finally:
        service.close()


app = FastAPI(title="audit-event-pipeline", lifespan=lifespan)
app.include_router(audit_router)


@app.get("/")
def read_root():
    return {"Hello": "World", "service": "audit-event-pipeline", "status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
