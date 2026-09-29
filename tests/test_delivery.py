"""下游投递：变慢/不可用时的背压与重试上限；既不拖住接入，也不静默丢失。"""

import threading
import time

from conftest import gitlab_event, log_case
from auditpipe.errors import BackpressureError
from auditpipe.models import PipelineConfig
from auditpipe.service import AuditService


def test_failure_retries_then_dead_letter():
    attempts = {"n": 0}

    def flaky_sink(payload):
        attempts["n"] += 1
        raise RuntimeError("downstream unavailable")

    cfg = PipelineConfig(rules=[], max_queue_size=100, max_retries=3,
                         retry_backoff_ms=1)
    svc = AuditService(":memory:", cfg, sink=flaky_sink)
    svc.start()
    r = svc.ingest(gitlab_event("dl-1"), source="gitlab", source_version="1.0")
    svc.bus.drain(2.0)
    failed = svc.list_delivery(state="failed")
    log_case("下游持续不可用 -> 重试上限 -> 死信可查",
             inputs={"max_retries": 3, "sink": "always fail"},
             basis="尝试次数=max_retries+1；用尽后落 failed 死信",
             result={"total_attempts": attempts["n"],
                     "ingest_status": r.status.value,
                     "dead_letters": [(d["attempts"], d["last_error"][:40])
                                      for d in failed]})
    assert attempts["n"] == 4  # 首次 + 3 次重试
    assert len(failed) == 1
    assert failed[0]["state"] == "failed" and failed[0]["attempts"] == 4
    assert "downstream unavailable" in failed[0]["last_error"]
    svc.close()


def test_retry_then_success():
    calls = {"n": 0}

    def sink(payload):
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("temporary")

    cfg = PipelineConfig(rules=[], max_queue_size=100, max_retries=4,
                         retry_backoff_ms=1)
    svc = AuditService(":memory:", cfg, sink=sink)
    svc.start()
    svc.ingest(gitlab_event("ok-1"), source="gitlab", source_version="1.0")
    svc.bus.drain(2.0)
    delivered = svc.list_delivery(state="delivered")
    log_case("下游短暂失败后恢复 -> 重试成功",
             inputs={"fail_first": 2, "max_retries": 4},
             basis="重试中成功即标记 delivered",
             result={"calls": calls["n"], "delivered": len(delivered)})
    assert calls["n"] == 3
    assert len(delivered) == 1
    svc.close()


def test_backpressure_does_not_block_or_silently_drop():
    gate = threading.Event()

    def slow_sink(payload):
        gate.wait(timeout=3)

    cfg = PipelineConfig(rules=[], max_queue_size=1, max_retries=0,
                         retry_backoff_ms=1)
    svc = AuditService(":memory:", cfg, sink=slow_sink)
    svc.start()
    # 第一条被 worker 取走阻塞；第二条填满容量为 1 的队列
    svc.ingest(gitlab_event("bp-1"), source="gitlab", source_version="1.0")
    time.sleep(0.05)
    svc.ingest(gitlab_event("bp-2"), source="gitlab", source_version="1.0")
    time.sleep(0.05)
    # 第三条必须立即得到背压反馈（不无限等待）
    t0 = time.time()
    r = svc.ingest(gitlab_event("bp-3"), source="gitlab", source_version="1.0")
    elapsed_ms = (time.time() - t0) * 1000
    gate.set()
    log_case("下游变慢、队列满 -> 立即背压且明确告知",
             inputs={"queue_capacity": 1, "inflight": 2},
             basis="queue.put(block=False) 满即抛 BackpressureError；"
                   "ingest 结果回传 backpressure=True",
             result={"elapsed_ms": round(elapsed_ms, 2),
                     "backpressure": r.backpressure,
                     "reason": (r.reason or "")[:60],
                     "event_still_stored": r.seq is not None})
    assert r.backpressure is True
    assert elapsed_ms < 500, "背压必须立即返回，不能无限期拖住接入"
    assert r.seq is not None, "即使投递背压，事件本身仍已落链，不会既不投递又不告知"
    svc.close()


def test_backpressure_exception_on_raw_publish():
    from auditpipe.delivery import DeliveryBus
    # 不启动 worker：容量 1 的队列先占满，第二条必须立即背压抛错
    bus = DeliveryBus(max_queue_size=1, max_retries=0)
    bus.publish({"x": 1}, seq=1, event_id="e1")
    try:
        bus.publish({"x": 2}, seq=2, event_id="e2")
        raised = False
    except BackpressureError:
        raised = True
    log_case("有界队列满 -> publish 立即抛 BackpressureError",
             inputs={"max_queue_size": 1, "enqueued": 2, "worker_started": False},
             basis="queue.put(block=False) 满即抛错，禁止无界等待",
             result={"raised": raised})
    assert raised
