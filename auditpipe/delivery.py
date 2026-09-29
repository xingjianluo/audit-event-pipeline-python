"""下游投递：有界队列 + 工作线程 + 重试上限 + 死信可查询（背压保护）。"""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from .errors import BackpressureError
from .models import DeliveryState


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _in_memory_sink(payload: dict) -> None:
    """默认本地 sink：仅收集，不访问任何外部服务。"""
    _in_memory_sink.delivered.append(payload)  # type: ignore[attr-defined]


_in_memory_sink.delivered = []  # type: ignore[attr-defined]


class _Task:
    __slots__ = ("delivery_id", "seq", "event_id", "payload", "enqueued_ts")

    def __init__(self, delivery_id: int, seq: int, event_id: str, payload: dict) -> None:
        self.delivery_id = delivery_id
        self.seq = seq
        self.event_id = event_id
        self.payload = payload
        self.enqueued_ts = _now_ms()


class DeliveryBus:
    def __init__(
        self,
        sink: Callable[[dict], None] | None = None,
        *,
        max_queue_size: int = 1000,
        max_retries: int = 3,
        retry_backoff_ms: int = 50,
        storage=None,
    ) -> None:
        self.sink = sink or _in_memory_sink
        self.max_queue_size = max_queue_size
        self.max_retries = max(0, max_retries)
        self.retry_backoff_ms = retry_backoff_ms
        self.storage = storage
        # 注意：queue.Queue(0) 在标准库里表示"无界"，这里把容量 0 归一化为 1，
        # 保证配置语义（极小容量）不被误解为无界、背压不失效。
        self._q: "queue.Queue[_Task | None]" = queue.Queue(
            maxsize=max(1, max_queue_size)
        )
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        # 仅用于测试/可观测：已尝试结束的投递结果
        self.results: list[dict] = []
        self._results_lock = threading.Lock()

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self._thread is not None:
            return
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._run, name="delivery-worker", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        if self._thread is None:
            return
        self._q.put(None)  # 哨兵：排空后退出
        self._stopping.set()
        self._thread.join(timeout=timeout)
        self._thread = None

    # ---------------------------------------------------------------- publish
    def publish(self, payload: dict, *, seq: int, event_id: str) -> int:
        """入队待投递。队列满时立即抛 BackpressureError（不无限拖住调用方）。

        先在存储里建一条 pending 投递记录（便于可查询），再尝试入队；
        若入队被拒（背压），该记录保持 pending，可经重试/补偿感知。
        """
        delivery_id = -1
        if self.storage is not None:
            rec = self.storage.insert_delivery(seq, event_id, _now_ms())
            delivery_id = rec.delivery_id
        task = _Task(delivery_id, seq, event_id, payload)
        try:
            self._q.put(task, block=False)
        except queue.Full as exc:
            raise BackpressureError(
                f"投递队列已满（容量 {self.max_queue_size}），触发背压拒绝"
            ) from exc
        return delivery_id

    def queue_size(self) -> int:
        return self._q.qsize()

    def _persist(self, task: _Task, state: DeliveryState, attempts: int, err: str | None) -> None:
        if self.storage is None:
            with self._results_lock:
                self.results.append(
                    {"delivery_id": task.delivery_id, "state": state.value,
                     "attempts": attempts, "last_error": err}
                )
            return
        from .models import DeliveryRecord

        self.storage.upsert_delivery(
            DeliveryRecord(
                delivery_id=task.delivery_id if task.delivery_id > 0 else 0,
                seq=task.seq,
                event_id=task.event_id,
                state=state,
                attempts=attempts,
                last_error=err,
                updated_ts=_now_ms(),
            )
        )

    # ---------------------------------------------------------------- worker
    def _run(self) -> None:
        while True:
            task = self._q.get()
            try:
                if task is None:
                    return
                self._deliver_with_retry(task)
            finally:
                self._q.task_done()

    def _deliver_with_retry(self, task: _Task) -> None:
        attempts = 0
        last_error: str | None = None
        # 总尝试次数 = max_retries + 1
        while attempts <= self.max_retries:
            attempts += 1
            try:
                self.sink(task.payload)
                self._persist(task, DeliveryState.DELIVERED, attempts, None)
                return
            except Exception as exc:  # noqa: BLE001  下游异常不可拖垮进程
                last_error = f"{type(exc).__name__}: {exc}"
                if attempts <= self.max_retries:
                    time.sleep(self.retry_backoff_ms / 1000.0)
        # 重试上限用尽：落死信，绝不静默丢弃
        self._persist(task, DeliveryState.FAILED, attempts, last_error)

    def drain(self, timeout: float = 2.0) -> None:
        """等待队列排空（主要供本地验证使用）。"""
        end = time.time() + timeout
        while self._q.unfinished_tasks and time.time() < end:
            time.sleep(0.01)
