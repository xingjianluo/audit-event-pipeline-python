"""下游投递：有界队列背压、重试上限、死信落盘。

背压语义：
- 队列有界（queue_size）；接入方 offer() 最多等待 timeout_seconds，
  队列持续满时返回 False（HTTP 层转 503），绝不无限期拖住接入请求。
- 投递失败按指数退避重试最多 max_retries 次；仍失败转入死信文件 dead_letter.jsonl
  并通过 /dispatch/status 暴露计数——不会“既不投递又不告知”。
- 关停时排空队列（限定等待），未处理完的也进死信，保证每条事件去向明确。

sink_type:
- null: 总成功（默认，纯本地跑通用）
- file: 投递即向 sink_path 追加一行 JSON（模拟本地下游）
- fail: 总失败（测试重试/死信用），可设置 fail_times=N 前 N 次失败后恢复（测试重试用）
"""
from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path
from typing import Any

from .config import DispatcherConfig
from .models import DeliveryStatus, NormalizedEvent
from .storage import canonical_json, event_body


class _Sink:
    def deliver(self, event: NormalizedEvent) -> None:
        raise NotImplementedError


class NullSink(_Sink):
    def deliver(self, event: NormalizedEvent) -> None:
        return None


class FileSink(_Sink):
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def deliver(self, event: NormalizedEvent) -> None:
        body = event_body(event, event.sequence)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(body) + "\n")


class FailingSink(_Sink):
    """前 fail_times 次投递抛错；fail_times<0 表示永远失败。"""

    def __init__(self, fail_times: int = -1) -> None:
        self.fail_times = fail_times
        self.attempts = 0
        self._lock = threading.Lock()

    def deliver(self, event: NormalizedEvent) -> None:
        with self._lock:
            self.attempts += 1
            if self.fail_times < 0 or self.attempts <= self.fail_times:
                raise RuntimeError("downstream unavailable")


def build_sink(config: DispatcherConfig) -> _Sink:
    if config.sink_type == "null":
        return NullSink()
    if config.sink_type == "file":
        if not config.sink_path:
            raise ValueError("file sink requires sink_path")
        return FileSink(config.sink_path)
    if config.sink_type == "fail":
        return FailingSink(fail_times=-1)
    raise ValueError(f"unknown sink_type: {config.sink_type}")


class EventDispatcher:
    def __init__(self, config: DispatcherConfig, data_dir: str) -> None:
        self.config = config
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.dead_letter_path = self.data_dir / "dead_letter.jsonl"
        self.sink = build_sink(config)
        self._queue: queue.Queue[NormalizedEvent | None] = queue.Queue(maxsize=max(1, config.queue_size))
        self._counters_lock = threading.Lock()
        self._delivered = 0
        self._failed = 0
        self._dead = 0
        self._worker: threading.Thread | None = None
        self._stopping = threading.Event()
        # 恢复此前落盘死信计数
        if self.dead_letter_path.exists():
            self._dead = sum(1 for line in self.dead_letter_path.read_text(encoding="utf-8").splitlines()
                             if line.strip())

    # ------------------------------------------------------------ 生命周期

    def start(self) -> None:
        if self._worker is not None:
            return
        self._worker = threading.Thread(target=self._run, name="audit-dispatcher", daemon=True)
        self._worker.start()

    def stop(self, drain_timeout: float = 5.0) -> None:
        if self._worker is None:
            return
        self._stopping.set()
        deadline = time.monotonic() + drain_timeout
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        while time.monotonic() < deadline:
            if self._queue.empty():
                break
            time.sleep(0.02)
        # 排空剩余项到死信，保证不静默丢失
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is not None:
                self._to_dead_letter(item, "dispatcher shutting down with undelivered event")
        if self._worker is not None:
            self._worker.join(timeout=2.0)
            self._worker = None

    # ---------------------------------------------------------------- 接入

    def offer(self, event: NormalizedEvent, timeout: float | None = None) -> bool:
        """有界入队。超时仍满则返回 False（调用方应明确告知上游 503，不阻塞更久）。"""
        timeout = self.config.timeout_seconds if timeout is None else timeout
        try:
            self._queue.put(event, block=True, timeout=timeout)
            return True
        except queue.Full:
            return False

    def status(self) -> DeliveryStatus:
        with self._counters_lock:
            return DeliveryStatus(
                delivered=self._delivered,
                pending=self._queue.qsize(),
                failed=self._failed,
                dead_letter=self._dead,
            )

    def list_dead_letter(self) -> list[dict[str, Any]]:
        if not self.dead_letter_path.exists():
            return []
        return [json.loads(line) for line in self.dead_letter_path.read_text(encoding="utf-8").splitlines()
                if line.strip()]

    # ---------------------------------------------------------------- 工作线程

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.1)
            except queue.Empty:
                if self._stopping.is_set():
                    continue
                continue
            if item is None:
                return
            self._deliver_with_retry(item)

    def _deliver_with_retry(self, event: NormalizedEvent) -> None:
        attempt = 0
        while True:
            attempt += 1
            try:
                self.sink.deliver(event)
                with self._counters_lock:
                    self._delivered += 1
                return
            except Exception as exc:  # 下游不可用：重试
                if attempt > self.config.max_retries:
                    with self._counters_lock:
                        self._failed += 1
                    self._to_dead_letter(
                        event,
                        f"delivery failed after {self.config.max_retries} retries: {exc!r}",
                    )
                    return
                delay = self.config.base_delay_seconds * (2 ** (attempt - 1))
                time.sleep(delay)

    def _to_dead_letter(self, event: NormalizedEvent, reason: str) -> None:
        record = {
            "event": event_body(event, event.sequence),
            "reason": reason,
            "moved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with self.dead_letter_path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(record) + "\n")
        with self._counters_lock:
            self._dead += 1
