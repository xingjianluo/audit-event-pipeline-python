"""事件幂等去重。

同一条事件（相同 event_id）重复上报只记账一次：第二次起返回 DUPLICATE。
内存中用 set 判定、deque 维持 FIFO 顺序做容量上界；超过容量（默认十万）淘汰
最旧 ID——被保留策略清理掉的极旧事件若极罕见地重放，会被当作新事件，
这与“保留期之外数据已不在账上”的语义一致。去重索引定期落盘，进程重启后仍幂等。
"""
from __future__ import annotations

import threading
from collections import deque
from pathlib import Path


class Deduplicator:
    def __init__(self, path: str | None = None, capacity: int = 100_000) -> None:
        self._path = Path(path) if path else None
        self.capacity = capacity
        self._seen: set[str] = set()
        self._order: deque[str] = deque()
        self._lock = threading.Lock()
        if self._path and self._path.exists():
            for line in self._path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and line not in self._seen:
                    self._seen.add(line)
                    self._order.append(line)

    def seen(self, event_id: str) -> bool:
        """已见过返回 True；首次见到则登记并返回 False。线程安全。"""
        with self._lock:
            if event_id in self._seen:
                return True
            self._seen.add(event_id)
            self._order.append(event_id)
            while len(self._order) > self.capacity:
                evicted = self._order.popleft()
                self._seen.discard(evicted)
            return False

    def save(self) -> None:
        if self._path is None:
            return
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text("\n".join(self._order) + ("\n" if self._order else ""), encoding="utf-8")
            tmp.replace(self._path)

    def __len__(self) -> int:
        return len(self._seen)
