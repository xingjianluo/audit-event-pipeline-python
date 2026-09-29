"""哈希链完整性：记录哈希、追加链接、全链校验、清理封包（锚点）。

链结构
------
- 创世哈希为 64 个 0（GENESIS_HASH）。
- 每条记录 H_i = SHA256(H_{i-1} || canonical(record_i))。
- 任何对内容的改动 -> 该记录 record_hash 不符；
  删除记录 -> 后一条 prev_hash 断链；调换顺序 -> seq 连续性/prev_hash 异常。

清理语义
--------
按保留期/容量删除旧记录后，在锚点表写入"封包"：被删除尾点的 seq 与其哈希。
之后链从 (anchor.tail_seq + 1) 继续，校验仍严格，但结论为
OK_AFTER_PRUNE（链对存活数据成立，但并非"自初始化以来完整无缺"）。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .models import ChainIssue, StoredEvent, VerifyResult, VerifyStatus

GENESIS_HASH = "0" * 64

# 参与哈希的字段，顺序固定即"链的位置约定"
_HASH_FIELDS = (
    "seq",
    "event_id",
    "source",
    "source_version",
    "event_type",
    "actor",
    "target",
    "event_ts",
    "ingest_ts",
    "dedup_key",
    "approval_ref",
    "severity",
    "extras_json",
    "raw_json",
)


def canonical_payload(ev: StoredEvent) -> str:
    """把记录中参与哈希的字段序列化为确定性字符串。"""
    obj = {name: getattr(ev, name) for name in _HASH_FIELDS}
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_record_hash(prev_hash: str, payload_canonical: str) -> str:
    return hashlib.sha256((prev_hash + payload_canonical).encode("utf-8")).hexdigest()


def hash_record(ev: StoredEvent, prev_hash: str) -> str:
    return compute_record_hash(prev_hash, canonical_payload(ev))


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def verify_chain(events: list[StoredEvent], anchor: dict | None) -> VerifyResult:
    issues: list[ChainIssue] = []

    # 锚点与链头一致性
    expected_prev = GENESIS_HASH
    expected_seq = 1
    if anchor is not None:
        expected_prev = anchor.get("tail_hash", GENESIS_HASH)
        expected_seq = int(anchor.get("tail_seq", 0)) + 1

    prev: StoredEvent | None = None
    for ev in events:
        # 1) 顺序/连续性
        if ev.seq != expected_seq:
            issues.append(
                ChainIssue(
                    index=ev.seq,
                    kind="order",
                    expected=str(expected_seq),
                    actual=str(ev.seq),
                    detail=f"序号不连续或顺序被调换：期望 seq={expected_seq}，实际 seq={ev.seq}",
                )
            )
        # 2) 前链指针
        if ev.prev_hash != expected_prev:
            issues.append(
                ChainIssue(
                    index=ev.seq,
                    kind="broken_link",
                    expected=expected_prev,
                    actual=ev.prev_hash,
                    detail=(
                        f"前链指针不匹配（可能删除了记录）："
                        f"期望指向 {'锚点' if prev is None else f'seq={prev.seq}'} 的哈希"
                    ),
                )
            )
        # 3) 内容哈希
        recomputed = hash_record(ev, ev.prev_hash)
        if recomputed != ev.record_hash:
            issues.append(
                ChainIssue(
                    index=ev.seq,
                    kind="hash_mismatch",
                    expected=recomputed,
                    actual=ev.record_hash,
                    detail="记录内容哈希不匹配（记录被篡改）",
                )
            )

        # 即使发现问题也继续扫描，以指出全部出错位置；
        # expected_prev 以存储值推进（避免一处断裂引发雪崩式误报）
        expected_prev = ev.record_hash
        expected_seq = ev.seq + 1
        prev = ev

    # 锚点本身与存活链头的对应
    if anchor is not None and events:
        head = events[0]
        if head.seq != int(anchor.get("tail_seq", 0)) + 1:
            issues.append(
                ChainIssue(
                    index=head.seq,
                    kind="anchor_mismatch",
                    expected=str(int(anchor.get("tail_seq", 0)) + 1),
                    actual=str(head.seq),
                    detail="存活链头与清理锚点不一致（可能截断了数据或锚点被改）",
                )
            )

    if issues:
        status = VerifyStatus.TAMPERED
    elif anchor is not None:
        status = VerifyStatus.OK_AFTER_PRUNE
    else:
        status = VerifyStatus.OK

    return VerifyResult(
        status=status,
        total_records=len(events),
        issues=issues,
        pruned=anchor is not None,
        head_seq=events[0].seq if events else None,
        tail_seq=events[-1].seq if events else None,
        checked_at=_now_ms(),
    )
