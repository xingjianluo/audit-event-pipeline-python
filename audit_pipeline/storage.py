"""只追加哈希链存储、完整性校验、保留清理。

磁盘布局（data_dir 下）：
- segments/000001.jsonl ... 事件段文件，每行一条事件的规范 JSON，
  额外带 sequence / prev_hash / record_hash；
  record_hash = sha256(prev_hash + 规范序列化后的事件体)，按磁盘行序首尾相扣成链。
- chain.log   锚点链：genesis 与每次保留清理(cut) 各一行，自身同样逐行哈希相扣；
              cut 记录“删到了哪里、新链头应是谁”，使合法截断与人为篡改可区分。
- tail.log    当前链尾：最后一条记录的 sequence 与 record_hash（原子覆盖写）。
              用于发现“截掉链尾/删掉最后一个段文件”这类删除。
- rejected.jsonl  校验未通过、拒绝入库的原始事件及拒绝原因（不静默丢弃）。

完整性语义：
- 从未清理过：verify() 给出 complete=True 的全链结论；
- 清理过后：complete=False，但只要剩余记录与最近 cut 锚点、tail.log 都吻合，
  结论依旧明确——剩余部分完整、此前数据已按保留策略移除（cuts 列出依据）；
- 任何改动(tampered)、中间删除(missing)、调换顺序(reordered)、文件损坏(corrupt_file)
  都会定位到具体文件:行号。
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import NormalizedEvent, RejectedEvent, VerificationIssue, VerificationResult

GENESIS_KIND = "genesis"
CUT_KIND = "cut"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def event_body(event: NormalizedEvent, sequence: int) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "source": event.source,
        "source_version": event.source_version,
        "schema_version": event.schema_version,
        "event_type": event.event_type,
        "actor": event.actor,
        "action": event.action,
        "resource": event.resource,
        "result": event.result,
        "occurred_at": _iso(event.occurred_at),
        "ingested_at": _iso(event.ingested_at),
        "sequence": sequence,
        "approval_id": event.approval_id,
        "metadata": event.metadata,
    }


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def chain_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode())
    digest.update(canonical_json(payload).encode())
    return digest.hexdigest()


class EventStore:
    def __init__(self, data_dir: str, segment_size: int = 1000) -> None:
        self.data_dir = Path(data_dir)
        self.segments_dir = self.data_dir / "segments"
        self.segments_dir.mkdir(parents=True, exist_ok=True)
        self.segment_size = max(1, segment_size)
        self.chain_path = self.data_dir / "chain.log"
        self.tail_path = self.data_dir / "tail.log"
        self.rejected_path = self.data_dir / "rejected.jsonl"
        self._lock = threading.RLock()
        self._anchor = self._init_anchor()
        self._sequence, self._tail_hash = self._load_tail()
        self._seg_no, self._seg_count = self._open_segment()

    # ---------------------------------------------------------------- 初始化

    def _init_anchor(self) -> dict[str, Any]:
        if self.chain_path.exists():
            return self._read_chain()[-1]
        payload = {"kind": GENESIS_KIND, "created_at": _iso(_utcnow()), "nonce": secrets.token_hex(16)}
        genesis = {"prev_hash": "", **payload, "chain_hash": chain_hash("", payload)}
        self._append_chain_line(genesis)
        return genesis

    def _read_chain(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for line in self.chain_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return entries

    def _append_chain_line(self, entry: dict[str, Any]) -> None:
        with self.chain_path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _write_tail(self, sequence: int, tail_hash: str) -> None:
        tmp = self.tail_path.with_suffix(".log.tmp")
        tmp.write_text(
            canonical_json({"sequence": sequence, "tail_hash": tail_hash}) + "\n", encoding="utf-8"
        )
        os.replace(tmp, self.tail_path)

    def _load_tail(self) -> tuple[int, str]:
        if self.tail_path.exists():
            obj = json.loads(self.tail_path.read_text(encoding="utf-8"))
            return int(obj["sequence"]), str(obj["tail_hash"])
        # 全新库或从 cut 后尚未写入：链尾锚点是 cut 所记的最后一条被删记录哈希
        if self._anchor["kind"] == CUT_KIND:
            return self._anchor["removed_last_seq"], self._anchor["last_removed_hash"]
        return 0, self._anchor["chain_hash"]

    def _segment_path(self, seg_no: int) -> Path:
        return self.segments_dir / f"{seg_no:06d}.jsonl"

    def _open_segment(self) -> tuple[int, int]:
        files = sorted(self.segments_dir.glob("*.jsonl"))
        if not files:
            # 新记录应落在哪个段：按当前 sequence 推算，保证段号连续
            seg_no = (self._sequence // self.segment_size) + 1
            return seg_no, 0
        last = files[-1]
        seg_no = int(last.stem)
        count = sum(1 for line in last.read_text(encoding="utf-8").splitlines() if line.strip())
        return seg_no, count

    # ------------------------------------------------------------------ 写入

    def append(self, event: NormalizedEvent) -> int:
        """把归一化事件追加进哈希链，返回全局单调递增的 sequence。"""
        with self._lock:
            sequence = self._sequence + 1
            body = event_body(event, sequence)
            prev_hash = self._tail_hash
            record_hash = chain_hash(prev_hash, body)
            record = {**body, "prev_hash": prev_hash, "record_hash": record_hash}
            path = self._segment_path(self._seg_no)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(canonical_json(record) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._sequence = sequence
            self._tail_hash = record_hash
            self._write_tail(sequence, record_hash)
            self._seg_count += 1
            if self._seg_count >= self.segment_size:
                self._seg_no += 1
                self._seg_count = 0
            return sequence

    def record_rejected(self, raw: dict[str, Any], reason: str) -> None:
        line = canonical_json(
            {"raw": raw, "reason": reason, "received_at": _iso(_utcnow())}
        )
        with self._lock:
            with self.rejected_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()

    def list_rejected(self) -> list[RejectedEvent]:
        if not self.rejected_path.exists():
            return []
        out: list[RejectedEvent] = []
        for line in self.rejected_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            out.append(
                RejectedEvent(
                    raw=obj["raw"],
                    reason=obj["reason"],
                    received_at=datetime.fromisoformat(obj["received_at"]),
                )
            )
        return out

    # ---------------------------------------------------------------- 读取/回放

    def iter_events(self) -> Iterator[NormalizedEvent]:
        for rec in self._iter_records():
            yield self._to_event(rec)

    @staticmethod
    def _to_event(rec: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=rec["event_id"],
            source=rec["source"],
            source_version=rec["source_version"],
            schema_version=rec["schema_version"],
            event_type=rec["event_type"],
            actor=rec["actor"],
            action=rec["action"],
            resource=rec["resource"],
            result=rec["result"],
            occurred_at=datetime.fromisoformat(rec["occurred_at"]),
            ingested_at=datetime.fromisoformat(rec["ingested_at"]),
            sequence=rec["sequence"],
            approval_id=rec.get("approval_id"),
            metadata=rec.get("metadata", {}),
        )

    def _iter_records(self) -> Iterator[dict[str, Any]]:
        """按磁盘物理顺序（文件名 + 行号）产出记录。"""
        for path in sorted(self.segments_dir.glob("*.jsonl")):
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)

    def count_records(self) -> int:
        return sum(1 for _ in self._iter_records())

    # -------------------------------------------------------------- 完整性校验

    def verify(self) -> VerificationResult:
        """按磁盘行序重算整条链。

        每条记录同时检查三件事：
        1) 内容哈希是否与自带 record_hash 一致（内容被改动 -> tampered）；
        2) prev_hash 是否等于上一物理行记录的哈希（调换顺序/删头部 -> reordered）；
        3) sequence 是否连续递增（中间删除 -> missing）。
        链头必须与 genesis 或最近一次 cut 锚点吻合；链尾必须与 tail.log 吻合。
        """
        issues: list[VerificationIssue] = []
        cuts: list[dict[str, Any]] = []
        entries = self._verify_anchor_chain(issues, cuts)

        if not self.tail_path.exists():
            issues.append(VerificationIssue("missing", "tail.log", "tail pointer file is absent"))
        tail_seq = self._sequence
        tail_hash = self._tail_hash

        last_cut = cuts[-1] if cuts else None
        if last_cut is not None:
            expected_first_seq: int | None = last_cut["new_first_seq"]
            head_hash = last_cut["last_removed_hash"]
        else:
            genesis = next((e for e in entries if e["kind"] == GENESIS_KIND), None)
            expected_first_seq = 1
            head_hash = genesis["chain_hash"] if genesis else ""

        verified = 0
        expected_prev = head_hash
        expected_seq = expected_first_seq
        first_seq_actual: int | None = None
        last_location = "segments/<empty>"
        last_stored_hash = head_hash
        last_seq: int | None = None

        for location, rec in self._iter_disk_lines(issues):
            seq = rec.get("sequence")
            stored_prev = rec.get("prev_hash")
            stored_hash = rec.get("record_hash")
            if not isinstance(seq, int):
                issues.append(VerificationIssue("corrupt_file", location, "missing integer sequence"))
                continue
            if first_seq_actual is None:
                first_seq_actual = seq
                if expected_first_seq is not None and seq != expected_first_seq:
                    issues.append(
                        VerificationIssue(
                            "missing", location,
                            f"chain head mismatch: expected first sequence {expected_first_seq}, found {seq}",
                            str(expected_first_seq), str(seq),
                        )
                    )
            if stored_prev != expected_prev:
                issues.append(
                    VerificationIssue(
                        "reordered", location,
                        "prev_hash mismatch: record moved/reordered, or predecessor deleted",
                        expected_prev, stored_prev,
                    )
                )
            if expected_seq is not None and seq != expected_seq:
                kind = "missing" if seq > expected_seq else "reordered"
                issues.append(
                    VerificationIssue(
                        kind, location,
                        f"sequence {seq} out of order: expected {expected_seq}",
                        str(expected_seq), str(seq),
                    )
                )

            body = {k: v for k, v in rec.items() if k not in ("prev_hash", "record_hash")}
            recomputed = chain_hash(stored_prev or "", body)
            if stored_hash != recomputed:
                issues.append(
                    VerificationIssue(
                        "tampered", location,
                        f"record hash mismatch for sequence {seq} (event_id={rec.get('event_id')!r})",
                        stored_hash, recomputed,
                    )
                )
            expected_prev = stored_hash if isinstance(stored_hash, str) else expected_prev
            if isinstance(seq, int):
                expected_seq = seq + 1
                last_seq = seq
                last_stored_hash = expected_prev
                last_location = location
            verified += 1

        if verified == 0:
            if last_cut is not None and last_cut["new_first_seq"] is not None:
                issues.append(
                    VerificationIssue(
                        "missing", "segments/",
                        f"cut {last_cut['cut_id']} expects surviving sequence "
                        f"{last_cut['new_first_seq']}, but no records remain",
                    )
                )
            elif last_cut is None and tail_seq > 0:
                issues.append(VerificationIssue("missing", "segments/", "all segment files are empty/missing"))
        else:
            if tail_seq != last_seq:
                issues.append(
                    VerificationIssue(
                        "missing", last_location,
                        f"tail truncation: tail.log expects last sequence {tail_seq}, found {last_seq}",
                        str(tail_seq), str(last_seq),
                    )
                )
            elif tail_hash != last_stored_hash:
                issues.append(
                    VerificationIssue(
                        "tampered", last_location,
                        "tail hash mismatch: tail record differs from tail.log pointer",
                        tail_hash, last_stored_hash,
                    )
                )

        return VerificationResult(
            ok=not issues,
            complete=not cuts,
            records_verified=verified,
            first_sequence=first_seq_actual,
            last_sequence=last_seq if last_seq is not None else 0,
            cuts=cuts,
            issues=issues,
        )

    def _verify_anchor_chain(
        self, issues: list[VerificationIssue], cuts: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if not self.chain_path.exists():
            issues.append(VerificationIssue("missing", "chain.log", "anchor chain file is absent"))
            return []
        entries: list[dict[str, Any]] = []
        prev = ""
        for lineno, line in enumerate(self.chain_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            location = f"chain.log#L{lineno}"
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                issues.append(VerificationIssue("corrupt_file", location, f"invalid JSON: {exc}"))
                return entries
            stored = entry.get("chain_hash")
            payload = {k: v for k, v in entry.items() if k not in ("chain_hash", "prev_hash")}
            if entry.get("prev_hash", "") != prev or chain_hash(entry.get("prev_hash", ""), payload) != stored:
                issues.append(
                    VerificationIssue(
                        "tampered", location, "anchor chain hash mismatch (chain.log altered)",
                        prev, entry.get("prev_hash"),
                    )
                )
            if isinstance(stored, str):
                prev = stored
            entries.append(entry)
            if entry.get("kind") == CUT_KIND:
                cuts.append(entry)
        return entries

    def _iter_disk_lines(self, issues: list[VerificationIssue]) -> Iterator[tuple[str, dict[str, Any]]]:
        """按物理顺序产出 (文件:行号, 记录)；损坏行作为问题上报但继续校验。"""
        for path in sorted(self.segments_dir.glob("*.jsonl")):
            rel = f"segments/{path.name}"
            with path.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    if not line.strip():
                        continue
                    location = f"{rel}#L{lineno}"
                    try:
                        yield location, json.loads(line)
                    except json.JSONDecodeError as exc:
                        issues.append(VerificationIssue("corrupt_file", location, f"invalid JSON: {exc}"))

    # -------------------------------------------------------------- 保留清理

    def enforce_retention(
        self, max_age_days: int | None = None, max_records: int | None = None
    ) -> dict[str, Any]:
        """从链头做前缀截断；每次截断都在 chain.log 留下可校验的 cut 锚点。

        - max_age_days：删除 occurred_at 早于 (now - max_age_days) 的连续链头前缀；
        - max_records：仅保留最新 max_records 条，其余前缀删除；
        两者同时配置时取删除量更大的方案，保证两条约束同时满足。
        其余数据一字不改，因此剩余记录的哈希链对 cut 锚点仍然成立。
        """
        with self._lock:
            saved = list(self._scan_ordered())
            total = len(saved)
            if total == 0:
                return {"removed": 0, "reason": None}

            cut_by_age = 0
            if max_age_days is not None:
                cutoff = _utcnow() - timedelta(days=max_age_days)
                for seq, _, rec in saved:
                    if datetime.fromisoformat(rec["occurred_at"]) < cutoff:
                        cut_by_age += 1
                    else:
                        break
            cut_by_capacity = 0
            if max_records is not None and total > max_records:
                cut_by_capacity = total - max_records

            remove_n = max(cut_by_age, cut_by_capacity, 0)
            if remove_n == 0:
                return {"removed": 0, "reason": None}
            remove_n = min(remove_n, total)

            removed = saved[:remove_n]
            survivors = saved[remove_n:]
            reasons = []
            if cut_by_age:
                reasons.append(f"age>{max_age_days}d")
            if cut_by_capacity:
                reasons.append(f"capacity>{max_records}")

            # 重写段文件：整段被移除的直接删除；有幸存者的段按原样重写（哈希不变）
            surviving_segments: dict[int, list[dict[str, Any]]] = {}
            for _, _, rec in survivors:
                seg_no = (rec["sequence"] - 1) // self.segment_size + 1
                surviving_segments.setdefault(seg_no, []).append(rec)
            keep = {self._segment_path(no) for no in surviving_segments}
            for path in sorted(self.segments_dir.glob("*.jsonl")):
                if path not in keep:
                    path.unlink()
            for seg_no, recs in surviving_segments.items():
                self._segment_path(seg_no).write_text(
                    "".join(canonical_json(rec) + "\n" for rec in sorted(recs, key=lambda r: r["sequence"])),
                    encoding="utf-8",
                )

            last_removed = removed[-1][2]
            cut_payload = {
                "kind": CUT_KIND,
                "cut_id": secrets.token_hex(8),
                "at": _iso(_utcnow()),
                "reason": ",".join(reasons),
                "max_age_days": max_age_days,
                "max_records": max_records,
                "removed_count": remove_n,
                "removed_first_seq": removed[0][0],
                "removed_last_seq": last_removed["sequence"],
                "new_first_seq": survivors[0][2]["sequence"] if survivors else None,
                "last_removed_hash": last_removed["record_hash"],
            }
            cut = {**cut_payload, "prev_hash": self._anchor["chain_hash"]}
            cut["chain_hash"] = chain_hash(cut["prev_hash"], cut_payload)
            self._append_chain_line(cut)
            self._anchor = cut

            if survivors:
                last_rec = survivors[-1][2]
                self._sequence = last_rec["sequence"]
                self._tail_hash = last_rec["record_hash"]
                self._write_tail(self._sequence, self._tail_hash)
                self._seg_no, self._seg_count = self._open_segment()
            else:
                self._sequence = last_removed["sequence"]
                self._tail_hash = last_removed["record_hash"]
                # 全部清空：tail 指向 cut 锚点所记的链尾，下一条记录续接其后
                self._write_tail(self._sequence, self._tail_hash)
                self._seg_no = (self._sequence // self.segment_size) + 1
                self._seg_count = 0

            return {
                "removed": remove_n,
                "reason": cut["reason"],
                "new_first_seq": cut["new_first_seq"],
                "cut_id": cut["cut_id"],
            }

    def _scan_ordered(self) -> list[tuple[int, str, dict[str, Any]]]:
        out: list[tuple[int, str, dict[str, Any]]] = []
        for location, rec in self._iter_disk_lines([]):
            if isinstance(rec.get("sequence"), int):
                out.append((rec["sequence"], location, rec))
        return out
