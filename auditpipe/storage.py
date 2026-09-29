"""SQLite 持久化层：事件哈希链、拒收记录、告警、投递记录、链锚点。

并发模型：进程内一把锁串行化所有写入；append 走 BEGIN IMMEDIATE 事务，
"查重（幂等）-> 取链尾 -> 算哈希 -> 插入"在同一事务内完成，
因此并发的相同事件只会落一条，绝不记成两笔。
"""

from __future__ import annotations

import json
import sqlite3
import threading

from . import integrity
from .errors import StorageError
from .models import (
    Alert,
    AlertSeverity,
    DeliveryRecord,
    DeliveryState,
    NormalizedEvent,
    RejectedRecord,
    StoredEvent,
)

_EVENT_COLS = (
    "seq, event_id, source, source_version, event_type, actor, target, "
    "event_ts, ingest_ts, dedup_key, approval_ref, severity, extras_json, "
    "raw_json, record_hash, prev_hash"
)


def _dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Storage:
    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    # ------------------------------------------------------------------ schema
    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id       TEXT NOT NULL UNIQUE,
                    source         TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    event_type     TEXT NOT NULL,
                    actor          TEXT NOT NULL,
                    target         TEXT NOT NULL,
                    event_ts       INTEGER NOT NULL,
                    ingest_ts      INTEGER NOT NULL,
                    dedup_key      TEXT NOT NULL UNIQUE,
                    approval_ref   TEXT,
                    severity       TEXT NOT NULL,
                    extras_json    TEXT NOT NULL,
                    raw_json       TEXT NOT NULL,
                    record_hash    TEXT NOT NULL,
                    prev_hash      TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rejected (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    source         TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    reason         TEXT NOT NULL,
                    raw_json       TEXT NOT NULL,
                    ingest_ts      INTEGER NOT NULL,
                    dedup_hint     TEXT
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id     TEXT NOT NULL,
                    rule_kind   TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    message     TEXT NOT NULL,
                    evidence    TEXT NOT NULL,
                    created_ts  INTEGER NOT NULL,
                    delivered   INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(rule_id, evidence)
                );
                CREATE TABLE IF NOT EXISTS delivery (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    seq         INTEGER NOT NULL,
                    event_id    TEXT NOT NULL,
                    state       TEXT NOT NULL,
                    attempts    INTEGER NOT NULL DEFAULT 0,
                    last_error  TEXT,
                    updated_ts  INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS meta_kv (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------- event chain
    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> StoredEvent:
        return StoredEvent(
            seq=row["seq"],
            event_id=row["event_id"],
            source=row["source"],
            source_version=row["source_version"],
            event_type=row["event_type"],
            actor=row["actor"],
            target=row["target"],
            event_ts=row["event_ts"],
            ingest_ts=row["ingest_ts"],
            dedup_key=row["dedup_key"],
            approval_ref=row["approval_ref"],
            severity=row["severity"],
            extras_json=row["extras_json"],
            raw_json=row["raw_json"],
            record_hash=row["record_hash"],
            prev_hash=row["prev_hash"],
        )

    def append_chain(
        self, ev: NormalizedEvent
    ) -> tuple[StoredEvent, bool]:
        """原子地幂等追加。返回 (记录, 是否为重复)。重复时返回已存在记录。"""
        extras_json = _dumps(ev.extras)
        raw_json = _dumps(ev.raw)
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    "SELECT * FROM events WHERE dedup_key=? OR event_id=?",
                    (ev.dedup_key, ev.event_id),
                ).fetchone()
                if row is not None:
                    self._conn.execute("COMMIT")
                    return self._row_to_event(row), True

                tail_row = self._conn.execute(
                    "SELECT record_hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_hash = (
                    tail_row["record_hash"] if tail_row else integrity.GENESIS_HASH
                )
                cur = self._conn.execute(
                    """INSERT INTO events (event_id, source, source_version,
                        event_type, actor, target, event_ts, ingest_ts,
                        dedup_key, approval_ref, severity, extras_json,
                        raw_json, record_hash, prev_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        ev.event_id, ev.source, ev.source_version, ev.event_type,
                        ev.actor, ev.target, ev.event_ts, ev.ingest_ts, ev.dedup_key,
                        ev.approval_ref, ev.severity, extras_json, raw_json,
                        "", prev_hash,
                    ),
                )
                seq = cur.lastrowid
                stored = StoredEvent(
                    seq=seq, event_id=ev.event_id, source=ev.source,
                    source_version=ev.source_version, event_type=ev.event_type,
                    actor=ev.actor, target=ev.target, event_ts=ev.event_ts,
                    ingest_ts=ev.ingest_ts, dedup_key=ev.dedup_key,
                    approval_ref=ev.approval_ref, severity=ev.severity,
                    extras_json=extras_json, raw_json=raw_json,
                    record_hash="", prev_hash=prev_hash,
                )
                record_hash = integrity.hash_record(stored, prev_hash)
                self._conn.execute(
                    "UPDATE events SET record_hash=? WHERE seq=?", (record_hash, seq)
                )
                stored.record_hash = record_hash
                self._conn.execute("COMMIT")
                return stored, False
            except Exception as exc:  # noqa: BLE001
                self._conn.execute("ROLLBACK")
                if isinstance(exc, sqlite3.IntegrityError):
                    # 并发下唯一键竞争：重查返回已有记录
                    row = self._conn.execute(
                        "SELECT * FROM events WHERE dedup_key=? OR event_id=?",
                        (ev.dedup_key, ev.event_id),
                    ).fetchone()
                    if row is not None:
                        return self._row_to_event(row), True
                raise StorageError(f"写入事件失败: {exc}") from exc

    def get_event(self, seq: int) -> StoredEvent | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_EVENT_COLS} FROM events WHERE seq=?", (seq,)
            ).fetchone()
            return self._row_to_event(row) if row else None

    def find_by_dedup(self, dedup_key: str) -> StoredEvent | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_EVENT_COLS} FROM events WHERE dedup_key=?", (dedup_key,)
            ).fetchone()
            return self._row_to_event(row) if row else None

    def list_events(self, after_seq: int = 0, limit: int = 1000) -> list[StoredEvent]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_EVENT_COLS} FROM events WHERE seq>? "
                "ORDER BY seq ASC LIMIT ?",
                (after_seq, limit),
            ).fetchall()
            return [self._row_to_event(r) for r in rows]

    def tail(self) -> StoredEvent | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_EVENT_COLS} FROM events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            return self._row_to_event(row) if row else None

    def count_events(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]

    def min_event_seq(self) -> int | None:
        with self._lock:
            row = self._conn.execute("SELECT MIN(seq) m FROM events").fetchone()
            return row["m"] if row and row["m"] is not None else None

    # -------------------------------------------------------------- rejections
    def insert_rejected(self, rec: RejectedRecord) -> RejectedRecord:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO rejected (source, source_version, reason, raw_json,
                                          ingest_ts, dedup_hint)
                   VALUES (?,?,?,?,?,?)""",
                (rec.source, rec.source_version, rec.reason, rec.raw_json,
                 rec.ingest_ts, rec.dedup_hint),
            )
            rec.reject_id = cur.lastrowid
            return rec

    def list_rejected(self, limit: int = 100) -> list[RejectedRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM rejected ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [
                RejectedRecord(
                    reject_id=r["id"], source=r["source"],
                    source_version=r["source_version"], reason=r["reason"],
                    raw_json=r["raw_json"], ingest_ts=r["ingest_ts"],
                    dedup_hint=r["dedup_hint"],
                )
                for r in rows
            ]

    # ------------------------------------------------------------------ anchor
    def get_anchor(self) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT v FROM meta_kv WHERE k='anchor'"
            ).fetchone()
            return json.loads(row["v"]) if row else None

    def put_anchor(self, anchor: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO meta_kv(k,v) VALUES('anchor',?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (_dumps(anchor),),
            )

    def prune_before(self, seq: int) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM events WHERE seq<?", (seq,))
            return cur.rowcount

    def prune_with_anchor(self, cutoff_seq: int, reason: str, now_ms: int) -> tuple[int, dict | None]:
        """原子地：删除 seq < cutoff_seq 的记录，并以最后被删记录封锚。

        返回 (删除条数, 锚点或None)。无记录可删时返回 (0, None) 且不改锚点。
        与历史锚点合并：新锚点 tail_seq 始终前移，tail_hash 取本次最后被删记录。
        """
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                last = self._conn.execute(
                    "SELECT seq, record_hash FROM events WHERE seq<? "
                    "ORDER BY seq DESC LIMIT 1",
                    (cutoff_seq,),
                ).fetchone()
                if last is None:
                    self._conn.execute("COMMIT")
                    return 0, None
                cur = self._conn.execute(
                    "DELETE FROM events WHERE seq<?", (cutoff_seq,)
                )
                deleted = cur.rowcount
                anchor = {
                    "tail_seq": last["seq"],
                    "tail_hash": last["record_hash"],
                    "reason": reason,
                    "pruned_at": now_ms,
                }
                self._conn.execute(
                    "INSERT INTO meta_kv(k,v) VALUES('anchor',?) "
                    "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (_dumps(anchor),),
                )
                self._conn.execute("COMMIT")
                return deleted, anchor
            except Exception as exc:  # noqa: BLE001
                self._conn.execute("ROLLBACK")
                raise StorageError(f"清理失败: {exc}") from exc

    # ------------------------------------------------------------------ alerts
    def insert_alert(self, alert: Alert) -> Alert | None:
        """插入告警；同一 (rule_id, evidence) 已存在则返回 None（去重）。"""
        with self._lock, self._conn:
            try:
                cur = self._conn.execute(
                    """INSERT INTO alerts (rule_id, rule_kind, severity, message,
                                            evidence, created_ts, delivered)
                       VALUES (?,?,?,?,?,?,0)""",
                    (
                        alert.rule_id, alert.rule_kind, alert.severity.value,
                        alert.message, _dumps(alert.evidence), alert.created_ts,
                    ),
                )
            except sqlite3.IntegrityError:
                return None
            alert.alert_id = cur.lastrowid
            return alert

    def list_alerts(self, delivered: bool | None = None, limit: int = 100) -> list[Alert]:
        sql = "SELECT * FROM alerts"
        params: tuple = ()
        if delivered is not None:
            sql += " WHERE delivered=?"
            params = (1 if delivered else 0,)
        sql += " ORDER BY id DESC LIMIT ?"
        params = params + (limit,)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [
                Alert(
                    alert_id=r["id"], rule_id=r["rule_id"], rule_kind=r["rule_kind"],
                    severity=AlertSeverity(r["severity"]), message=r["message"],
                    evidence=json.loads(r["evidence"]), created_ts=r["created_ts"],
                    delivered=bool(r["delivered"]),
                )
                for r in rows
            ]

    def mark_alert_delivered(self, alert_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE alerts SET delivered=1 WHERE id=?", (alert_id,))

    # ---------------------------------------------------------------- delivery
    def upsert_delivery(self, rec: DeliveryRecord) -> DeliveryRecord:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO delivery (id, seq, event_id, state, attempts,
                                          last_error, updated_ts)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET state=excluded.state,
                     attempts=excluded.attempts, last_error=excluded.last_error,
                     updated_ts=excluded.updated_ts""",
                (rec.delivery_id, rec.seq, rec.event_id, rec.state.value,
                 rec.attempts, rec.last_error, rec.updated_ts),
            )
            return rec

    def insert_delivery(self, seq: int, event_id: str, now_ms: int) -> DeliveryRecord:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO delivery (seq, event_id, state, attempts,
                                          last_error, updated_ts)
                   VALUES (?,?,?,?,?,?)""",
                (seq, event_id, DeliveryState.PENDING.value, 0, None, now_ms),
            )
            return DeliveryRecord(
                delivery_id=cur.lastrowid, seq=seq, event_id=event_id,
                state=DeliveryState.PENDING, attempts=0, last_error=None,
                updated_ts=now_ms,
            )

    def list_delivery(self, state: str | None = None) -> list[DeliveryRecord]:
        sql = "SELECT * FROM delivery"
        params: tuple = ()
        if state is not None:
            sql += " WHERE state=?"
            params = (state,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [
                DeliveryRecord(
                    delivery_id=r["id"], seq=r["seq"], event_id=r["event_id"],
                    state=DeliveryState(r["state"]), attempts=r["attempts"],
                    last_error=r["last_error"], updated_ts=r["updated_ts"],
                )
                for r in rows
            ]
