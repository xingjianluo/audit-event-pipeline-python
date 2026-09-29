"""完整性校验：改动/删除/乱序必须被发现并指出位置；清理后结论必须明确。"""

from conftest import gitlab_event, log_case
from auditpipe.models import VerifyStatus


def _seed(service, uuids):
    for i, u in enumerate(uuids):
        service.ingest(gitlab_event(u, minutes_ago=10 - i),
                       source="gitlab", source_version="1.0")


def _tamper_record(db_path, seq, new_actor):
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE events SET actor=? WHERE seq=?", (new_actor, seq))
    conn.commit()
    conn.close()


def _raw_delete(db_path, seq):
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM events WHERE seq=?", (seq,))
    conn.commit()
    conn.close()


def test_clean_chain_ok(tmp_path, service):
    _seed(service, ["a", "b", "c"])
    r = service.verify()
    log_case("完整链校验", inputs={"records": 3},
             basis="逐条重算 SHA256 并比对 prev_hash 与 seq 连续性",
             result={"status": r.status.value, "issues": len(r.issues)})
    assert r.status == VerifyStatus.OK


def test_tamper_detected_with_location(tmp_path):
    db = str(tmp_path / "t.db")
    from auditpipe.models import PipelineConfig
    from auditpipe.service import AuditService
    svc = AuditService(db, PipelineConfig(rules=[]))
    svc.start()
    _seed(svc, ["a", "b", "c", "d"])
    svc.close()

    _tamper_record(db, seq=2, new_actor="attacker")

    svc = AuditService(db, PipelineConfig(rules=[]))
    r = svc.verify()
    kinds = [(i.index, i.kind) for i in r.issues]
    log_case("篡改第 2 条记录的 actor",
             inputs={"db": "t.db", "tampered_seq": 2, "change": "actor->attacker"},
             basis="重算哈希 != 存储 record_hash",
             result={"status": r.status.value, "issues": kinds})
    assert r.status == VerifyStatus.TAMPERED
    assert (2, "hash_mismatch") in kinds
    svc.close()


def test_delete_detected(service):
    _seed(service, ["a", "b", "c"])
    # 通过存储连接直接物理删除中间记录模拟人为删除
    service.storage._conn.execute("DELETE FROM events WHERE seq=2")
    service.storage._conn.commit()
    r = service.verify()
    kinds = [(i.index, i.kind) for i in r.issues]
    log_case("物理删除第 2 条记录", inputs={"deleted_seq": 2},
             basis="后一条 prev_hash 断裂 / seq 不连续",
             result={"status": r.status.value, "issues": kinds})
    assert r.status == VerifyStatus.TAMPERED
    assert any(k == "broken_link" for _, k in kinds)


def test_swap_order_detected(tmp_path):
    db = str(tmp_path / "s.db")
    from auditpipe.models import PipelineConfig
    from auditpipe.service import AuditService
    svc = AuditService(db, PipelineConfig(rules=[]))
    svc.start()
    _seed(svc, ["a", "b", "c"])
    svc.close()
    # 调换两条记录的 seq（破坏顺序）
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET seq=999 WHERE seq=2")
    conn.execute("UPDATE events SET seq=2 WHERE seq=3")
    conn.execute("UPDATE events SET seq=3 WHERE seq=999")
    conn.commit()
    conn.close()
    svc = AuditService(db, PipelineConfig(rules=[]))
    r = svc.verify()
    log_case("调换第 2/3 条顺序", inputs={"swapped": [2, 3]},
             basis="按 seq 读出后 prev_hash/连续性校验失败",
             result={"status": r.status.value,
                     "issues": [(i.index, i.kind) for i in r.issues]})
    assert r.status == VerifyStatus.TAMPERED
    svc.close()


def test_prune_then_ok_after_prune(service):
    service.config.retention_max_records = 3
    _seed(service, ["a", "b", "c", "d", "e"])
    info = service.prune()
    r = service.verify()
    log_case("按容量清理旧数据后校验",
             inputs={"total": 5, "retention_max_records": 3},
             basis="锚点封包被删尾点；存活链从 anchor.tail_seq+1 续算",
             result={"prune": {k: info[k] for k in ("deleted", "remaining", "pruned")},
                     "status": r.status.value, "head": r.head_seq, "tail": r.tail_seq})
    assert info["deleted"] == 2
    assert r.status == VerifyStatus.OK_AFTER_PRUNE
    assert r.status != VerifyStatus.OK  # 明确区别于"完整无缺"
    assert r.issues == []


def test_truncate_after_prune_detected(service):
    service.config.retention_max_records = 2
    _seed(service, ["a", "b", "c", "d"])
    service.prune()  # 剩 seq=3,4，锚点 tail_seq=2
    # 再人为删掉存活链头 seq=3，只剩 seq=4
    service.storage._conn.execute("DELETE FROM events WHERE seq=3")
    service.storage._conn.commit()
    r = service.verify()
    log_case("清理后又被截断存活链头", inputs={"deleted_after_prune": 3},
             basis="存活链头 seq 必须等于 anchor.tail_seq+1",
             result={"status": r.status.value,
                     "issues": [(i.index, i.kind) for i in r.issues]})
    assert r.status == VerifyStatus.TAMPERED
    assert any(i.kind == "anchor_mismatch" for i in r.issues)


def test_anchor_tamper_detected(service):
    service.config.retention_max_records = 2
    _seed(service, ["a", "b", "c"])
    service.prune()
    anchor = service.storage.get_anchor()
    anchor["tail_hash"] = "f" * 64  # 篡改锚点哈希
    service.storage.put_anchor(anchor)
    r = service.verify()
    log_case("锚点哈希被篡改", inputs={"anchor_forged": True},
             basis="存活链头 prev_hash 与锚点 tail_hash 不一致",
             result={"status": r.status.value,
                     "issues": [(i.index, i.kind) for i in r.issues]})
    assert r.status == VerifyStatus.TAMPERED
