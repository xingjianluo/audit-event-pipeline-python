"""场景一：并发重复接入——同一批输入必须得到稳定且可解释的结论。"""
import threading

from tests.conftest import default_rules


LOGIN_EVENT = {
    "source": "login", "version": "1.0", "id": "DUP-1",
    "username": "alice", "op": "login", "target": "console",
    "ok": False, "ts": 1780000000,
}


def test_concurrent_duplicate_ingested_once(caplog, pipeline_factory):
    pipeline = pipeline_factory(rules=default_rules())
    caplog.set_level("INFO")

    results: list[str] = []
    lock = threading.Lock()

    def worker():
        r = pipeline.ingest(dict(LOGIN_EVENT))
        with lock:
            results.append(r.status.value)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    print("\n[输入] 20 个线程并发上报同一条事件:", LOGIN_EVENT)
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    accepted = [s for s in results if s == "accepted"]
    duplicates = [s for s in results if s == "duplicate"]
    print(f"[判定依据] event_id='DUP-1' 以去重索引(dedup-ids.txt)为幂等键，持锁串行检查")
    print(f"[结果] accepted={len(accepted)} duplicate={len(duplicates)} 全部响应={sorted(results)}")

    assert len(accepted) == 1, f"同一条事件只能记账一次，实际 accepted {len(accepted)}"
    assert len(duplicates) == 19
    verification = pipeline.verify()
    print(f"[结果] 链上记录数={verification.records_verified} 完整性 ok={verification.ok}")
    assert verification.records_verified == 1
    assert verification.ok


def test_concurrent_distinct_events_all_accepted(pipeline_factory):
    pipeline = pipeline_factory(rules=default_rules())

    def make_event(i):
        return {
            "source": "login", "version": "1.0", "id": f"E{i:03d}",
            "username": f"user{i}", "op": "login", "target": "console",
            "ok": True, "ts": 1780000000 + i,
        }

    results: dict[int, str] = {}
    lock = threading.Lock()

    def worker(i):
        r = pipeline.ingest(make_event(i))
        with lock:
            results[i] = r.status.value

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
    print("\n[输入] 40 个不同 event_id 并发上报")
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    accepted = sum(1 for s in results.values() if s == "accepted")
    print(f"[结果] accepted={accepted}/40, sequence 范围=1..{pipeline.store._sequence}")
    assert accepted == 40
    assert pipeline.verify().ok
