"""并发重复接入：同一条事件被多线程/多次重复上报，只能记一笔账。"""

from concurrent.futures import ThreadPoolExecutor

from conftest import gitlab_event, log_case


def _ingest_one(svc, raw):
    return svc.ingest(raw, source="gitlab", source_version="1.0")


def test_concurrent_duplicate_single_record(service):
    raw = gitlab_event("dup-uuid", minutes_ago=1)
    n_threads = 32
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: _ingest_one(service, dict(raw)),
                                range(n_threads)))

    accepted = [r for r in results if r.status.value == "accepted"]
    firsts = [r for r in accepted if not r.deduped]
    dups = [r for r in accepted if r.deduped]
    events = service.list_events(limit=1000)
    same_id = {r.event_id for r in accepted}

    log_case("32 线程并发重复上报同一事件",
             inputs={"threads": n_threads, "event_uuid": "dup-uuid"},
             basis="append 在 BEGIN IMMEDIATE 事务内查重+取尾+插链",
             result={"total_responses": len(results),
                     "first_inserts": len(firsts),
                     "dedup_hits": len(dups),
                     "stored_records": len(events),
                     "distinct_event_ids": len(same_id)})

    assert len(events) == 1, "重复事件被记成多条"
    assert len(firsts) == 1
    assert len(dups) == n_threads - 1
    assert len(same_id) == 1
    assert results[0].seq == results[-1].seq


def test_sequential_duplicate_same_seq(service):
    raw = gitlab_event("seq-uuid", minutes_ago=1)
    r1 = service.ingest(raw, source="gitlab", source_version="1.0")
    r2 = service.ingest(dict(raw), source="gitlab", source_version="1.0")
    r3 = service.ingest(dict(raw), source="gitlab", source_version="1.0")
    log_case("串行重复上报 3 次",
             inputs={"event_uuid": "seq-uuid", "calls": 3},
             basis="dedup_key=source:event_uuid 唯一",
             result={"seqs": [r1.seq, r2.seq, r3.seq],
                     "deduped": [r1.deduped, r2.deduped, r3.deduped]})
    assert r1.deduped is False
    assert r2.deduped is True and r3.deduped is True
    assert r1.seq == r2.seq == r3.seq


def test_distinct_events_kept(service):
    ra = gitlab_event("a", minutes_ago=3)
    rb = gitlab_event("b", minutes_ago=2)
    service.ingest(ra, source="gitlab", source_version="1.0")
    service.ingest(rb, source="gitlab", source_version="1.0")
    events = service.list_events(limit=1000)
    log_case("不同事件分别记账", inputs=["uuid=a", "uuid=b"],
             basis="dedup_key 不同", result={"stored": len(events)})
    assert len(events) == 2
