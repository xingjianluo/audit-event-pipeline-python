"""场景四：下游投递失败——重试上限、死信可查、背压不拖住接入。"""
import time


def _event(eid):
    return {"source": "login", "version": "1", "id": eid,
            "username": "alice", "op": "login", "target": "console",
            "ok": False, "ts": 1780000000}


def test_delivery_failure_goes_dead_letter(pipeline_factory):
    p = pipeline_factory(sink_type="fail", max_retries=2)
    print("\n[输入] sink_type=fail（下游持续不可用），max_retries=2")
    r = p.ingest(_event("D1"))
    print(f"[结果] 接入仍成功(事件已落哈希链): status={r.status.value} seq={r.sequence}")
    assert r.status.value == "accepted"
    time.sleep(0.3)
    status = p.dispatcher.status()
    print(f"[判定依据] 指数退避重试 2 次仍失败 -> dead_letter.jsonl；status={status}")
    assert status.delivered == 0
    assert status.failed == 1
    assert status.dead_letter == 1
    dl = p.dispatcher.list_dead_letter()
    assert dl[0]["event"]["event_id"] == "D1"
    assert "retries" in dl[0]["reason"]
    print(f"[结果] 死信可查询: {dl[0]['reason']}")
    # 事件本身没有丢：链上仍可验证
    assert p.verify().ok and p.verify().records_verified == 1


def test_backpressure_does_not_block_ingest_forever(pipeline_factory):
    # 队列极小 + 极慢下游 + 极短 offer 超时
    p = pipeline_factory(sink_type="null", queue_size=1, timeout_seconds=0.05)

    class SlowSink:
        def deliver(self, event):
            time.sleep(0.5)

    p.dispatcher.sink = SlowSink()

    print("\n[输入] 队列容量1、每条投递耗时0.5s、offer 超时50ms，连续接入5条")
    outcomes = []
    started = time.monotonic()
    for i in range(5):
        r = p.ingest(_event(f"B{i}"))
        outcomes.append((r.status.value, r.reason))
    elapsed = time.monotonic() - started
    print(f"[判定依据] offer 最多阻塞 timeout_seconds，满了立即返回背压信号")
    print(f"[结果] 5 次接入总耗时={elapsed:.2f}s（必须远小于 2.5s）; 结果={outcomes}")
    assert elapsed < 1.0, "接入请求不得被无限期拖住"
    # 全部事件都已记账（accepted 表示已落链；背压只影响投递）
    assert p.verify().records_verified == 5
    rejected_backpressure = [o for o in outcomes if o[1] and "backlog" in o[1]]
    print(f"[结果] 返回背压说明的次数={len(rejected_backpressure)}，这些事件仍在链上并可事后核验")
    assert len(rejected_backpressure) >= 1


def test_file_sink_happy_path(pipeline_factory, tmp_path):
    sink_path = str(tmp_path / "downstream.jsonl")
    p = pipeline_factory(sink_type="file", sink_path=sink_path)
    print("\n[输入] sink_type=file，正常投递3条")
    for i in range(3):
        assert p.ingest(_event(f"F{i}")).status.value == "accepted"
    p.shutdown()
    with open(sink_path, encoding="utf-8") as fh:
        lines = [line for line in fh if line.strip()]
    print(f"[判定依据] 每条入库事件异步追加到下游文件；[结果] 投递行数={len(lines)}")
    assert len(lines) == 3
