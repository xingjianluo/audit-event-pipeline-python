"""场景二：数据被篡改、截断、换序后必须定位问题；合法清理后结论必须明确。"""
import json
from datetime import timedelta

from audit_pipeline.normalize import utcnow
from audit_pipeline.models import NormalizedEvent
from tests.conftest import default_rules


def make_event(eid, sequence, days_ago=0):
    ts = utcnow() - timedelta(days=days_ago)
    return NormalizedEvent(
        event_id=eid, source="login", source_version="login/1", schema_version="audit/1",
        event_type="authentication", actor="alice", action="login", resource="console",
        result="failure", occurred_at=ts, ingested_at=ts)


def seed(pipeline, n, days_ago_fn=lambda i: 0):
    for i in range(1, n + 1):
        seq = pipeline.store.append(make_event(f"e{i}", i, days_ago_fn(i)))
        pipeline.dedup.seen(f"e{i}")
    return seq


def test_tampered_content_detected(pipeline_factory):
    p = pipeline_factory(rules=default_rules())
    seed(p, 5)
    seg = sorted(p.store.segments_dir.glob("*.jsonl"))[0]
    lines = seg.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["actor"] = "mallory"  # 改动内容但保留 record_hash
    lines[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    seg.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = p.verify()
    print("\n[输入] 篡改 segments 第2行 actor -> mallory")
    print(f"[判定依据] 重算 sha256(prev_hash+canonical body) 与自带 record_hash 比对")
    kinds = [(i.kind, i.location) for i in result.issues]
    print(f"[结果] ok={result.ok} 定位={kinds}")
    assert not result.ok
    assert result.issues[0].kind == "tampered"
    assert result.issues[0].location.endswith("#L2")


def test_reorder_detected(pipeline_factory):
    p = pipeline_factory(rules=default_rules())
    seed(p, 5)
    seg = sorted(p.store.segments_dir.glob("*.jsonl"))[0]
    lines = seg.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    seg.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = p.verify()
    print("\n[输入] 调换段文件第1、2行顺序（记录本身未改）")
    print("[判定依据] 按磁盘行序检查 prev_hash 是否等于上一物理行 record_hash")
    print(f"[结果] ok={result.ok} 问题={[i.kind for i in result.issues]}")
    assert not result.ok
    assert any(i.kind == "reordered" for i in result.issues)


def test_middle_deletion_detected(pipeline_factory):
    p = pipeline_factory(rules=default_rules())
    seed(p, 6)
    seg = sorted(p.store.segments_dir.glob("*.jsonl"))[0]
    lines = seg.read_text(encoding="utf-8").splitlines()
    del lines[2]  # 删除 seq=3
    seg.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = p.verify()
    print("\n[输入] 删除中段 seq=3")
    print("[判定依据] sequence 必须连续 + prev_hash 必须相接，tail.log 指向链尾")
    print(f"[结果] ok={result.ok} 问题位置={[(i.kind, i.location) for i in result.issues]}")
    assert not result.ok
    assert any(i.kind == "missing" for i in result.issues)


def test_tail_truncation_detected(pipeline_factory):
    p = pipeline_factory(rules=default_rules(), segment_size=2)
    seed(p, 6)
    last_seg = sorted(p.store.segments_dir.glob("*.jsonl"))[-1]
    lines = last_seg.read_text(encoding="utf-8").splitlines()
    last_seg.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")  # 截掉最后一条

    result = p.verify()
    print("\n[输入] 截掉最后一条记录（tail.log 未动）")
    print("[判定依据] 链尾 sequence/hash 必须与 tail.log 一致")
    print(f"[结果] ok={result.ok} 详情={[i.detail for i in result.issues]}")
    assert not result.ok
    assert any("tail truncation" in i.detail for i in result.issues)


def test_segment_file_deleted_detected(pipeline_factory):
    p = pipeline_factory(rules=default_rules(), segment_size=2)
    seed(p, 6)
    sorted(p.store.segments_dir.glob("*.jsonl"))[-1].unlink()  # 删整个尾段

    result = p.verify()
    print("\n[输入] 删除最后一个段文件")
    print(f"[结果] ok={result.ok} 已验证记录={result.records_verified}")
    assert not result.ok


def test_clean_cut_remains_verifiable_and_marked_incomplete(pipeline_factory):
    p = pipeline_factory(rules=default_rules(), segment_size=3, max_age_days=2)
    # 前 7 条是 5~9 天前的旧数据，后 3 条是新数据
    seed(p, 10, days_ago_fn=lambda i: max(0, 10 - i))

    before = p.verify()
    print(f"\n[输入] 清理前 {before.records_verified} 条，complete={before.complete}")
    assert before.ok and before.complete

    cut = p.enforce_retention()
    print(f"[判定依据] enforce_retention(max_age_days=2) -> cut={cut}")
    after = p.verify()
    print(f"[结果] ok={after.ok} complete={after.complete}（清理后必须明确标记为不完整全量）"
          f" 剩余={after.records_verified} first_seq={after.first_sequence}")
    print(f"[结果] cuts={[c['reason'] for c in after.cuts]}")
    assert after.ok, "合法清理后剩余数据必须仍然校验通过"
    assert after.complete is False, "清理过的数据不能被误判为完整无缺"
    assert len(after.cuts) == 1
    assert after.first_sequence == cut["new_first_seq"]

    # 清理后再追加新记录，链仍然成立（新记录续接幸存链尾）
    p.store.append(make_event("e11", 11))
    reopened = p.verify()
    assert reopened.ok and not reopened.complete
    print(f"[结果] 清理后追加新记录仍可校验: ok={reopened.ok}, records={reopened.records_verified}")


def test_capacity_retention_crossing_segments(pipeline_factory):
    p = pipeline_factory(rules=default_rules(), segment_size=3, max_records=4)
    seed(p, 10)
    cut = p.enforce_retention()
    print(f"\n[输入] 容量上限 4 条，共 10 条，跨多个段文件；cut={cut}")
    result = p.verify()
    on_disk = [e.sequence for e in p.store.iter_events()]
    print(f"[结果] ok={result.ok} complete={result.complete} 剩余序列={on_disk}")
    assert result.ok and not result.complete
    assert on_disk == [7, 8, 9, 10]
    assert cut["removed"] == 6
