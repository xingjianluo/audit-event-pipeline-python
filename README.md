# 审计事件采集、留存与合规检查管线

在原有 FastAPI 服务（`GET /` 返回 `{"Hello": "World"}`，保持不变）之上，增加一套
**完全本地运行、不依赖任何外部服务**的审计事件能力：

1. 多来源/多版本事件接入，归一化为统一记录格式；坏事件显式拒绝不静默丢弃；同一事件重复上报只记账一次。
2. 哈希链只追加存储，任何改动、删除、调换顺序都能被校验出来并定位到 `文件:行号`；按保留期/容量合法清理后，
   剩余数据仍可校验，且结论明确标记为“全量不完整、剩余部分完好”。
3. 配置声明式合规规则（时间窗失败阈值、敏感操作审批），命中产出可查询告警。
4. 下游异步投递带背压、重试上限与死信：不会无限拖住接入，也不会“既不投递又不告知”。

## 一、统一记录格式与兼容范围

归一化后的每条记录（schema_version = `audit/1`）字段：

| 字段 | 含义 |
| --- | --- |
| `event_id` | 来源事件唯一 ID（幂等键，字符串或整数） |
| `source` / `source_version` | 归一化后的来源名 / 实际接入的来源版本 |
| `schema_version` | 统一格式版本，当前 `audit/1` |
| `event_type` / `actor` / `action` / `resource` | 事件类型、主体、动作、资源 |
| `result` | 规范结果，仅 `success` / `failure` / `denied`（`ok`、`OK`、`failed` 等别名会被映射） |
| `occurred_at` / `ingested_at` | 事件发生时间 / 入库时间，统一为 UTC ISO8601 |
| `sequence` | 入库时分配的全局单调递增序号 |
| `approval_id` | 审批单号，无则为 `null` |
| `metadata` | 来源附加字段（对象） |

内置适配器（**主版本号**兼容；不同主版本视为不兼容，显式拒绝）：

- `audit/1.x`：规范格式直传，`occurred_at` 为 ISO8601（支持结尾 `Z`）。
- `login/1.x`：登录服务旧格式 `id/username/op/target/ok(bool)/ts(Unix 秒)`，
  归一化为 `authentication` 事件，`ok` 映射为 success/failure。
- `payment/2.x`：支付服务格式 `event_id/actor(对象取 id)/action/resource/result/occurred_at/approval_ref`，
  `approval_ref` 映射为 `approval_id`。

时间字段容忍 ISO8601、Unix 秒、Unix 毫秒。校验规则（不通过即拒绝，原样写入 `rejected.jsonl`）：

- 缺失必填字段（event_id、source、version、主体/动作/资源/结果/时间等）；
- 时间无法解析、早于 2000 年、或比当前时间超前超过 24 小时；
- 来源未知或主版本不兼容；
- `result` 无法映射到三个规范值。

新增来源：在 `audit_pipeline/normalize.py` 的 `_ADAPTERS` 注册 `(source, 主版本)` 适配器。

## 二、完整性校验与保留清理语义

磁盘布局（默认 `data/audit/`，可用配置 `data_dir` 或 `AUDIT_CONFIG` 指向配置文件修改）：

```
segments/000001.jsonl ...  事件段（segment_size 行滚动一个文件），每行 = 事件体 + sequence + prev_hash + record_hash
chain.log                  锚点链：1 行 genesis + 每次保留清理 1 行 cut，自身逐行哈希相扣
tail.log                   当前链尾指针（最后一条记录的 sequence/hash，原子覆盖写）
rejected.jsonl             被拒绝入库的原始事件 + 拒绝原因
alerts.jsonl               告警（更新以追加新版本行留痕，查询时折叠为最新）
dedup-ids.txt              幂等去重索引
dispatch/dead_letter.jsonl 投递重试耗尽或关停时未送达的事件
```

哈希链：

```
record_hash(n) = sha256( prev_hash(n) || canonical_json(事件体) )
prev_hash(1)   = genesis 的 chain_hash
prev_hash(n)   = record_hash(n-1)     # 按磁盘物理行序
```

`GET /audit/verify`（或 `EventStore.verify()`）按**磁盘物理顺序**重算每条记录，检查：

1. 内容哈希与自带 `record_hash` 一致 —— 改动内容报 `tampered`；
2. `prev_hash` 等于上一物理行哈希 —— 调换顺序/头部删除报 `reordered`；
3. `sequence` 连续递增 —— 中间删除报 `missing`，坏行报 `corrupt_file`；
4. 链头锚定 genesis 或最近一次 cut；链尾必须与 `tail.log` 一致 —— 截掉链尾/删尾段报 `missing`。

每条问题都给出 `location`（如 `segments/000001.jsonl#L13`）与 expected/actual，可直接定位。

保留清理（`POST /audit/retention/run` 或 `enforce_retention`）：

- 只允许从**链头做前缀截断**：`max_age_days` 按 `occurred_at` 删除过旧前缀，
  `max_records` 只保留最新 N 条；两者同时配置时取删除量更大者，保证两条约束都满足。
- 每次清理在 `chain.log` 追加一条可校验的 `cut` 记录（删除区间、原因、被删最后一条的哈希、
  新链头序号）。其余记录一字不改，因此剩余记录的哈希链对 cut 锚点仍然成立。
- 清理后 `verify()` 返回 `ok=true, complete=false` 并在 `cuts` 中给出清理依据——
  **明确区分“合法清理过”与“被人动过”**，绝不会把清理过的库说成完整无缺。

## 三、合规规则配置

配置文件格式见 `scripts/config.example.json`，两类规则：

```json
{
  "rule_id": "LOGIN_FAILURE_5_5M",
  "rule_type": "failure_threshold",
  "description": "5分钟内登录失败达到5次",
  "severity": "warning",
  "window_seconds": 300,
  "threshold": 5,
  "match_source": "login",
  "match_action": null,
  "match_result": "failure"
}
```

- `failure_threshold`：滑动时间窗（秒，边界为**闭区间**，恰好在 `now-window` 的事件计入）内，
  同时满足 match_source/match_action/match_result（null 表示不限）的事件计数达到 threshold 即开告警；
  同窗口内持续命中只更新该告警（event_ids、count），窗口滑过阈值后去抖锁解除，再次穿越才新开告警。
- `approval_required`：`actions` 列出的敏感动作若 `approval_id` 为空，每条事件各产一条 `critical` 告警。

告警通过 `GET /audit/alerts?rule_id=...` 查询，含消息、命中的 event_ids、判定参数与时间。

## 四、下游投递、背压与重试

- 接入与投递解耦：事件先落哈希链（已持久化），再放入**有界队列**异步投递。
- `sink_type`：`null`（默认，恒成功）、`file`（追加到本地 `sink_path`）、`fail`（恒失败，演练用）。
- 队列满时 `offer` 最多等待 `timeout_seconds`，仍满则 HTTP 返回 **503** 并在 `reason` 中说明
  “已存储、下游积压”——接入请求不会被无限期拖住，事件也不丢（已在链上）。
- 失败按 `base_delay_seconds × 2^(n-1)` 退避重试，最多 `max_retries` 次；
  仍失败写入 `dispatch/dead_letter.jsonl`，并计入 `GET /dispatch/status` 与
  `GET /dispatch/dead-letter`。关停时未送达的队列项同样进死信。

## 五、HTTP 接口

| 方法路径 | 说明 |
| --- | --- |
| `GET /` | 原有服务，保持 `{"Hello": "World"}` |
| `POST /audit/events` | 上报单条来源事件；200 accepted / 200 duplicate / 422 rejected / 503 背压（已入库） |
| `GET /audit/verify` | 完整性校验结论（ok/complete/记录数/问题定位/cuts） |
| `POST /audit/retention/run` | 按配置执行一次保留清理 |
| `GET /audit/alerts` | 查询告警（可按 rule_id 过滤） |
| `GET /audit/rejected` | 查询被拒绝事件与原因 |
| `GET /dispatch/status` | delivered/pending/failed/dead_letter 计数 |
| `GET /dispatch/dead-letter` | 死信明细 |

## 六、本地验证方法

要求 Python ≥ 3.14、uv（全部组件仅用标准库 + FastAPI/httpx，无外部服务）。

```bash
# 1) 全量自动化测试（21 个用例，覆盖并发重复、篡改/截断/换序/合法清理、规则边界、投递失败与背压）
uv run pytest -q -s          # -s 可查看每个用例打印的输入、判定依据与最终结果

# 2) 端到端本地演示（接入/去重/拒绝/规则告警/篡改校验，产物在 data/audit_demo/）
uv run python scripts/local_demo.py

# 3) 启动 HTTP 服务后手工验证
uv run uvicorn main:app --host 127.0.0.1 --port 8000
curl -s localhost:8000/                                    # 原有服务不受影响
curl -s -X POST localhost:8000/audit/events -H 'Content-Type: application/json' \
  -d '{"source":"login","version":"1.0","id":"t1","username":"alice","op":"login","target":"console","ok":false,"ts":1780000000}'
curl -s localhost:8000/audit/verify
```

用自定义配置启动（保留策略/规则/投递均来自 JSON）：

```bash
AUDIT_CONFIG=scripts/config.example.json uv run uvicorn main:app --host 127.0.0.1 --port 8000
```

## 七、目录结构

```
audit_pipeline/
  models.py      统一记录/告警/校验结论等数据类型
  config.py      管线与规则配置（JSON 加载）
  normalize.py   多来源多版本适配器与严格校验
  dedup.py       有界持久化幂等去重
  storage.py     哈希链存储、完整性校验、保留清理
  rules.py       failure_threshold / approval_required 规则引擎
  alerts.py      告警留存与折叠查询
  dispatcher.py  有界队列、退避重试、死信、本地 sink
  pipeline.py    门面：把上述环节串成 ingest/verify/retention
  api.py         FastAPI 路由（create_app / register_audit_routes）
main.py          原服务文件，根路由不变，仅注册审计路由
tests/           pytest 用例（conftest 提供临时目录管线工厂）
scripts/         config.example.json 与 local_demo.py
```

并发与一致性说明：单进程内用锁保证“去重检查→哈希链入库”原子，
sequence 单调、链不会分叉；所有落盘均 flush/fsync，tail 指针原子替换，进程重启后可继续校验与追加。
