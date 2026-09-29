# audit-event-pipeline（审计事件采集、留存与合规检查）

在原有 FastAPI 服务基础上新增的一套**本地运行、无任何外部服务依赖**的审计事件管道：

- 多来源/多版本事件接入并统一成一致的记录格式；
- 缺失字段、时间异常、版本不兼容的事件**不静默丢弃**（单独留痕可查）；
- 同一事件重复上报（含高并发）**只记一笔账**（哈希链 + 幂等键）；
- 留存数据具备可验证的**哈希链完整性**，可指出被篡改/删除/乱序的具体位置；
- 按保留期或容量清理后，对剩余数据的校验结论**明确区分**“完整无缺”与“清理后成立”；
- 声明式合规规则（失败阈值窗、敏感操作审批），命中即产出**可查询告警**；
- 下游投递有**有界队列背压**与**重试上限**，既不无限拖住接入，也不静默丢消息（死信可查）。

原有 `GET /` 健康端点保持不变。

---

## 1. 快速开始

```bash
uv sync                      # 安装依赖（fastapi + pytest）
uv run pytest -s             # 运行全部测试（-s 打印每个用例的输入/判定依据/结果）
uv run python main.py        # 启动服务，默认 http://127.0.0.1:8000
```

使用规则配置与文件数据库启动：

```bash
AUDIT_CONFIG_PATH=examples/rules.json \
AUDIT_DB_PATH=data/audit.db \
uv run python main.py
```

环境变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `AUDIT_DB_PATH` | `data/audit.db` | SQLite 文件路径；`:memory:` 为内存库 |
| `AUDIT_CONFIG_PATH` | 空 | 合规规则 JSON 配置；不设则仅用内建默认参数、无规则 |

---

## 2. 统一记录格式与兼容范围

### 2.1 统一记录 `NormalizedEvent`

| 字段 | 含义 |
| --- | --- |
| `event_id` | 稳定标识，`sha256(source + "|" + dedup_key)` 前 32 位，相同输入恒定 |
| `source` / `source_version` | 来源系统与上报的格式版本，如 `gitlab` / `1.0` |
| `event_type` | 统一动作类型（如 `login_failed`、`sensitive_op`） |
| `actor` / `target` | 操作主体 / 操作对象 |
| `event_ts` | 事件发生时间，统一为 **epoch 毫秒（UTC）** |
| `ingest_ts` | 接入时间，epoch 毫秒 |
| `dedup_key` | 幂等键，`source:<来源业务唯一ID>` |
| `approval_ref` | 审批记录引用，无则为 `null` |
| `severity` / `extras` | 级别 / 附加信息（含版本兼容标记） |
| `raw` | 来源原始事件原文，完整留存 |

落库记录 `StoredEvent` 额外携带哈希链字段：`seq`（单调递增位置）、`record_hash`、`prev_hash`。

### 2.2 已登记的来源适配器与版本兼容

| 来源 | 登记版本 | 来源字段 → 统一字段 |
| --- | --- | --- |
| `gitlab` | `1.x` | `action→event_type`、`user→actor`、`object→target`、`timestamp→event_ts`、`event_uuid→dedup`、`approval→approval_ref`、`level→severity` |
| `jenkins` | `2.x` | `eventType→event_type`、`userId→actor`、`resource→target`、`occurredAt→event_ts`、`id→dedup`、`ticket→approval_ref` |

版本兼容规则（`auditpipe/normalize.py`）：

- **主版本不同**（如 `gitlab 2.0`）→ 拒收 `版本不兼容`；
- **来源未登记** → 拒收 `不支持的事件来源`；
- 同主版本、**更高次版本**（如 `1.7`）→ 兼容接入，并在 `extras.forward_compat=true` 标记；
- 必填字段（事件类型、主体、对象、事件时间、来源唯一 ID）缺失或为空 → 拒收；
- 时间无法解析、早于 2000-01-01、或超过 `now + allowed_clock_skew_seconds`（默认 300s）的未来时间 → 拒收 `时间异常`。

> 拒收不是丢弃：拒收事件连同**原因与原文**写入 `rejected` 表，可经
> `GET /api/v1/rejected` 查询，接入响应也返回 `status=rejected` 与 `reason`。

支持的时间字面量：ISO-8601（含 `Z`）、epoch 秒/毫秒（数字或数字串，自动判别）。

---

## 3. 完整性校验与保留清理语义

### 3.1 哈希链

- 创世哈希 `GENESIS_HASH = "0"*64`；
- 每条记录：`record_hash = SHA256(prev_hash || canonical(record))`，
  `canonical` 是对参与哈希字段（含 `seq`、业务字段、`raw_json` 等，键排序、无空白）的确定性 JSON；
- 因此：
  - **改动内容** → 该记录 `hash_mismatch`；
  - **删除记录** → 后继 `broken_link`（prev_hash 断链）；
  - **调换顺序** → `order`（seq 不连续）/ `broken_link`；
  - 校验会扫描整链并报告**全部出错位置**（每条 issue 含 `index=seq`、`kind`、期望值、实际值、说明）。

校验结论 `GET /api/v1/verify` 的 `status`：

| 状态 | 含义 |
| --- | --- |
| `ok` | 链完整，且自初始化以来**没有发生过清理**（完整无缺） |
| `ok_after_prune` | 链对当前存活数据完整，但存在过按策略的清理——**不会被当成完整无缺** |
| `tampered` | 发现篡改 / 删除 / 乱序 / 锚点不符，`issues` 给出定位 |

### 3.2 保留清理（`POST /api/v1/prune`）

- 触发条件：`retention_days`（按事件时间，0 表示不按年龄清理）与
  `retention_max_records`（容量，只保留最新 N 条，0 表示不限），两者取更激进者；
- 清理是**原子事务**：删除旧记录的同时，把“最后被删记录”的 `seq/hash` 与原因、时间写入
  **锚点封包（anchor）**；
- 之后链从 `anchor.tail_seq + 1` 继续，校验仍严格，但结论为 `ok_after_prune`；
- 清理后若存活链头再被截断/删除，或锚点本身被伪造 → `tampered`
  （含 `anchor_mismatch`），不会因为“清过一次”就放松校验。

---

## 4. 合规规则配置

配置文件为 JSON（见 `examples/rules.json`），顶层参数（均可选）：

```json
{
  "max_queue_size": 2000,
  "max_retries": 3,
  "retry_backoff_ms": 50,
  "retention_days": 90,
  "retention_max_records": 100000,
  "allowed_clock_skew_seconds": 300,
  "rules": [ /* 见下 */ ]
}
```

### 规则一：固定时间窗失败次数超标 `failure_threshold`

```json
{
  "rule_id": "login-failure-burst",
  "kind": "failure_threshold",
  "match_event_types": ["login_failed"],
  "match_sources": [],
  "threshold": 5,
  "window_seconds": 300,
  "severity": "high",
  "enabled": true
}
```

同一 `actor` 的匹配事件，在任意 `window_seconds` 滑窗内计数 **`>= threshold`** 即命中
（窗口边界为闭区间：时间差恰好等于窗口仍算同窗）。`evidence` 给出命中的事件
`matched_seqs`、时间窗起止与计数，作为可解释的判定依据。

### 规则二：敏感操作必须有审批 `approval_required`

```json
{
  "rule_id": "sensitive-op-needs-approval",
  "kind": "approval_required",
  "match_event_types": ["sensitive_op", "user_deleted", "permission_granted"],
  "severity": "critical"
}
```

匹配事件且 `approval_ref` 为空 → 逐条告警；有审批单号则放行。

`match_sources` 非空时两类规则都额外要求来源在名单内。告警按
`(rule_id, evidence)` 唯一约束去重，重复评估不会产生重复告警；可通过
`GET /api/v1/alerts` 查询（支持 `?delivered=true|false` 过滤）。配置非法
（缺字段、非法 kind/severity、阈值非正、rule_id 重复等）在加载时即抛 `ConfigError`。

---

## 5. 投递、背压与重试

- 每个**新事件**与其命中产生的**新告警**都会发布到本地投递总线（`auditpipe/delivery.py`）；
- 总线是**有界队列 + 单工作线程**，`sink` 为可注入的本地回调（默认仅内存收集，不访问网络）；
- **背压**：队列满时 `publish` 立即抛 `BackpressureError`，接入响应回传
  `backpressure=true` 与原因——不会无限期阻塞接入；注意事件**本身已落哈希链**，不会“既不投递又不告知”；
- **重试上限**：失败按 `retry_backoff_ms` 退避重试，总尝试次数 = `max_retries + 1`；
  用尽后状态置 `failed` 进入死信，`GET /api/v1/delivery?state=failed` 可查
  （含尝试次数与最后错误），绝不静默丢消息。

---

## 6. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `GET /` | 原有健康端点，保持可用 |
| `POST /api/v1/events?source=&source_version=` | 接入事件（也可在 body 顶层给 source 字段） |
| `GET /api/v1/events?after_seq=&limit=` | 查询统一记录（含哈希链字段） |
| `GET /api/v1/rejected` | 查询被拒收事件（原因 + 原文） |
| `GET /api/v1/alerts?delivered=&limit=` | 查询合规告警与判定依据 |
| `GET /api/v1/delivery?state=` | 查询投递状态（pending/delivered/failed） |
| `GET /api/v1/verify` | 完整性校验结论与逐条问题定位 |
| `POST /api/v1/prune` | 按保留期/容量清理并封锚 |

接入示例：

```bash
curl -s -X POST "http://127.0.0.1:8000/api/v1/events?source=gitlab&source_version=1.0" \
  -H 'Content-Type: application/json' \
  -d '{"action":"login_failed","user":"alice","object":"web",
       "timestamp":"2026-09-30T01:00:00Z","event_uuid":"evt-1"}'
# {"status":"accepted","event_id":"...","deduped":false,"seq":1,"backpressure":false,...}
```

---

## 7. 本地验证方法

```bash
# 全量测试（用例日志打印 输入 -> 判定依据 -> 最终结果）
uv run pytest -s

# 仅看某一类场景
uv run pytest -s tests/test_idempotency.py            # 并发重复接入
uv run pytest -s tests/test_integrity.py             # 篡改/删除/乱序/清理后截断
uv run pytest -s tests/test_rules.py                 # 规则边界命中 + 结论稳定性
uv run pytest -s tests/test_delivery.py              # 投递失败/重试/死信/背压
uv run pytest -s tests/test_config_and_retention.py  # 配置校验 + 保留期/容量清理
```

测试覆盖的关键场景：

1. **并发重复接入**：32 线程重复上报同一事件 → 仅 1 条记录、其余返回 `deduped=true`；
2. **数据被篡改或截断**：改字段、删记录、调换顺序、伪造锚点、清理后再截断，均能检出并定位；
3. **规则边界**：阈值恰好达到（窗含端点）命中、差一次不命中、窗口滑出不命中、
   审批有无的边界；同一批输入两次评估结论完全一致（稳定可解释）；
4. **投递失败**：持续不可用重试到上限进死信、短暂失败重试成功、队列满立即背压且事件仍留存。

代码结构：

```
auditpipe/
  models.py     # 统一记录/留存/校验/告警/配置等数据模型
  normalize.py  # 多来源多版本适配、字段与时间/版本校验
  storage.py    # SQLite：哈希链、拒收、告警、投递、锚点（原子幂等追加）
  integrity.py  # 记录哈希、全链校验、锚点语义
  rules.py      # failure_threshold / approval_required 规则引擎
  delivery.py   # 有界队列、工作线程、重试上限、死信
  config.py     # JSON 声明式配置加载与校验
  service.py    # 编排：接入→规范化→幂等落链→规则→投递；清理
  api.py        # FastAPI 路由
main.py         # 入口（保留 GET /，挂载 /api/v1/*）
examples/rules.json
tests/          # pytest 套件
```
