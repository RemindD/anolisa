# AgentSecCore SQLite 存储协议

## 1. 状态、范围与权威关系

| 项目 | 内容 |
| --- | --- |
| 协议标识 | `ASC-SQLITE-STORAGE` |
| 文档版本 | `0.1`，Definition Review 草案 |
| 当前实现基线 | `main@9f109d55964cfc5820d41564869f70879a8de21f` 的 Python CLI/daemon |
| 目标 | Rust 重写时合并 securityEvents 与 observability 底层数据结构，支持条件原子更新、本地 SQLite 持久化和旧版本迁移 |
| 适用组件 | security-events、observability、SQLite persistence、state migrator，以及直接消费者 |
| 实现状态 | 本文定义要求，不表示 Rust 存储实现或验收 fixture 已完成 |

本文是可独立评审的数据库存储协议，规定逻辑模型、Repository/Sink 操作、事务、错误、
恢复和验收。它不是新的 RPC 协议，不向客户端开放 SQL 或通用数据库修改接口，也不定义
Policy、Credential、Skill Ledger 等领域的业务状态机。

权威入口仍是 [V2 迁移架构](AGENT_SEC_RUST_MIGRATION_zh.md)。本文不是第七份冻结 V1
事实的行为契约。事件语义遵循 [Security Middleware 契约](SECURITY_MIDDLEWARE_CONTRACT_zh.md)，
查询兼容遵循 [Daemon V1 协议](DAEMON_PROTOCOL_V1_zh.md)，身份、目录和迁移遵循
[进程部署契约](DAEMON_PROCESS_DEPLOYMENT_CONTRACT_zh.md)。Rust crate 边界遵循迁移架构。

标签含义：

- **[CURRENT]**：已核对的 Python 当前事实；不自动成为 V2 内部实现约束。
- **[PRESERVE V1]**：支持 V1 兼容接口期间必须保持的外部语义。
- **[TARGET V2]**：本协议提出的目标；新增设计在 Definition Review 冻结前均为草案。

本任务已经明确：旧版本数据库的迁移逻辑必须在 Rust 中保留；数据写入本地 SQLite 文件；
revision 由调用方管理，数据库在版本条件匹配时原子更新。这些要求不再作为待确认选项。
第 12 节说明开发时需要补齐的实现细节，不要求使用者逐项选择 SQL、索引或参数。

第 3 至 9 节的“必须/不得”是目标实现的验收要求。修改已有对外行为时，需先冻结第 10 节
对应变更记录、更新受影响契约和可执行 fixture，再交付实现。

## 2. [CURRENT] 现有数据库使用方式

### 2.1 数据与操作

| 项目 | securityEvents | observability |
| --- | --- | --- |
| 数据库 | `security-events.db` | `observability.db` |
| 表 | `security_events` | `observability_events` |
| SQLite schema 版本 | 3；v2 增加关联字段，v3 增加并回填 verdict | 1 |
| 主键 | 字符串 `event_id` | 自增整数 `id` |
| 分类 | `event_type`、`category` | `hook` |
| 时间 | UTC `timestamp`、浮点秒 `timestamp_epoch` | 带时区 `observed_at`、浮点秒 `observed_at_epoch` |
| 关联 | trace/session/run/call/tool-call IDs | session/run/call/tool-call IDs |
| 特有内容 | `result`、PID/UID、投影 verdict、JSON details | JSON metadata、JSON metrics |
| 写操作 | 插入、过期删除、schema 迁移回填 | 插入、过期删除 |
| 重复提交 | 相同 event_id 忽略；不核对内容是否相同 | 无提交幂等键，每次新增 |
| 默认保留期 | 30 天 | 7 天 |

两者共用 `SqliteStore`，但每个 Repository 写操作自行开启、提交事务；尚无业务层条件更新
或跨 Repository 的公共事务接口。schema 回填中的 `UPDATE` 不是业务原子更新接口。

### 2.2 双写与调用结果

- security event：先尝试 JSONL，再独立尝试 SQLite；一个失败不阻止另一个，失败不改变
  capability 的业务结果。每次已路由 invocation 至多一条最终安全事件。
- `observability record`：先写 JSONL，再调用 SQLite `write_or_raise`；JSONL 失败会中止
  后续 SQLite 写入；SQLite 失败返回非零，此时 JSONL 可能已经存在。
- SQLite 单次插入在事务内完成；JSONL 与 SQLite 双写之间无原子提交。
- 多数读取路径在数据库不可用或 SQL 异常时返回空集合或零。不能把这种结果解释为已证实
  “没有安全风险”。

### 2.3 连接、维护与恢复

- 写连接使用 WAL、`busy_timeout=200ms`、`synchronous=NORMAL`、`foreign_keys=ON`、
  `wal_autocheckpoint=100`；初始化尝试启用 incremental auto-vacuum。
- 只读连接使用 `mode=ro` 和 `query_only=ON`；不创建缺失 DB、不执行 schema 迁移。
- 写入端尝试设置数据库 `0600`，新建父目录 `0700`；权限设置存在 best-effort 路径。
- writer close 通过每库默认 24 小时一次的维护门控执行 prune 和 WAL checkpoint；
  门控使用文件锁，维护不在每次 insert 时执行。
- 真实损坏按 SQLite 错误码识别，当前恢复删除 DB/WAL/SHM 后重建空索引；删除失败时禁写。
  此恢复路径不回灌历史 JSONL。busy/locked 不按损坏处理。
- security event 并发测试允许锁忙时丢记录，以“落库数 + 丢弃诊断数 = 总数”验收。
  observability 并发读测试不能证明所有并发写都成功。

这些事实说明当前 SQLite 承担可丢弃查询索引的角色；Rust 实现需要按第 6.3 节验证本地
数据保存和重启恢复，不能直接照搬“数据库损坏就删除重建”的行为。

## 3. [TARGET V2] 统一数据模型

### 3.1 存储边界

security event 和 observability record 使用同一 SQLite 数据库、统一事件主表和公共
存储 envelope。两者保留不同的 typed payload 与校验规则；Rust 可使用带类型枚举表达。
不得继续依赖两个独立 ORM schema/version 管理器初始化同一库。

事务、连接、迁移和 SQLite 错误转换由 persistence adapter 统一管理。领域 service 负责
数据校验、状态转换和安全投影；adapter 不决定扫描结论或复制 Action Runtime lifecycle。

同一事务需共同修改的数据必须位于同一数据库。只要求共享事务和模型，不要求把所有领域
对象塞入事件主表；可变业务状态仍采用其领域模型。

### 3.2 事件主表逻辑字段

下表为逻辑模型；物理 DDL、字段类型宽度和索引名称在 Definition Review 冻结。

| 字段 | 要求 |
| --- | --- |
| `record_id` | 稳定记录标识；在调用写入前确定，重试不得重新生成 |
| `owner_principal` | 非空可信 owner，由 daemon 或受控迁移器提供 |
| `kind` | `security` 或 `observability`，必填 |
| `payload_schema_version` | payload 解释版本；与 SQLite schema 版本分离 |
| `occurred_at` | 发生时间的统一索引；保留兼容输出所需的原始时间表示和精度 |
| `session_id` / `run_id` / `call_id` / `tool_call_id` | 公共关联索引；null 与空字符串按源契约处理 |
| `trace_id` / `span_id` | 可空；仅按 payload 版本及领域事件契约解释 |
| `event_name` | security 的 event_type 或 observability 的 hook；必须与 kind 联合解释 |
| `category` | security 分类；observability 无对应值时为 null |
| `execution_result` | security 的 succeeded/failed；不能从风险 verdict 推导 |
| `verdict` | 安全 payload 的查询投影；允许 null，不能将缺失值填成 pass |
| `payload` | 完整、经过领域校验与必要脱敏的 typed JSON payload |

存储标识至少以 `(owner_principal, kind, record_id)` 唯一约束。记录标识不能从 trace、
session、run 或 tool-call ID 推导：这些关联标识允许多个不同事件共享。

历史 SecurityEvent 保留原 event_id；历史 observability 保留整数 id 到新记录的稳定映射，
映射包含 owner、来源库身份和来源表，避免不同用户数据库的整数 id 冲突。V1 timeline
仍按兼容协议输出其整数 id。新 V2 记录如何投影到仍受支持的 V1 整数 id，由实现者按
第 12 节记录映射方案并验证兼容性。

### 3.3 payload 与投影一致性

1. security payload 保留 event_type/category/result、时间、PID/UID、关联字段和 details。
   PID/UID 是审计归因字段，不替代 owner principal。
2. observability payload 保留 hook、observedAt、metadata、metrics；继续按六种 hook
   校验。session/run 必填、tool hook 的 toolCallId 必填；未知字段的忽略规则和 metric
   allowlist 遵循已有 schema，不能因统一 envelope 放宽或收紧。
3. `verdict` 的 V1 投影顺序为字符串 `details.verdict`，其次字符串
   `details.result.verdict`。保留源值；不存在有效字符串时为 null。
4. 执行结果与安全结论分别存储。扫描正常完成且 verdict=deny 时，execution_result
   仍可为 succeeded。`observability report.security_verdicts` 当前按执行结果聚合，
   不能作为 verdict 模型的来源。
5. 缺少事件 schema_version 的历史安全记录按 V1 解释；V1 trace_id 是 opaque correlation。
   V2 安全事件 trace/span 由当前 OTel context 投影，不转换任意 legacy trace 为 OTel ID。
6. payload 和所有冗余索引字段必须在同一事务生成、写入；不得允许调用方分别修改两份值。
7. 合并不合并事实：before/after hook、模型调用、工具调用和关联安全事件仍各自追加记录。
   关联推断不是外键唯一关系，不应据此删除或覆盖原始事件。

### 3.4 查询与索引

- 所有查询、聚合和关联读取必须应用服务端生成的 QueryScope；关联候选也不能跨 owner。
- 保留 security 的类型、分类、执行结果、verdict、关联 ID、时间过滤及分组能力，以及
  observability 的 session/run/timeline 查询。
- 常规时间范围使用 `[since, until)`；关联 fallback 的当前 ±10 秒窗口及其边界独立保留。
- V2 分页顺序必须包括稳定唯一的 tie-breaker；V1 支持的排序与分页输出通过兼容投影验证。
- 需要同一时点一致性的 items、total、分组和两类事件关联查询使用同一读事务快照。
  多次翻页之间的快照持续性不自动保证；cursor/offset 产品规则另按 query contract 定义。
- 热路径使用 owner、kind、时间，以及 session/run、category/verdict 等组合索引；
  索引由真实 query plan 和数据规模验证，不以“存在某索引名”代替性能验收。
- 列表默认投影有界字段，详情按 record ID 单独读取。不能先加载所有大 payload 再限流。

## 4. [TARGET V2] 数据操作协议

以下为语义操作，不固定 Rust trait 签名，也不要求公共 SQL/CRUD endpoint。

| 操作 | 成功结果 | 约束 |
| --- | --- | --- |
| `append` | `Inserted` 或 `AlreadyPresent` | 返回成功前 SQLite commit 完成 |
| `append_batch` | 整批提交结果 | 任一非法记录、内容冲突或写入错误使整批回滚 |
| `get/query/count` | 数据或明确存储错误 | 应用可信 scope，按需共享读快照 |
| `compare_and_update` | 条件满足后的更新结果 | 调用方指定 expected_revision；如需替换 revision，也由调用方指定新值 |
| `atomic` | 事务内全部操作的提交结果 | 同一事务组合追加、条件更新或领域允许的删除 |
| `prune` | 清理结果或明确错误 | 按 kind 的保留期执行，不能误删其它 kind |

### 4.1 追加与重复提交

V2 相同记录键、相同规范化 payload 的重试返回 `AlreadyPresent`，不得增加记录。
相同键但不同 payload 返回 `Conflict`，不得静默忽略或覆盖。规范化依据领域序列化契约，
忽略 JSON object 键序，不忽略字段缺失/null、数组顺序或值差异；精确数值规则需冻结。

这比 V1 SecurityEvent 的 `ON CONFLICT DO NOTHING` 更严格；属于显式版本化差异。
V1 observability 输入没有幂等键，不能通过 payload hash 去重两个内容恰好相同的合法事件。
新的跨请求幂等能力必须具有稳定 producer/request ID；不能由一次 server 调用随机生成的
ID 声称已经解决响应丢失后的重试问题。

幂等保证的有效期必须明确。prune 删除记录后，不承诺仍能识别其重试；需要更长保证时，
由具体消费者定义独立保留的提交凭据及期限。

### 4.2 历史事实与可变状态

已追加的原始安全审计和 hook 事实保持不可变。更正通过引用原记录的新事实表达；修改
查询投影、派生状态或其它业务状态必须先声明可修改字段、revision 和审计要求。

原子更新是 persistence 的事务能力，不等于开放任意历史事件覆盖接口。本文不为尚无
生产消费者的可变对象引入通用状态机、通用 KV 表或额外业务 CRUD 层。

## 5. [TARGET V2] 原子更新与并发

### 5.1 事务边界

1. 一个 atomic 操作使用同一 SQLite 连接和显式事务，操作成功后统一 commit。
   内部 Repository 不得自行开启独立连接或提前 commit。
2. 任一业务前置条件、校验、CAS 或 SQL 操作失败，必须回滚整个操作；不能只回滚最后一条
   SQL 后提交之前的修改。
3. 事务内禁止外部网络、模型调用、subprocess 和与事务无关的等待。输入准备在事务外完成，
   但依赖当前数据库状态的条件必须在事务内重新验证。
4. 不依赖 task-local/process-local mutex 证明并发正确性；数据库约束、条件语句和事务是
   权威。涉及读后写时可采用 `BEGIN IMMEDIATE`，仍须处理锁竞争。
5. 嵌套组合复用外层事务。若使用 savepoint，其成功不构成独立持久化成功；外层失败仍全部
   回滚。禁止子操作在外层提交前向业务调用者确认持久化。

### 5.2 按预期 revision 条件更新

revision 的生成、分配和 bump 属于调用方的领域逻辑。数据库只负责在写入时原子地检查
预期 revision，并在条件满足时写入指定值；不得自行执行 `revision + 1`、分配下一版本，
或用当前版本替换调用方的预期版本。

基本要求是：操作针对 revision A 计算出更新结果，只有记录当前仍为 A 时才允许写入；
若另一操作已将记录改为 revision B，则本次更新不生效。即使两个操作完全串行执行，
后到达的旧版本结果也必须被拒绝。仅保证同一时刻只有一个 writer 不满足此要求。

这属于基于 revision 比较的原子条件更新，可以用数据库 CAS 表达；CAS 不要求数据库
自动递增 revision。应区分下面两种领域操作。

#### 5.2.1 更新 revision A 对应的状态，不改变 revision

调用方提供 `expected_revision=A` 和该版本对应的新状态；`domain_state` 是示意表名，
不要求实现一张通用状态表。SQL 语义如下：

```sql
UPDATE domain_state
SET payload_json = :new_payload
WHERE owner_principal = :owner
  AND record_id = :id
  AND revision = :expected_revision;
```

若数据库中已为 B，影响行数为 0，B 的 payload 和 revision 都保持不变。
若仍为 A，则更新 payload，revision 仍为 A。

该条件只防止跨 revision 的过期写入；同一 revision 下的两次状态更新都可能成功。
若领域还要求拒绝同一 revision 内的过期状态，需要显式增加预期状态等比较条件，
不能由 persistence 擅自 bump 业务 revision 来制造“恰好一个成功”。

#### 5.2.2 将预期旧 revision 替换为调用方指定的新 revision

如领域操作本身要发布 revision A，调用方必须分别提供 `expected_revision=R` 和
`new_revision=A`，数据库仅在当前仍为 R 时写入 A：

```sql
UPDATE domain_state
SET payload_json = :new_payload,
    revision = :new_revision
WHERE owner_principal = :owner
  AND record_id = :id
  AND revision = :expected_revision;
```

若另一操作已先从 R 发布为 B，本次 R → A 更新不生效；不得把 B 改回 A，也不得自行
生成 B 的下一版本。仅提供目标 A 而不提供预期旧值或其它业务条件，无法判断应否覆盖 B。

#### 5.2.3 结果与共同提交要求

两种操作都必须检查受影响行数：1 表示条件更新已执行，但整个事务 commit 成功后才能
对外确认成功；0 表示没有满足授权 scope 和版本条件的行，返回未应用/Conflict，
不得作为成功。若是组合事务的一部分，条件失败使整个操作回滚。
对外错误映射不得暴露未授权 owner 的记录是否存在。revision 的合法转换、溢出、
删除后重建的版本复用/ABA 防护由该领域契约定义，并在消费者验收中覆盖。

payload、索引、调用方明确要求替换的 revision，以及业务要求共同提交的审计/状态记录
必须同事务更新。独立计数器等增量修改可使用数据库表达式，例如
`SET count = count + :delta`；该规则不适用于业务 revision。约束和溢出须验证，
不得用不受保护的应用层“读、计算、覆盖”。

若某业务要求“状态更新和审计必须同时成功”，必须明确声明为该 atomic 操作；不能因此
将所有 ActionResult 都改成依赖审计落库成功。现有安全扫描的 best-effort 语义仍保留。

### 5.3 锁竞争、取消与重试

- SQLite 同时只有一个写事务。WAL 允许读写并发，不提供多个并行 writer 的提交能力。
- writer 排队、busy timeout、总 deadline、重试次数和批量上限必须有界，并留有诊断。
  具体配置按第 12 节由实现者记录和测试；V1 的 200ms 是基线，不自动作为 V2 最终值。
- `Busy` 仅在事务结果已确定、重试不会重复副作用时允许有界重试；CAS Conflict 不能直接
  改用新 revision 重试覆盖，必须由领域 service 重新计算或返回冲突。
- 请求取消或超时不表示事务未提交。确认已经回滚才可报告确定未提交；结果无法确认时
  返回/记录 `OutcomeUnknown`，调用方通过稳定操作身份查询或协调，不自动重放增量更新。
- 复用连接前必须确保没有遗留事务；无法确认时废弃该连接，并保留可诊断错误。

## 6. [TARGET V2] 成功确认、错误与持久性

### 6.1 成功确认

存储层必须返回结构化结果，不能吞掉失败或把“入队”报告为已提交。
`Committed` 表示 SQLite commit 已成功，不表示 JSONL、OTel exporter 或其它外部系统成功。

Action Runtime 的 event sink 可将失败映射为 best-effort emission report；前台 ingestion
必须将失败映射为其协议错误。诊断/health 记录失败阶段及安全上下文，不能改变领域结果。
在兼容阶段，调用返回前须完成约定的 sink 尝试；成功写入后立即查询应可见。

### 6.2 内部错误分类

| 分类 | 语义 |
| --- | --- |
| `InvalidRecord` | 不满足 typed payload、字段或容量约束；不触发重建 |
| `Conflict` | 重复键内容不同、revision/业务条件不满足 |
| `NotFound` | 已授权范围内找不到对象；对外投影遵循授权规则 |
| `Busy` | 锁竞争达到约定等待/重试边界；不等于损坏 |
| `Unavailable` | 数据库尚未就绪或处于维护/禁写状态 |
| `SchemaIncompatible` | 数据库或 payload 版本不被该操作支持 |
| `Corrupt` | SQLite 明确报告数据库损坏 |
| `StorageFull` / `Io` | 空间不足或存储 I/O 失败 |
| `OutcomeUnknown` | 未能确认操作最终提交结果；不表示回滚 |

内部错误到 RPC/CLI 的映射由对应版本协议定义。不得直接返回 SQL、数据库路径、原始
payload、token、passphrase 或底层异常字符串。读失败必须在内部与“成功且零条”区分；
V1 若保留空结果兼容投影，也必须保留诊断，不能把失败包装为无风险结论。

### 6.3 本地存储与重启恢复

本协议中的持久化要求是：数据保存到本机 SQLite 文件，关闭连接、退出程序或重启进程后
仍可读取已提交的数据。具体要求如下：

1. 生产存储使用本地数据库文件，不能用内存数据库或内存队列代替。
2. 写接口返回成功前完成 SQLite commit；另一连接可以查询到已提交数据。
3. 正常关闭、重开数据库及 daemon 进程重启后，已提交数据仍存在。
4. 进程异常退出后，已提交事务可恢复，未提交事务不部分生效。
5. 文件写入、空间或 commit 失败必须返回存储错误，不能报告写入成功。

开发验收使用本地文件 SQLite，验证关闭重开、独立进程重启及事务提交前后的进程强杀。
本次不增加分布式复制、远端存储或硬件断电测试要求；这些测试结果也不用于承诺硬件
故障或断电时绝不丢数据。SQLite 同步参数由实现者选择并记录，不再要求使用者选择
“durability 等级”。

### 6.4 JSONL 与 SQLite

JSONL 的记录格式、使用方、并发追加、轮转、权限和 Rust 验收要求单独维护在
[JSONL 存储协议](JSONL_STORAGE_PROTOCOL_zh.md)；本节只规定与 SQLite 的组合边界。

兼容期保留第 2.2 节两种调用各自的顺序和失败语义，不能统一改成一个异常策略。
本协议的原子提交只覆盖 SQLite 内部。统一库不自动改变 JSONL 的写入、保留或恢复规则。

“数据权威性”指的是：SQLite 中的数据是否能从其它完整记录恢复，还是
只有数据库保存了最新结果。例如，JSONL 若没有记录某次状态更新，就不能用旧 JSONL
重建这次更新。本次无需使用者为这个术语单独作选择：统一库按需要保留的本地数据处理，
损坏时报告错误并保留现场；没有经过验证的完整恢复来源时，不自动删除整库重建。

SQLite 作为唯一事实源、outbox、JSONL 异步投影属于独立后续变更，需定义 ack、重复投影、
积压、失败恢复和 shutdown；本草案不默认启用。数据库更新不得依赖两个独立文件的“双写”
证明原子提交，也不得依赖跨独立 WAL 数据库的 ATTACH 事务证明整体原子性。

## 7. [TARGET V2] 所有权、资源与维护

- persistence 由系统级 asc-daemon composition root 装配；Rust CLI/TUI 经 daemon-core
  授权，不直读/写 SQLite，不自行推导 HOME 或 XDG 数据库路径。
- owner 来自可信 Principal/QueryScope；调用方传入 UID/role/scope 和 trace 仅作归因或
  correlation，不能成为权限凭据。state migrator 使用显式 owner 映射。
- 数据目录、DB、WAL/SHM、备份和迁移产物按部署契约受限；验证权限、symlink/hardlink
  和路径替换，不把 best-effort chmod 视为权限验收完成。
- SQLite 使用本机受支持文件系统；部署存储类型必须符合 WAL 的共享内存/锁要求。
- 同步 SQLite 工作进入有容量上限的 blocking executor 或 writer actor；accept、认证、
  deadline 和 shutdown 必须继续推进。不得持数据库事务等待异步队列。
- shutdown 停止 admission，处理或明确中止在途操作，排空已接收的写入并报告结果；
  不要求每次 commit 都 checkpoint，不能将 checkpoint 当作唯一提交点。
- 默认保留 security 30 天、observability 7 天，按发生时间分别清理；不得因同库合并
  统一成较短保留期。迟到事件的清理结果遵循该规则，清理边界须有 fixture。
- 清理可按有界批次提交，每批原子；整个保留期清理不承诺单事务。维护应具备触发、互斥、
  retry、健康和停止规则，不为此引入无其它消费者的通用周期调度框架。
- 统一库损坏时停止相关写入并报告；不得照搬 V1 删除整库重建。
  可重建派生索引只能在来源完整、版本匹配且恢复过程经过验收时重建。

## 8. [TARGET V2] schema、导入与回滚

### 8.1 Rust 必须保留旧版本迁移能力

旧版本迁移是 Rust 实现的一部分，不是只运行一次后删除的开发脚本。Rust 迁移入口必须
直接读取受支持的旧数据库，完成字段升级、旧数据转换和两库合并；不得要求先运行 Python
CLI 将源库升级到最新版本，也不得依赖 Python 模块或 SQLAlchemy 执行迁移。

| 输入 | Rust 必须完成的迁移 |
| --- | --- |
| security-events schema v1 | 处理缺少 run/call/tool-call 关联字段和 verdict 的旧行，迁入统一模型 |
| security-events schema v2 | 保留关联字段，按原有规则从 details 提取 verdict，再迁入统一模型 |
| security-events schema v3 | 保留既有记录及 verdict 语义，迁入统一模型 |
| observability schema v1 | 保留 hook、时间、metadata、metrics、关联字段及旧整数 id 映射，迁入统一模型 |
| 后续受支持的 Rust 数据库旧版本 | 按有序迁移步骤升级到当前版本，保留已有数据 |

迁移后的缺失字段按原字段默认值/null 规则解释，不伪造关联信息。每个受支持旧版本必须
保留可执行迁移测试；维护 Rust 新版本时，这些旧库输入仍需通过。停止支持某旧版本需要
显式兼容变更，不能因为 Rust 已上线就删除相应迁移代码。Python 可以用于生成冻结的
测试样本，但运行 Rust 迁移及其验收不依赖 Python。

### 8.2 迁移执行、恢复与回滚

1. 统一库只使用一个数据库 schema 版本序列。数据库版本、事件 payload 版本和本文文档
   版本分别管理；不能将 V1 两个 `user_version` 简单覆盖到同一文件。
2. 新建空库、已有库结构升级和 V1 数据导入分别定义。只读查询不得触发迁移；未知较新
   schema 不降级、不覆盖，不能以空结果掩盖不兼容状态。
3. V1 source 支持显式指定并核对路径、schema 和 owner；导入前固定可重复读取的 source
   snapshot 或停止源写入，不能跨两个仍在变动的源库声称获得一致快照。
4. 导入记录和该批次的进度/ID 映射在同一目标事务提交。记录 source identity、版本、
   checkpoint、计数和校验结果；重复运行不能重复导入。
5. 批次迁移不宣称整体一次原子提交。迁移中目标库不对普通查询开放，完成校验后才切换；
   若将来支持在线 mixed-read，必须另行定义去重、可见性和恢复协议。
6. 按第 8.1 节处理受支持旧库，保存历史关联字段、null 和 verdict 语义；坏行必须记入
   有界报告，不得静默丢弃后声明全部成功。
7. 保留 V1/V2 混合历史 payload 的读取能力，直到批准的兼容窗口结束。Rust 运行时及
   迁移入口都不依赖 Python；旧版本迁移能力的支持期限按第 8.1 节管理。
8. 切换前失败可回滚到未修改的 source；V2 接收新写入后回滚必须包含这些新增数据的处理
   方案，不能简单启动 V1 指向旧库并声称无损。备份、还原和回切均需独立测试。

## 9. [TARGET V2] 可执行验收矩阵

以下 `DB-*` 是本协议新分配的验收 ID，目前均为**待实现 fixture/runner**。
每项交付必须记录输入、步骤、预期数据/错误、有序提交轨迹和实际结果。

| ID | 验收要求 | 最低证据 |
| --- | --- | --- |
| DB-001 | 两类 payload 到统一模型往返，类型规则、null、时间精度与字段投影正确 | V1 frozen fixtures + Rust runner + 文件 DB |
| DB-002 | 原始事实不覆盖，重复键同内容幂等、不同内容冲突 | 顺序与独立连接并发测试 |
| DB-003 | 多条/多 Repository 组合全部提交或回滚 | 首步、后续步骤、commit 故障注入并重开 DB |
| DB-004 | 预期 A 的状态更新在当前为 B 时不生效；预期 R 发布为指定 A 时，若 B 已先发布则不覆盖 B；数据库不 bump revision | 独立连接及独立进程，barrier 协调及完全串行的过期请求；验证匹配成功、不匹配零更新、同版本状态更新不自动改 revision |
| DB-005 | 独立计数器的数据库内增量更新不丢计数，越界不部分生效；不代替调用方管理 revision | 并发及溢出/约束失败测试 |
| DB-006 | payload、索引、revision 同步；列表/get/count 不读到半更新 | 并发读写、回滚及快照测试 |
| DB-007 | 提交后响应丢失不被误报确定回滚，重试规则正确 | 真实请求边界故障；幂等写与非幂等更新分别验证 |
| DB-008 | busy、full、I/O、corrupt、schema、invalid 分开处理 | 真正锁竞争 + 可控底层故障；不误删库 |
| DB-009 | 安全审计失败不改变业务结果，前台 obs 失败可见 | 两种 sink 各阶段故障，兼容输出和诊断 fixture |
| DB-010 | 无 exporter、未采样和 telemetry 故障不跳过安全事件尝试 | Action Runtime 直接消费者测试，对应 SMC-021 |
| DB-011 | security 查询、session/run/timeline、关联与分页兼容 | DPV1 查询 fixture；同时间戳、迟到、重复关联 ID |
| DB-012 | 多 owner 查询/更新/聚合/关联隔离，不能自报越权 | 真实 daemon + 不同 UID client；对应 DPROC/DPV1 授权要求 |
| DB-013 | PII、passphrase 脱敏，执行结果不与 verdict 混淆 | SMC-009/010 和 deny/error/missing 样本 |
| DB-014 | 只读不建库/迁移，未知版本不降级 | 文件/目录状态对比及错误断言 |
| DB-015 | Rust 独立迁移每种受支持旧库，无需先用 Python 升级；迁移可重复、中断恢复、owner/ID 无冲突 | 旧 security v1/v2/v3、obs v1 文件 fixture；无 Python 的 Rust 迁移环境，分批故障、计数/字段校验及后续 Rust schema 升级回归 |
| DB-016 | 回滚覆盖切换前和 V2 新写入后两个阶段 | 备份、切换、恢复、回切后的完整数据校验 |
| DB-017 | commit 前强杀无部分更新，commit 后强杀可恢复 | 独立 Rust 进程 + 文件 SQLite + 确定的进程间同步点 |
| DB-018 | 数据写入本地 SQLite 文件，关闭连接后由新进程重开仍可读；文件写入失败不报告成功 | 明确文件路径，独立写入/读取进程，以及写入/commit 失败注入 |
| DB-019 | 两类保留期独立，清理并发有界且不误删需保留的数据 | 时间边界/迟到/大批量/损坏恢复测试 |
| DB-020 | writer 队列、事务、阻塞线程有界，停止排空可观测 | 压测 + shutdown/timeout；资源和分位延迟报告 |
| DB-021 | Rust CLI 经 UDS 访问真实 daemon，成功后立即可查，重启保留 | 真实 Rust binaries、文件 DB、SIGTERM 和重启 |

单元测试、mock Repository、`:memory:` SQLite、临时文件 SQLite 和独立进程是不同证据层级。
临时路径上的文件 DB 可以验证重开和进程崩溃恢复，但不能证明实际部署目录的权限布局。
进程内测试全绿不完成 Integration Ready；硬件断电测试不属于本次门禁。

crate 验收必须提供 build/fmt/clippy/test、适用 fixture 的 pass/fail 矩阵、外部兼容报告、
内部变更记录、直接消费者证据和回滚程序。验收命令须指向实际交付的 runner；不能只写
`cargo test` 或一个不存在的 fixture 路径。

## 10. 兼容性变更记录

下列为随本草案提交的提案，状态均为**待 Definition Review 冻结**，不是已批准发布变更。

| ID | 变化 | 必须同步的兼容证据 |
| --- | --- | --- |
| DBCR-001 | 两份 SQLite 索引合并为统一库/事件结构，Rust 保留受支持旧版本迁移逻辑 | Rust 独立迁移、state schema/路径迁移、owner/ID 映射、查询协议兼容 |
| DBCR-002 | 新增 atomic、按调用方预期 revision 的条件更新和明确提交结果；revision 分配/bump 由调用方负责 | 新能力 DB-003 至 DB-008；首个可变状态直接消费者 |
| DBCR-003 | V2 同键异内容从忽略改为冲突 | V1/V2 幂等分类及错误 projection；无键 obs 不擅自去重 |
| DBCR-004 | 统一库不再损坏即删除重建，保留本地数据并报告错误 | 部署契约、恢复、诊断、备份/回滚和混合保留期 |
| DBCR-005 | V2 查询内部明确区分错误与空结果 | query protocol 的版本化错误映射及兼容 fixture |

仅交付本文不修改现有 Python/Rust runtime、CLI/RPC 或 fixtures 的行为。实现上述变化时，
必须同步更新相关行为契约和 fixture，不能只引用这张表跳过兼容评审。

## 11. 基线证据与来源

### 11.1 当前源码

- [SecurityEvent schema](../../agent-sec-cli/src/agent_sec_cli/security_events/schema.py)、
  [ORM model](../../agent-sec-cli/src/agent_sec_cli/security_events/models.py)、
  [schema versions](../../agent-sec-cli/src/agent_sec_cli/security_events/schema_version.py)、
  [Repository](../../agent-sec-cli/src/agent_sec_cli/security_events/repositories.py)。
- [Observability schema](../../agent-sec-cli/src/agent_sec_cli/observability/schema.py)、
  [ORM model](../../agent-sec-cli/src/agent_sec_cli/observability/models.py)、
  [Repository](../../agent-sec-cli/src/agent_sec_cli/observability/repositories.py)。
- [SqliteStore](../../agent-sec-cli/src/agent_sec_cli/security_events/orm_store.py)、
  [maintenance](../../agent-sec-cli/src/agent_sec_cli/security_events/sqlite_maintenance.py)。
- [Security 双写](../../agent-sec-cli/src/agent_sec_cli/security_events/__init__.py)、
  [Observability 双写](../../agent-sec-cli/src/agent_sec_cli/observability/__init__.py)、
  [foreground CLI](../../agent-sec-cli/src/agent_sec_cli/observability/cli.py)。
- [Security writer](../../agent-sec-cli/src/agent_sec_cli/security_events/sqlite_writer.py)、
  [Observability writer](../../agent-sec-cli/src/agent_sec_cli/observability/sqlite_writer.py)、
  [Observability retention](../../agent-sec-cli/src/agent_sec_cli/observability/config.py)。
- [Daemon queries](../../agent-sec-cli/src/agent_sec_cli/daemon/handlers/security_query.py)、
  [correlation](../../agent-sec-cli/src/agent_sec_cli/observability/correlation.py)、
  [report aggregation](../../agent-sec-cli/src/agent_sec_cli/observability/session_report.py)。

### 11.2 已运行的 V1 基线

在第 1 节 checkout、Python 3.11.6 下，从 agent-sec-core 运行：

```bash
agent-sec-cli/.venv/bin/python -m pytest tests/unit-test/security_events tests/unit-test/observability tests/unit-test/daemon/test_security_query_handler.py -q --disable-warnings
agent-sec-cli/.venv/bin/python -m pytest tests/e2e/cli/test_observability_record_sqlite_e2e.py tests/e2e/cli/test_observability_record_jsonl_e2e.py -q --disable-warnings
```

本轮分析基线结果分别为 **466 passed**、**2 passed**。后者因 PATH 无 `agent-sec-cli`，
实际使用 Python 模块 CLI 子进程，验证临时文件 SQLite/JSONL；没有验证已安装 CLI 二进制、
Rust daemon、CAS、Rust 跨记录原子更新或断电恢复。这些结果不是第 9 节新增 DB 门禁的通过记录。

### 11.3 SQLite 依据

- 一个 writer、事务快照、BEGIN IMMEDIATE、savepoint 和错误后的回滚处理：
  [SQLite Transactions](https://www.sqlite.org/lang_transaction.html)。
- WHERE 条件不满足时更新零行，未在 SET 中指定的列保持不变：
  [SQLite UPDATE](https://www.sqlite.org/lang_update.html)。
- WAL 读写并发、文件系统要求、checkpoint 与跨 ATTACH 数据库原子性边界：
  [SQLite WAL](https://www.sqlite.org/wal.html)。
- NORMAL/FULL 与进程崩溃、系统崩溃和断电持久性的区别：
  [SQLite synchronous](https://www.sqlite.org/pragma.html#pragma_synchronous)。

## 12. 开发时需要补齐的实现说明

前文已经明确本地 SQLite、统一模型、Rust 旧版本迁移及按预期 revision 条件更新。
下面是实现者需要在代码和测试中说明的细节，不是要求使用者再逐项批准。
普通技术选择由实现者依据已有源码和兼容契约完成；只有改变已约定的行为或支持范围时，
才需要说明具体变化及其影响。

| 实现细节 | 说明 | 实现者的交付 |
| --- | --- | --- |
| 数据库文件和表 | 文件放在哪里、表有哪些列、怎样快速查询 | DDL、索引、目录配置、时间精度和 schema 版本 |
| 旧版本迁移 | Rust 怎样把旧库转成新库，失败后怎样继续 | 第 8.1 节各版本迁移代码、样本和运行命令 |
| 记录 ID 与重试 | 重试同一条写入不能多记一条；两条合法相同内容也不能误合并 | 旧/新 ID 映射、重复提交规则及测试 |
| 条件更新的调用 | 哪个模块提交 expected_revision，需要更新哪些字段 | 调用参数、版本不匹配结果和真实调用方测试；数据库不 bump revision |
| 容量和等待时间 | 一条记录能多大、一次能写多少、锁忙时等多久 | 有界参数、默认值和测试结果 |
| 对外读取 | 合并后原来的列表、统计和时间线还能正确读取 | 兼容输出测试及明确的变更记录 |
| 验收结果 | 怎样运行测试、怎样确认旧数据和新写入都正确 | DB-001 至 DB-021 对应测试、结果及回滚说明 |

这些说明随对应模块实现补齐，无需等待其它无关模块的设计。
