# AgentSecCore JSONL 存储协议

## 1. 范围与文档关系

| 项目 | 内容 |
| --- | --- |
| 协议标识 | `ASC-JSONL-STORAGE` |
| 文档版本 | `0.1`，实现与评审草案 |
| 当前实现基线 | `main@9f109d55964cfc5820d41564869f70879a8de21f` 的 Python CLI/daemon，以及同 checkout 的 ANOLISA telemetry 代码 |
| 目标 | 在 Rust 中保留 JSONL 本地记录与 telemetry 追加能力，明确文件格式、并发、轮转、失败处理和验收 |
| 实现状态 | 本文定义存储要求，不表示 Rust writer 或对应验收已经完成 |

本文独立描述 JSONL 文件存储，与 [SQLite 存储协议](SQLITE_STORAGE_PROTOCOL_zh.md) 配套。
SQLite 负责结构化查询和条件原子更新；JSONL 负责逐条追加记录，不提供 revision CAS、
原地更新或多记录事务。合并 SQLite 中的两类数据结构，不代表合并所有 JSONL 文件或 schema。

总体架构遵循 [V2 迁移架构](AGENT_SEC_RUST_MIGRATION_zh.md)。安全事件字段与脱敏遵循
[Security Middleware 契约](SECURITY_MIDDLEWARE_CONTRACT_zh.md)，诊断日志与目录遵循
[进程部署契约](DAEMON_PROCESS_DEPLOYMENT_CONTRACT_zh.md)，telemetry 字段和采集门控遵循
[Telemetry 安全事件同步规格](telemetry-security-event-sync.md)。本文不是新增的 V1 行为契约。

- **[CURRENT]**：当前源码可确认的行为，包括实现限制。
- **[PRESERVE V1]**：兼容期间需要保留的格式、调用结果和文件消费语义。
- **[TARGET V2]**：Rust 实现应满足的要求；修正已有行为时需同步相关契约及 fixture。

实现说明由开发者随代码和测试补齐，不要求使用者逐项选择文件锁、缓冲区或底层 API。

## 2. [CURRENT] 哪些组件使用 JSONL

### 2.1 五条文件流

| 文件流 | 写入方与内容 | 已确认的消费方式 |
| --- | --- | --- |
| `security-events.jsonl` | 安全中间件在 action 完成/异常时，经 `log_event` 写入 SecurityEvent | 本地审计记录；集成及 Hook E2E 测试直接读取文件 |
| `observability.jsonl` | `observability record` CLI 写入 Agent/LLM/Tool hook 记录 | 本地轨迹记录；Hook/Gateway E2E 直接读取，格式可供脚本消费 |
| `cli.jsonl` | CLI logging 写入诊断，包括能力异常、JSONL/SQLite 写入失败等 | 本地排障及日志测试 |
| `daemon.jsonl` | daemon logging 写入启动、请求和后台任务等诊断 | 本地排障及 daemon 测试 |
| `/var/log/anolisa/sls/ops/agent-sec-core.jsonl` | lifecycle 将安全事件投影成字段受限的 telemetry，再调用 `TelemetryWriter` | ANOLISA telemetry uploader 读取，并在采集启用时上传 SLS |

前四条文件流复用 `JsonlEventWriter`。telemetry 使用独立 `TelemetryWriter`，文件创建、
锁、轮转和隐私规则不同，不能因扩展名相同而统一成一套默认写策略。

OpenClaw、Hermes、Cosh、Codex、Qoder 和 Qwen Code 集成经 CLI 提交 observability
记录，不直接打开 observability JSONL 文件。这描述仓库中的调用链，不证明某台机器
已经启用这些插件或 telemetry 上传。

### 2.2 查询读取的是 SQLite

- `agent-sec-cli events` 使用 SQLite reader。`--output jsonl` 是查询结果的输出格式，
  不表示读取 `security-events.jsonl`。
- `observability review/report` 和 daemon 的 security/session/run/timeline 查询使用 SQLite。
- 当前这些查询没有 SQLite 不可用时自动读取 JSONL 的 fallback。
- 当前损坏数据库的重建路径不从 JSONL 回灌历史数据。
- telemetry uploader 是第五条流的实际程序读取方；不能把它视为前四条文件的默认上传方。

JSONL 受轮转和失败丢弃影响，不能仅凭文件存在就认为它包含完整数据库历史。

## 3. [CURRENT][PRESERVE V1] 记录格式

### 3.1 共同格式

本地 writer 将一条记录序列化为 UTF-8 JSON，再追加一个 LF（`\n`）。一条记录占一个
物理行；字符串中的换行由 JSON 序列化转义。JSONL 文件不是 JSON 数组，没有文件级
包头或结束标记。telemetry writer 也使用这一行格式。

读取时按每行 JSON 内容解释，不依赖 object key 顺序或分隔符空格。字段名称、值、
缺失/null、嵌套结构和各记录类型的校验规则仍属于兼容契约，不能因重写而改变。

### 3.2 每条流的 payload

| 流 | 记录内容 |
| --- | --- |
| security | `event_id/event_type/category/result/timestamp/trace_id/pid/uid/session_id/run_id/call_id/tool_call_id/details`；V2 标准 trace/span 和 schema version 按 middleware 契约扩展 |
| observability | `hook/observedAt/metadata/metrics`；metadata 使用 sessionId/runId/callId/toolCallId 等既有别名，六种 hook 各有 metric allowlist |
| CLI/daemon 诊断 | 必有 `timestamp/level/component/event/message/pid`，按上下文增加 logger/function、invocation/request IDs、trace/correlation、data 和异常字段 |
| telemetry | 从安全事件生成独立的字段白名单投影；不复制完整 details 或诊断日志 |

security 的 `result=succeeded/failed` 表示操作是否成功执行，不等同于风险 verdict。
observability 的 metrics 与 security 的 details 保留各自含义；合并存储基础设施不能把
两个字段互相替换。

当前诊断记录可包含异常文本，ERROR 及以上可包含 traceback。它们是本地诊断内容，
不能自动进入 telemetry 或对外 RPC 错误。安全事件的 PII/Skill Ledger 脱敏必须在写入前
完成，不能依赖后续 JSONL reader 清理敏感内容。

## 4. [CURRENT] 本地四条流的文件行为

### 4.1 路径、权限和默认轮转

四条本地流使用共享的数据目录解析：`AGENT_SEC_DATA_DIR` 可覆盖目录；未指定时尝试
`/var/log/agent-sec`、`~/.agent-sec-core` 和 per-user 临时目录。此路径发现用于 V1 兼容
与迁移，V2 按系统级 daemon 的部署契约配置路径。

| 流 | writer 默认轮转大小 | 默认保留备份数 |
| --- | --- | --- |
| security-events | 100 MiB | 10 |
| observability | 256 MiB | 3 |
| cli | 10 MiB | 5 |
| daemon | 10 MiB | 5 |

这些值来自 writer 源码。JSONL 按文件大小和备份数量管理，SQLite 的 30 天/7 天保留期
不适用于 JSONL。阈值不是单条记录大小上限：当前 writer 没有独立的单记录拒绝上限。

本地活动文件和独立 `.lock` 文件创建为 `0600`，打开已有文件时通过 fd 收紧权限，
不依赖调用方 umask。共享路径解析器会尝试将选中的数据目录设置为 `0700`；直接指定
writer 路径时，writer 使用 `0700` 新建目标父目录，不统一修复既有父目录和祖先目录。

writer 首次写入时尝试收紧旧备份权限，只识别下列后缀的备份：

```text
<stream>.jsonl.YYYYMMDD-HHMMSS.fff
<stream>.jsonl.YYYYMMDD-HHMMSS.fff.N
```

`.old/.bak/.lock` 等不属于备份迁移目标。收紧备份权限使用不跟随 symlink 的打开路径；
不能据此推断活动文件、lock 文件和所有清理路径都已具备同样的链接安全检查。

### 4.2 并发与追加

通常写入顺序是：

```text
进程内锁
  → 序列化完整一行
  → 获取独立 <stream>.jsonl.lock 的 flock
  → 按路径打开活动文件
  → 检查大小并按需轮转
  → 重新打开轮转后的活动文件
  → append + flush + close
  → 释放文件锁
```

锁覆盖轮转和随后的追加；每次临界区内重新按路径打开文件，避免后续写入继续落在已轮转
的旧 inode 上。当前 writer 调用 flush，没有调用 fsync，也没有 JSONL 事务日志。

现有实现存在两个必须区分的失败行为：

- 获取 lock 文件或 flock 失败时，仍尝试无 flock 写入；此路径不能保证进程间互斥。
- rotate/备份清理的部分错误被内部捕获，写入可能继续；因此 `write_or_raise` 成功不证明
  本次所有轮转和清理步骤都成功。

### 4.3 轮转与清理

追加前以“当前文件字节数 + 新行 UTF-8 字节数 >= 阈值”判断轮转。轮转将当前文件移动为
UTC 毫秒时间戳后缀的备份，重名时尝试追加数字后缀，再打开活动路径写入。

清理只选择匹配备份命名格式的文件，按 mtime 从旧到新删除超额备份。阈值判断包括待写
行，超大首条记录也可能触发空文件轮转；现有行为不等于已经具备完善的超大记录策略。

这些规则有现有并发与轮转测试，但不能据此声称断电、写到一半进程崩溃或每一种路径替换
均已被测试覆盖。

## 5. [CURRENT][PRESERVE V1] 调用结果与失败处理

| 调用路径 | JSONL 失败时的行为 |
| --- | --- |
| 安全事件 `log_event` | JSONL 失败不改变 action 结果，仍独立尝试 SQLite；可经诊断 logger 记录失败 |
| 前台 `observability record` | JSONL 序列化/追加失败传播到 CLI，返回非零，并且不继续 SQLite 写入 |
| CLI/daemon 诊断 | best-effort；失败不抛回业务，也不递归记录同一个日志写入错误 |
| telemetry | best-effort；允许跳过或丢弃，不影响本地安全事件和业务结果 |

前台 observability 在 JSONL 成功、SQLite 失败时仍返回非零，JSONL 中已追加的记录不会
撤回。因此重试可能再次追加同样内容。安全事件在 SQLite 中按 event_id 去重，不代表
JSONL 文件也去重。JSONL 当前没有跨调用幂等保证。

诊断级别当前为：CLI 默认 WARNING，daemon 默认 INFO；分别使用
`AGENT_SEC_CLI_LOG_LEVEL` 和 `AGENT_SEC_DAEMON_LOG_LEVEL`。`off` 禁用，值按去空格、
大小写不敏感解析，未知值回到各自默认级别。迁移时需保留支持接口的行为。

## 6. [CURRENT][PRESERVE V1] telemetry 文件的独立规则

### 6.1 写入与门控

- 默认路径为 `/var/log/anolisa/sls/ops/agent-sec-core.jsonl`，可由
  `AGENT_SEC_TELEMETRY_LOG_PATH` 覆盖；不使用本地四条流的数据目录 resolver。
- 每次由 `record_security_event_telemetry` 发出记录前检查
  `/etc/anolisa/.telemetry_disabled`：存在则停写；检查失败且非 ENOENT 时也停写。
- 目标文件必须已存在；不存在则不构造/写入该次 telemetry。
- writer 不创建目录、目标文件、lock 文件、备份或临时文件，不负责修改权限和轮转。
- 使用进程内非阻塞锁及目标 fd 上的非阻塞 flock；竞争时允许跳过，不排队重试。
- 每条记录重新打开目标路径，处理短写，完成后关闭；不持久占用旧文件 fd。
- `.telemetry_linked` 用于未来获批的 L3 字段；当前 L3 mapper 为空，不得据此额外输出原文。

### 6.2 文件管理与消费

同 checkout 的 ANOLISA `OpsLayout` 预创建组件 JSONL 文件并配置 logrotate，当前配置
为 `size 30M / rotate 1`。其文件权限由 ANOLISA 管理，不能将本地私有日志的 chmod/轮转
逻辑套到此路径。

ANOLISA uploader 发现 ops 目录下的组件文件，按文件及偏移读取记录，构造 SLS 请求。
因此修改 telemetry 的文件名、行格式、字段或轮转行为需要直接消费者验证。AgentSec
只完成本地追加，不代表 uploader 已读取或远端已接收。

## 7. [TARGET V2] Rust JSONL 存储要求

### 7.1 保留流边界和字段契约

1. Rust 直接完成序列化和文件操作，不依赖 Python writer、logging handler 或 SQLAlchemy。
2. 四条本地流可以共用追加/轮转实现，但保持各自文件、payload、大小和备份配置。
   telemetry 保留第 6 节的独立策略及字段投影。
3. 使用完整记录输入，先完成领域校验和脱敏再序列化；存储层不自行补业务 verdict，
   不根据任意 request 自动增加审计字段。
4. 保留受支持旧 JSONL 的读取语义、备份命名识别和权限收紧。Rust 无需先运行 Python
   改写旧文件；payload 版本变化通过明确版本解释，不批量覆盖历史行。
5. V2 标准 trace/span 由 OTel context 提供；无 exporter 或未采样不跳过安全事件写入。
6. V2 事件写入由 daemon 内约定的 lifecycle owner 完成；asc-cli 作为客户端不再自行
   生成第二条同一业务事件。CLI 自身诊断与业务安全事件分别管理。

### 7.2 追加的成功含义

本地追加接口应能区分 `Appended` 与具体失败。成功表示完整的 UTF-8 JSON 行及 LF
已经写入文件、必要的用户态缓冲已 flush；不能仅表示进入后台队列。
上层再按第 5 节分别选择传播错误或 best-effort。

正常关闭重开、新进程读取时应看到已完成的记录。本次以本地文件保存为验收目标，
不新增硬件断电测试，也不将 flush 描述为 fsync 或断电持久性保证。

一条记录写到一半发生 I/O 失败或进程退出，可能留下尾部残片；JSONL 不提供 SQLite
式回滚。接口不得把失败说成“确定没有写入任何字节”，也不得在没有幂等协议时自动
重试并承诺只追加一次。批量 JSONL 写入是多次追加，不承诺整批全有或全无。

### 7.3 并发、轮转和资源

- 对同一本地流，锁必须覆盖检查、轮转、追加和必要的尾部处理；不同流各自管理锁。
- 所有共享文件的 writer 必须遵守相同锁协议；advisory lock 不能约束不合作的写入者。
- Rust 本地 writer 获取锁失败时返回失败，由上层执行 best-effort/报错策略，不能静默
  降级到无锁写入。这是对当前 fallback 的明确修正，需对应变更记录和并发 fixture。
- 文件轮转后重新按活动路径打开。备份命名碰撞不得覆盖已有备份；清理仅处理本流被识别
  的普通备份文件，不删除其它日志、锁文件或不相关文件。
- 轮转阈值、超大记录和空文件策略由实现说明记录并测试；不得静默截断 JSON/payload，
  或因空备份轮转而意外淘汰本应保留的数据。若新增拒绝上限，需验证调用方兼容性。
- 活动文件、lock 和备份受部署权限约束；验证不安全链接/文件类型及路径替换。
  telemetry 目标按其外部管理契约处理，不由 AgentSec 扩权或收紧权限。
- 文件 I/O 和锁等待进入有界执行资源；限制排队和等待，不能阻塞 daemon 的 accept、
  timeout、授权和 shutdown。参数由实现者依据负载记录并验证。
- shutdown 停止接收新追加，处理或明确失败在途记录，flush 已接受的数据，报告排空结果。
  业务 best-effort 不代表允许隐藏已接受但未处理的后台队列。

### 7.4 读取、尾部不完整与旧文件

本节约束需要消费文件的 Rust reader/迁移工具，不要求把现有 SQLite 查询改成 JSONL reader。

- 读取正在追加的文件时，仅消费有完整 LF 的行；未完成尾行暂不消费，不能将其解释成
  成功的空记录，也不能使前面的完整行无法读取。
- 已封闭备份中的坏行或残片必须报告位置和原因；按调用场景拒绝导入或跳过并计数，
  不能静默跳过后声明完整迁移。
- writer 在异常退出后继续写同一文件时，不得把新 JSON 直接拼到已知残片后。具体恢复
  可采用保留问题文件并切换到干净活动文件等办法；需在同一流锁内执行并保留诊断，
  不静默删除既有完整记录。
- 读取活动文件及轮转备份时记录来源，不能因重名、轮转或重复扫描伪造“恰好一次”。
  telemetry uploader 的偏移与轮转消费由 ANOLISA 负责，需复用其直接消费者测试。
- 旧备份权限处理只针对已识别的文件。JSONL 旧文件兼容不同于 SQLite schema 迁移，
  不得为了升级数据库而删除或重写所有 JSONL。

## 8. JSONL 与 SQLite 的组合

1. 同一 SecurityEvent 的 JSONL 和 SQLite 使用同一预先生成的 event_id 和业务 payload，
   两次写入按兼容契约独立尝试。
2. observability 保留先 JSONL、后 SQLite 的前台失败语义；不能为了复用 writer 而改变
   这一调用顺序。
3. JSONL 追加与 SQLite commit 不是共同事务；本地两份输出可以暂时或永久不一致。
4. SQLite 的 revision 条件更新不自动修改历史 JSONL 行。若某业务要求更新后留下新审计
   记录，由业务明确产生追加事件，不能默认全部变更都能从旧 JSONL 重放恢复。
5. SQLite 失败时不能默认让 query fallback 到 JSONL，也不能默认删库后回放 JSONL。
   重建数据库需要另有完整来源、ID 映射、重复处理、保留期和校验协议。
6. 后续若改成 SQLite commit 后经 outbox 生成 JSONL，需单独变更确认时点、投影重试、
   重复处理、恢复和消费者兼容；本次不引入 outbox。

## 9. Rust 验收要求

以下 `JL-*` 是新增验收 ID，当前均为**待交付 fixture/runner**。已有 Python 测试作为
源码行为与冻结样本来源，不表示 Rust 已通过相应门禁。

| ID | 要求 | 最低证据 |
| --- | --- | --- |
| JL-001 | 四条本地流和 telemetry 的行格式、字段及版本正确 | 各流冻结样本，UTF-8/中文/内嵌换行/null 往返测试 |
| JL-002 | 写入成功后完整行可被独立进程读取 | 本地文件、关闭重开和新进程读取，不以纯内存测试代替 |
| JL-003 | 同流多线程/多进程追加不交错成坏 JSON | 独立进程并发，完整行数、唯一事件和字段校验 |
| JL-004 | 轮转与并发追加无意外丢失，后续记录落入当前文件 | 真实跨进程锁竞争、低阈值轮转、活动文件及全部保留备份校验 |
| JL-005 | 备份命名、碰撞、保留数量、超大首条与清理正确 | 固定时间碰撞、大记录、空文件、无关文件及 symlink 样本 |
| JL-006 | 本地权限、旧备份收紧、文件类型与路径安全符合约定 | 不同 umask、遗留权限、链接与路径替换测试 |
| JL-007 | 锁失败不降级无锁写，短写/空间/追加/flush 失败可诊断 | 可控故障注入，明确失败和已写字节边界 |
| JL-008 | 序列化/追加/轮转故障按调用方策略处理 | 安全业务结果不变、前台 obs 返回错误、诊断失败不递归 |
| JL-009 | JSONL/SQLite 两种双写顺序与部分失败兼容 | 每个 sink 分别故障，验证另一 sink 是否尝试及 CLI 输出 |
| JL-010 | PII/Skill Ledger 脱敏，执行结果与 verdict 不混淆 | 领域 projection fixture，不修改业务返回数据 |
| JL-011 | CLI/daemon 日志级别、off、关联字段与异常字段兼容 | 现有诊断样本及真实入口测试 |
| JL-012 | telemetry sentinel 每次生效，白名单不泄露业务原文 | disabled 存在/移除/检查异常、linked 及新业务字段测试 |
| JL-013 | telemetry 不创建文件/锁/备份、不修改外部权限，竞争可跳过 | 不存在文件、锁忙、外部 rename 后 fresh open、短写测试 |
| JL-014 | telemetry 仍可由 ANOLISA uploader 按原格式读取 | 直接消费者文件/偏移/轮转/请求构造测试；本地追加不宣称远端成功 |
| JL-015 | 进程中断的残片不污染后续完整记录，旧文件可解释 | 写入中断、活动尾行、坏备份及恢复后继续写入测试 |
| JL-016 | Rust 不依赖 Python 写入或处理受支持旧文件 | 无 Python 的 Rust 文件读写、旧备份兼容和权限处理测试 |
| JL-017 | 有界队列/锁等待/I/O，shutdown 处理已接受记录 | 负载、timeout、排空测试和资源报告 |
| JL-018 | 实际业务入口写入正确流且至多产生一条最终安全事件 | Rust daemon + 直接调用方集成；telemetry 故障不跳过本地事件 |

测试报告必须区分库测试、临时文件、跨进程和真实部署证据。磁盘本地追加测试不证明
硬件断电恢复或 SLS 上传完成。每项交付记录 fixture、运行命令、输入、预期和实际结果。

## 10. 实现时需要记录的变化

| 项目 | 已明确的要求 | 实现者补齐内容 |
| --- | --- | --- |
| 本地 writer | Rust 实现，四条流独立配置，保留支持接口 | 文件 API、锁/排队上限、默认配置、错误类型 |
| 路径与旧文件 | V2 系统部署路径，旧文件无需 Python 预处理 | 新旧目录映射、保留备份处理及回滚说明 |
| 轮转 | 保留命名/数量语义，不覆盖已有备份或误删数据 | 碰撞、超大行、空备份和失败处理策略 |
| 部分写入 | 不承诺回滚，不把残片与新记录拼接 | 中断恢复步骤、保留的问题文件和诊断 |
| telemetry | 只写预创建目标，门控/白名单/外部轮转不变 | 与 ANOLISA 文件管理和 uploader 的直接消费者证据 |
| 兼容变化 | 不静默改变对外字段、调用结果或保留语义 | 变更记录、对应契约和 JL fixture |

特别需要记录的草案变化：本地锁失败从“继续无锁写入”改为“失败并由上层处理”；新增
明确的残片恢复规则；如果新增单记录拒绝上限或调整轮转异常策略，也需列明对调用方的
影响。文档提出这些要求不代表已有实现已修复，不能只修改文档即宣称通过验收。

## 11. 当前源码与测试来源

### 11.1 AgentSecCore

- [共享本地 writer](../../agent-sec-cli/src/agent_sec_cli/security_events/writer.py)、
  [路径配置](../../agent-sec-cli/src/agent_sec_cli/security_events/config.py)。
- [SecurityEvent schema](../../agent-sec-cli/src/agent_sec_cli/security_events/schema.py)、
  [安全事件双写](../../agent-sec-cli/src/agent_sec_cli/security_events/__init__.py)、
  [lifecycle](../../agent-sec-cli/src/agent_sec_cli/security_middleware/lifecycle.py)。
- [Observability schema](../../agent-sec-cli/src/agent_sec_cli/observability/schema.py)、
  [writer](../../agent-sec-cli/src/agent_sec_cli/observability/writer.py)、
  [双写入口](../../agent-sec-cli/src/agent_sec_cli/observability/__init__.py)。
- [诊断公共组件](../../agent-sec-cli/src/agent_sec_cli/diagnostic_logging.py)、
  [CLI logging](../../agent-sec-cli/src/agent_sec_cli/cli_logging.py)、
  [daemon logging](../../agent-sec-cli/src/agent_sec_cli/daemon/logging.py)。
- [Telemetry writer](../../agent-sec-cli/src/agent_sec_cli/telemetry/writer.py)、
  [门控和路径](../../agent-sec-cli/src/agent_sec_cli/telemetry/config.py)、
  [字段投影](../../agent-sec-cli/src/agent_sec_cli/telemetry/schema.py)。
- [本地 writer 测试](../../tests/unit-test/security_events/test_writer.py)、
  [observability 测试](../../tests/unit-test/observability/test_writer.py)、
  [CLI 日志测试](../../tests/unit-test/test_cli_logging.py)、
  [daemon 测试](../../tests/unit-test/daemon/test_client_server.py)、
  [telemetry 测试](../../tests/unit-test/telemetry/test_writer.py)。
- [OpenClaw JSONL 消费示例](../../openclaw-plugin/tests/e2e/pilot/gateway-probes.mjs)、
  [CLI JSONL E2E](../../tests/e2e/cli/test_observability_record_jsonl_e2e.py)。

### 11.2 ANOLISA telemetry 直接消费者

- [OpsLayout 文件创建与轮转](../../../anolisa/crates/anolisa-core/src/telemetry/ops.rs)。
- [Uploader 文件读取与 SLS 请求](../../../anolisa/crates/anolisa-core/src/telemetry/uploader.rs)。

本次文档整理核对源码和既有测试，不新增运行时实现，也不将未运行的测试记为通过。
