# Canonical Policy IR 第一阶段实现与 Demo 交付计划

> 状态：Phase 1 实施基线  
> 日期：2026-08-19  
> 实现语言：Rust

> SecCore 实施进度：S1、S2、S3 的第一阶段代码已落到 `v2/`，包括共享合同、三类
> Template Lowering、Policy 组合、持久化 PCP controller、AgentSight HTTP client、
> Mapping 门禁和 Receipt cursor。真实闭环仍等待 AgentSight A0～A4。

## 1. 目标

第一阶段以《Canonical Policy IR 设计》为语义基线，在 AgentSecCore（以下简称
SecCore）与 AgentSight 之间跑通一个真实、可验证的策略执行闭环：

```text
Policy Template
    → Canonical Policy IR
    → Effective Policy Snapshot
    → ReconcilePolicy
    → ReconcileBinding + BindingScope
    → AgentSight Profile/Capability Mapping
    → ActPlane Target Bundle / DSL
    → BPF-LSM 执行
    → Receipt / State 回传
```

第一阶段的成功标准不是让 ActPlane 支持全部 IR 语义，而是同时证明：

1. 已支持语义能够被真实编译、激活并在内核阻断；
2. 未支持语义会得到明确的 `UNSUPPORTED`、`WIDER` 或 `INCOMPARABLE`，不会静默降级；
3. Policy、Binding、Mapping、执行状态和回执可以端到端关联和对账；
4. 重复调用、失败和未知状态不会被误报为策略已经生效。

## 2. 当前基础

### 2.1 SecCore

`v2` 当前只有 `asc-policy-types`，已经具备 Policy、Binding、Scope、Mapping、Receipt
等契约雏形，但还没有：

- Canonical Policy IR 的最终数据结构；
- Policy Template Lowering；
- Effective Policy 组合；
- PCP 状态存储和 reconcile controller；
- AgentSight client；
- Demo 生命周期控制程序。

第一阶段需要把现有具体 Policy 联合重构为 Canonical Policy IR 合同，并在其上增加
SecCore 控制面实现。

### 2.2 AgentSight

AgentSight 已经具备可复用的执行基础：

- Actix HTTP 服务和本地 enforcement API；
- `agentsight-enforcer` 独立特权进程；
- 版本化 UDS enforcement protocol；
- ActPlane adapter 和固定 revision；
- PID/start-time 校验、attach/detach、binding 状态机；
- violation/security event 采集和 SQLite 审计存储；
- 已在 Linux 上验证的文件打开阻断链路。

因此第一阶段不新建执行框架，而是在现有链路前增加 Canonical IR API、Profile
校验、Mapping 和 IR-to-ActPlane adapter，在现有链路后增加标准 Receipt/State 视图。

## 3. 第一阶段范围

### 3.1 必须实现

- 严格的 `PolicyEnvelope` 与 `CanonicalPolicyIr` Wire 合同；
- `ResourceSet`、`RuleIr`、`SemanticAtom`、`RuleOutcome`、`RuleEnforcement`；
- `BindingScope` 和可信 Runtime Context；
- `ResourceOperation` Atom；
- `InformationFlow` Atom 的结构、校验和能力拒绝路径；
- V1 Profile 校验；
- Policy revision 不可变和 operationId 幂等；
- ReconcilePolicy/ReconcileBinding 两阶段 Mapping；
- Policy/Binding desired-current 状态；
- Deployment/Enforcement/Effect Receipt；
- Mock PEP 闭环和至少一个真实 ActPlane/BPF-LSM 阻断闭环；
- attach、重复调用、detach、Unsupported、stale PID 和执行失败测试。

### 3.2 第一阶段限制

- 正向 Demo 只要求一个 Effective Policy、一个 Binding、一个目标 PEP；
- 多 Policy 组合实现固定的单调收紧算法，但不作为主 Demo 场景；
- V1 `Expression` 只允许 `Atom` 和同一决策事件内的受限 `All`；
- V1 只产生限制性 `Deny`，不授予 Permission；
- V1 `InformationFlow` 只允许 `Direct`；`Derived` 作为未来枚举保留，但在 V1
  Policy 校验阶段直接拒绝；
- 当前 ActPlane 不支持的 Atom 必须明确拒绝；
- `payloadDigest` 不作为第一阶段功能闭环的主键或激活前置条件；如请求携带摘要，
  必须按已经冻结的算法校验；
- 不实现通用 PDP、任意脚本 Predicate、任意布尔表达式、优先级覆盖和动态用户函数；
- 不改造 AgentSight 现有观测管线，不引入新的 ActPlane 源码副本。

## 4. 开工门禁

以下内容必须在 M0 契约冻结时确定，否则不能对外宣称 V1 已经支持：

### 4.1 Demo 正向 Atom

当前已验证的 ActPlane Profile 能够阻止文件打开，但尚未证明它等价覆盖 Canonical
IR 中完整的 `Read`、`NamespaceMutation` 或 `Direct InformationFlow`。

首先完成 capability spike，并在以下方案中选择一个：

1. 证明现有文件打开拦截在选定 Activation、Scope 和 FileResolution 下可等价实现
   V1 `Read`；
2. 将 V1 正向 Atom 收窄为语义明确的 `FileReadAdmission`；
3. 扩展 ActPlane Profile，使其完整实现已定义的 `Read`。

不得把只能覆盖部分读取路径的实现报告为 `EXACT`。

### 4.2 V1 Profile 身份

第一阶段使用不可变 Profile 标识，例如：

```text
agentseccore-canonical-ir/v1alpha1-demo1
```

同一标识的 Atom、Expression、资源匹配、Guarantee 和限制不得变化。语义发生变化时
创建新 Profile 标识，不能复用旧标识。

### 4.3 InformationFlow

V1 只接受 `Direct`。SecCore Lowerer 不产生 `Derived`，Canonical IR Validator 对 V1
Policy 中的 `Derived` 返回 `Invalid`。`Derived` 仅保留为未来 Profile 的枚举值；在新
Profile 冻结前不能进入 ReconcileBinding。具体目标无法可靠建立 Direct Source 与
Destination 关系时，在 Binding 阶段返回 `Unsupported`。

### 4.4 FailurePolicy 合并

冻结逐项合并表。第一阶段至少覆盖：

- `BeforeWorkerStart` 强于 `PostAttachAllowed`；
- 硬阻断要求 `PreEffect`；
- 不兼容的 Runtime/Update FailurePolicy 拒绝组合；
- `AuditOnly` 不得满足硬阻断 Policy；
- Demo 使用 `PostAttachAllowed + FailClosed`，只保证 BindingReady 后的事件；更新失败保持
  last-known-good 或拒绝激活。

### 4.5 规范化与摘要

第一阶段允许不提供 `payloadDigest`。如果启用摘要，必须同时固定：

- 确定性序列化算法；
- 哪些列表是集合、哪些列表有序；
- 集合排序键；
- 重复项处理；
- 摘要算法和 Wire 前缀。

在这些规则冻结前，不能使用摘要相等代替语义相等。

## 5. 双方职责边界

| 职责 | SecCore | AgentSight |
|---|---|---|
| Policy Template 定义 | 负责 | 不感知 |
| Template → Canonical IR | 负责 | 不负责 |
| 多 Policy 单调组合 | 负责 | 不组合 Source Policy |
| Canonical IR Schema/Profile 防御性校验 | 负责 | 必须重复校验 |
| Scope/Binding 选择 | 负责 desired state | 验证可信运行时身份 |
| PEP capability 和最终 Mapping | 消费结果、审批 | 负责 |
| IR → Target Bundle/DSL | 不负责 | 负责 |
| BPF/LSM attach/detach | 不负责 | 负责 |
| Desired state | 权威来源 | 持久化请求副本 |
| Actual enforcement state | 消费和对账 | 权威来源 |
| 执行 Receipt | 拉取和归档 | 产生并持久化 |

AgentSight 只依赖共享 Canonical IR 合同，不依赖 SecCore 的 Template、Lowerer、存储或
控制循环。SecCore 不依赖 ActPlane DSL、BPF map 或 AgentSight 内部 Target Bundle。

## 6. 共享契约

`asc-policy-types` 继续作为唯一共享 Wire crate，双方不得复制结构定义。第一阶段需要
在该 crate 中固定：

- `PolicyEnvelope` / `CanonicalPolicyIr`；
- V1 Profile 和 Atom/Expression 类型；
- Resource selector 和严格路径语义；
- `BindingScope` / Runtime Context；
- ReconcilePolicy/ReconcileBinding request/response；
- CapabilitySnapshot / MappingReport；
- State / Receipt / Error；
- identifier、revision 和 cursor 类型；
- `Validate` 跨字段校验。

要求：

- 所有安全语义对象拒绝未知字段、重复字段、未知枚举和类型不匹配；
- Wire enum 使用穷举匹配；
- Resource/Rule 引用必须存在；
- operation 与 resource kind 组合必须合法；
- Profile 限制 Rule 数量、Atom 数量和 Expression 深度；
- 提供双方共同消费的 golden JSON fixtures 和错误 fixtures。

第一阶段可在 monorepo 中使用 path dependency；后续发布时再决定独立 crate 版本或固定
Git revision，但不能在两个仓库中维护副本。

## 7. SecCore 工作计划

### S1. Canonical IR 类型与校验

重构 `asc-policy-types`：

- 移除具体 Policy 类型作为 PCP-AgentSight 固定联合的做法；
- 增加 Canonical IR Envelope/Payload；
- 完成 V1 Profile、Resource、Rule、Atom、Outcome、Enforcement；
- 对齐 Scope、Mapping、State、Receipt 和 Reconcile API；
- 增加 round-trip、unknown-field、非法引用、非法组合和版本拒绝测试。

交付物：共享 crate、JSON fixtures、Wire/Validate 测试。

### S2. Policy Lowering Engine

建议新增 `asc-policy-engine`：

```text
Template Parser
    → Template Validator
    → Policy Lowerer
    → Canonical IR Validator
    → Effective Policy Composer
```

第一阶段至少提供：

- 高敏文件禁止读取 Template；
- 文件防误删 Template，Lowering 为 `NamespaceMutation + Deny`；
- 低敏信息外泄 Template，Lowering 为 `InformationFlow`，用于 Unsupported 负向路径；
- 单 Policy Snapshot；
- 多 Policy Rule 合并、局部 ID 重映射、Activation 合并和 FailurePolicy 合并；
- 相同 policyId/revision 对应不同内容时拒绝。

### S3. PCP Store 与 Controller

建议新增 `asc-pcp`：

- 保存 Policy Template、Canonical IR、Effective Snapshot；
- 保存 Binding desired state、operationId 和 AgentSight observed state；
- 实现 AgentSight HTTP client；
- ReconcilePolicy/ReconcileBinding 幂等重试；
- UNKNOWN 后通过 GetState 对账，不能盲目重放不同操作；
- 持久化 PullReceipts cursor，按 receiptId 去重；
- 对 `NARROWER` 实现显式批准；
- 对 `WIDER/INCOMPARABLE/UNSUPPORTED/INVALID` 拒绝激活；
- 第一阶段使用 SQLite 或单进程持久化存储，不引入分布式一致性。

### S4. Demo Runner

新增 Rust Demo runner，证明对已运行进程的 `PostAttachAllowed`：

1. 创建专用临时目录和测试文件；
2. 启动 Worker，并记录绑定前行为不在保证范围内；
3. 获取 PID、start time、cgroup 和 namespace identity；
4. 创建 Policy 和 Binding；
5. 等待 AgentSight 返回 `BINDING_READY`；
6. 成功后执行受保护操作，失败则终止 Worker；
7. Worker 执行受保护操作；
8. 查询 State 和 Receipt；
9. 删除 Binding 并验证操作恢复；
10. 清理全部临时资源。

## 8. AgentSight 工作计划

### A0. Capability Spike

在正式开发前用现有 ActPlane adapter 验证：

- 文件打开拦截的操作覆盖；
- read-only/open mode 差异；
- PathEntry/FinalObject、symlink 和 hardlink 行为；
- PostAttachAllowed 下 root、绑定后子进程和跨 exec 的覆盖边界；
- 正确的 `EXACT/NARROWER/WIDER/INCOMPARABLE/UNSUPPORTED`；
- 当前 Profile 是否需要新增 BPF hook 或 IR Atom。

输出一份机器可测试的 capability fixture，作为 V1 Profile 和 Demo 场景的依据。

### A1. Enforcement V1 API

在现有 `/api/enforcement/*` 旁新增目标接口：

```text
PUT /api/enforcement/v1/policies
PUT /api/enforcement/v1/bindings
GET /api/enforcement/v1/state
GET /api/enforcement/v1/receipts
```

要求：

- 外部接口只接收 Canonical IR，不接受 ActPlane DSL；
- `ReconcilePolicy` 只做 Schema、Profile、不可变 revision 和静态能力检查；
- `ReconcilePolicy` 不返回依赖 Scope 的最终 Mapping；
- `ReconcileBinding` 验证真实 PID/start-time/cgroup/namespace；
- `ReconcileBinding` 完成目标编译、最终 Mapping、批准校验和 attach；
- `GetState` 返回 desired/current、capability snapshot、Mapping 和错误；
- `PullReceipts` 使用单调 cursor 分页；
- operationId 重复且内容一致时幂等，不一致时冲突。

现有 raw DSL API 可以保留为内部或兼容路径，但 PCP 和 Demo 不直接调用它。

### A2. IR Profile Validator 与 PEP Adapter

新增独立的 AgentSight policy compiler/adapter 模块：

```text
Canonical IR
    → Strict Decode + Validate
    → V1 Profile Check
    → Scope/Runtime Resolution
    → Capability Mapping
    → Target Plan / ActPlane DSL
    → MappingReport
```

约束：

- 模块不负责 HTTP、SQLite 和 reconcile 生命周期；
- 每个 Atom、Expression、Guarantee 都必须产生显式 Mapping；
- obligations、remediation 和 evidence 不能只用允许行为集合推导，必须单独检查；
- 未实现 Atom 返回 `UNSUPPORTED`；
- 部分覆盖不得返回 `EXACT`；
- Target Bundle/DSL 只存在于 AgentSight/enforcer 内部。

### A3. Enforcer Protocol 与 ActPlane 接入

复用当前 `agentsight-enforcer` 和 UDS：

- 增加 Canonical Policy prepare/apply 命令，或由内部 adapter 生成 DSL 后复用
  `ApplyPolicyLeased`；
- 保留 peer credential、frame size、protocol version 和 stale PID 校验；
- required evidence subscription 未就绪时不能激活；
- 只有 ActPlane 确认 attach 后才能返回 `BINDING_READY`；
- 保存 target digest、ActPlane revision、rule/atom mapping；
- detach 必须等待后端确认；
- enforcer 重启后对 desired/current binding 做对账。

### A4. Store、State 与 Receipt

在现有 SQLite/audit 基础上增加：

- immutable policy revision；
- operation idempotency record；
- effective binding desired/current state；
- capability snapshot；
- MappingReport；
- Target Bundle digest 和 PEP instance；
- receipt sequence、receiptId 和 cursor。

把现有 binding acknowledgement、violation 和 security event 归一为：

- Deployment Receipt：编译、安装、BindingReady、detach；
- Enforcement Receipt：Rule/Atom 命中和 requested decision；
- Effect Receipt：内核实际结果，例如 `EPERM/blocked`。

Receipt 不包含文件内容或敏感数据，只保留标识、摘要、规范化操作和实际结果。

## 9. 联合交付顺序

### M0. Contract/Profile Freeze

- 完成 A0 capability spike；
- 冻结 Demo 正向 Atom；
- 冻结 Profile 标识和支持矩阵；
- 冻结四个 API 的 JSON fixtures；
- 冻结 FailurePolicy 合并表；
- 决定 payloadDigest 是否启用；
- 双方 contract tests 使用同一 fixtures。

退出条件：双方可以独立解析全部 fixture，并对非法 fixture 返回一致错误分类。

### M1. Mock End-to-End

- SecCore Lowering、Store、Controller 可运行；
- AgentSight V1 API、Store、Compiler 和 mock backend 可运行；
- 跑通 Policy → Binding → State → Receipt → Detach；
- 跑通幂等冲突、Unsupported、stale PID 和 backend failure。

退出条件：不依赖 root/BPF 的 CI 测试稳定通过。

### M2. Real ActPlane End-to-End

- 使用固定 ActPlane revision 和认可的 Profile；
- 在专用 Linux 环境运行 Demo runner；
- 真实受保护操作返回 `EPERM`；
- AgentSight 返回对应 Effect Receipt；
- detach 后操作恢复；
- V1 非法的 Derived policy 在 ReconcilePolicy 前被明确拒绝；目标不支持 Direct 时，
  Binding 返回 Unsupported。

退出条件：真实内核结果、Binding、Policy、Rule、Atom 和 Receipt 可完整关联。

### M3. Reconciliation and Failure Hardening

- AgentSight/enforcer 重启对账；
- PCP 超时/UNKNOWN 查询恢复；
- cursor 续拉和 receipt 去重；
- 同 operationId 冲突拒绝；
- failed/degraded 不显示为 ready；
- Demo 异常路径自动清理。

### M4. Demo Packaging

- 一键构建和启动脚本；
- 示例 Policy Template；
- Demo Worker；
- 一键执行和清理脚本；
- 操作手册、预期输出和已知限制；
- Mock Demo 和 Linux ActPlane Demo 两种模式。

## 10. Demo 验收流程

正向流程：

```text
1. SecCore 创建高敏文件 Policy Template
2. Lowering 为 Canonical Policy IR
3. ReconcilePolicy 返回 VALID/AVAILABLE
4. Demo Runner 启动暂停 Worker
5. SecCore 创建 BindingScope 并调用 ReconcileBinding
6. AgentSight 完成 Runtime 校验、Mapping、ActPlane attach
7. 返回 BINDING_READY 后 Runner 释放 Worker
8. Worker 执行受保护操作并得到 EPERM
9. PullReceipts 返回 OperationDenied 和实际 Effect Receipt
10. GetState 返回一致的 Policy、Binding、Mapping 和 current state
11. ReconcileBinding(ABSENT) 后同一操作恢复成功
```

负向流程：

- 相同 operationId、相同 body：幂等返回当前结果；
- 相同 operationId、不同 body：返回 conflict；
- 相同 policyId/revision、不同 payload：返回 revision conflict；
- stale PID/start-time：拒绝 Binding；
- V1 `InformationFlow::Derived`：Policy 校验返回 Invalid，不进入 Binding；
- 目标无法实现 `InformationFlow::Direct`：Binding 返回 Unsupported 并拒绝激活；
- invalid Profile/unknown field：拒绝 Policy；
- enforcer 不可用：不得返回 BindingReady；
- receipt stream 丢失：状态进入 degraded，不能伪造完整证据。

## 11. 测试矩阵

### 11.1 共享契约

- serde round-trip；
- unknown/duplicate field；
- invalid enum/version/profile；
- duplicate/missing references；
- resource-operation 非法组合；
- Profile expression 限制；
- stable validation path/code。

### 11.2 SecCore

- Template Lowering golden tests；
- Effective Policy 单调组合；
- ID 重映射和冲突；
- FailurePolicy 合并；
- controller retry/UNKNOWN/idempotency；
- receipt cursor 恢复。

### 11.3 AgentSight

- ReconcilePolicy/ReconcileBinding API contract；
- operation/revision conflict；
- profile/capability mapping；
- scope/runtime identity mismatch；
- mock attach/detach/restart；
- receipt ordering/dedup/pagination；
- error-to-state 映射。

### 11.4 Linux

- 真实 attach 和 BPF-LSM deny；
- blocked result 与 Effect Receipt 一致；
- detach 后恢复；
- stale PID；
- invalid target DSL；
- enforcer restart reconciliation；
- symlink/hardlink/path resolution capability cases。

## 12. 完成标准

第一阶段只有同时满足以下条件才算完成：

- SecCore 与 AgentSight 使用同一 Canonical IR crate 和 fixtures；
- 外部 API 不暴露 ActPlane DSL；
- ReconcilePolicy 与 ReconcileBinding 的职责分离；
- 只有最终 Mapping 通过且后端确认后才进入 BindingReady；
- 至少一个语义通过真实 BPF-LSM 阻断；
- 不支持语义明确拒绝；
- 内核实际结果可通过 Receipt 查询；
- Policy、Scope、Binding、Mapping、Target 和 Receipt 可关联；
- detach 后执行状态真实恢复；
- Mock 测试进入常规 CI；
- Linux E2E 有可重复运行和清理的脚本；
- 文档列出 Profile 能力边界，不宣称未验证能力。

## 13. 代码量估算

以下为新增/修改的人工代码估算，不包含生成代码、构建产物和第三方代码：

| 部分 | 生产代码 | 测试/Fixture |
|---|---:|---:|
| 共享 IR 契约与校验 | 1,200～1,800 | 600～1,000 |
| SecCore Lowering/组合 | 1,000～1,500 | 600～1,000 |
| SecCore Controller/存储/Client | 1,500～2,300 | 800～1,200 |
| Demo Runner/CLI | 300～600 | 200～400 |
| AgentSight V1 API/状态存储 | 1,200～1,800 | 700～1,100 |
| IR → ActPlane Adapter/Mapping | 1,000～1,600 | 800～1,200 |
| Enforcer protocol 与 Receipt | 700～1,200 | 500～900 |
| E2E/脚本/Fixture | — | 800～1,200 |

总量约为：

- SecCore：5,500～8,000 行；
- AgentSight：4,500～7,000 行；
- 合计：10,000～16,000 行。

如果 capability spike 证明需要新增 ActPlane/BPF hook，预计额外增加 1,500～3,000 行
代码和对应 Linux 测试。

## 14. 主要风险与控制

| 风险 | 控制措施 |
|---|---|
| IR `Read` 与现有 file-open hook 不等价 | A0 先验证，收窄 Atom 或扩展后端，不错误返回 Exact |
| Derived 信息流不属于 V1 | SecCore 校验阶段拒绝；目标 Direct 能力缺失在 Binding 阶段返回 Unsupported |
| Scope 与实际 PID/namespace 不一致 | AgentSight 从 `/proc` 和内核身份重新验证 |
| PostAttach 错误声明历史或既有子进程覆盖 | Scope 固定 `includeExistingMembers=false`，Demo 只验证 BindingReady 后事件 |
| AgentSight API 与现有 raw DSL API 混用 | 新建 `/api/enforcement/v1`，PCP 禁止提交 DSL |
| 只记录请求而没有真实执行证据 | BindingReady 依赖后端确认，Effect Receipt 记录实际 errno/result |
| 多 Policy FailurePolicy 不可比较 | 使用冻结合并表；不能证明兼容时拒绝组合 |
| Schema 演进导致旧实现忽略安全字段 | 严格解码；安全语义变化提升 Schema/Profile |
| Digest 规则未冻结 | 第一阶段不作为功能主键；启用前先冻结 canonicalization |
| Linux/ActPlane 环境不稳定 | Mock CI 与隔离 Linux E2E 分层，固定 ActPlane revision/Profile |

## 15. 推荐代码布局

SecCore：

```text
v2/crates/asc-policy-types/    # 唯一共享 Wire contract
v2/crates/asc-policy-engine/   # Template lowering、组合、校验
v2/crates/asc-pcp/             # Store、controller、AgentSight client
v2/crates/asc-policy-service/  # 测试用常驻 HTTP 服务和后台 reconcile
v2/crates/asc-policy-demo/     # Demo runner/worker/CLI
v2/tests/fixtures/             # 双方共享 golden JSON
```

AgentSight：

```text
crates/agentsight-policy-compiler/  # IR Profile、Mapping、Target Plan
crates/enforcement-protocol/        # UDS protocol 扩展
crates/agentsight-enforcer/         # ActPlane adapter 与真实执行
crates/agentsight-audit/            # State/Receipt 持久化
src/server/enforcement.rs           # `/api/enforcement/v1` HTTP 边界
integration-tests/                  # Mock/Linux E2E
```

具体 crate 是否单独拆分可以在 M0 确定，但依赖方向必须保持：Template 层不能进入
AgentSight，ActPlane 类型不能进入共享 IR 或 SecCore。
