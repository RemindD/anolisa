# PAP、PCP 与 AgentSight 第一阶段接口场景

> 状态：Phase 1 golden contract
> Profile：`agentseccore-canonical-ir/v1alpha1-demo1`

## 1. 边界

用户只向 PAP 提交 `PolicyTemplate`，不提交 Canonical Policy IR：

```text
用户 PolicyTemplate
    → PAP 分配 policyId/revision
    → Template Lowering
    → Canonical Policy IR
    → PCP ReconcilePolicy/ReconcileBinding
    → AgentSight
```

PAP 用户输入不包含 `FileMatcher`、`FileResolution`、Rule、Evidence 或 FailurePolicy。
这些字段由固定版本的 Lowerer 生成。

测试用 `asc-policy-service` 提供 Product Template HTTP 入口：

```http
PUT /api/v1/policies/{policyId}/revisions/{revision}
Idempotency-Key: <operationId>
Content-Type: application/json
```

`fixtures/pap/*.json` 是该接口冻结的 `PolicyTemplate` 请求主体；测试调用方通过 URL
提供 `policyId/revision`，通过 header 提供幂等键。服务据此构造内部
`TemplateEnvelope`。这只是测试/Demo API，不是已冻结的生产 PAP API。

## 2. PAP 输入与翻译结果

| 场景 | 用户输入 | PAP 生成的 Canonical IR |
|---|---|---|
| 高敏文件禁止读取 | [high-sensitivity-read.json](../fixtures/pap/high-sensitivity-read.json) | [canonical-policy-high-sensitive-read.json](../fixtures/canonical-policy-high-sensitive-read.json) |
| 防止文件误删/移动 | [prevent-file-deletion.json](../fixtures/pap/prevent-file-deletion.json) | [canonical-policy-prevent-file-deletion.json](../fixtures/canonical-policy-prevent-file-deletion.json) |
| 低敏信息限制外发 | [low-sensitivity-egress.json](../fixtures/pap/low-sensitivity-egress.json) | [canonical-policy-low-sensitivity-egress.json](../fixtures/canonical-policy-low-sensitivity-egress.json) |

固定翻译规则：

- 高敏读取：用户文件列表 → `FinalObject` → `ResourceOperation::Read + Deny`；
- 防误删：用户文件列表 → `FinalObject` → `NamespaceMutation + Deny`；
- 低敏外发：用户文件列表和可信目的地 → `InformationFlow::Direct + Deny`；
- 含 `*` 或 `?` 的文件值翻译为 bounded glob，否则翻译为 exact path；
- Activation 固定为 `post_attach_allowed`；仅保证 BindingReady 之后发生的事件；
- Runtime failure 固定为 `fail_closed`；
- 高敏读取要求 `operation_denied`；防误删要求 `binding_ready + operation_denied`；
  低敏外发要求 `operation_denied + effect_receipt`。

## 3. PCP → AgentSight 接口场景

真实 AgentSight 要求 Canonical mutation 携带 service credential。测试服务通过
`--agentsight-token-file <PATH>` 在启动时读取 token，`HttpAgentSightClient` 对下列四个
Canonical 接口统一设置：

```http
Authorization: Bearer <token>
```

token 文件和 header 属于传输认证，不进入 Canonical JSON body，也不进入 golden fixture。
连接无需认证的 mock 时可以省略该启动参数。

### 3.1 创建高敏 Policy

```http
PUT /api/enforcement/v1/policies
```

- 输入：[policy-present-high.request.json](../fixtures/pcp-agentsight/policy-present-high.request.json)
- 输出：[policy-present-high.response.json](../fixtures/pcp-agentsight/policy-present-high.response.json)
- 结果：`AVAILABLE`；目标相关编译延迟到 Binding。

### 3.2 创建低敏外发 Policy

```http
PUT /api/enforcement/v1/policies
```

- 输入：[policy-present-low-egress.request.json](../fixtures/pcp-agentsight/policy-present-low-egress.request.json)
- 输出：[policy-present-low-egress.response.json](../fixtures/pcp-agentsight/policy-present-low-egress.response.json)
- 结果：Policy Schema/Profile 合法，因此为 `AVAILABLE`；这不代表任何具体 PEP 已支持
  `Direct InformationFlow`。

### 3.3 Binding 精确映射并激活

```http
PUT /api/enforcement/v1/bindings
```

- 输入：[binding-exact.request.json](../fixtures/pcp-agentsight/binding-exact.request.json)
- 输出：[binding-exact.response.json](../fixtures/pcp-agentsight/binding-exact.response.json)
- 结果：mock PEP 返回逐 Rule、Atom 和 Guarantee 的 `EXACT`，最终
  `BINDING_READY`。

此正向 fixture 使用 `mock-pep-v1`。在 ActPlane capability spike 完成前，不得把它改成
真实 ActPlane 的 `EXACT` 能力声明。

### 3.4 Direct Flow 在目标 ActPlane 上不支持

```http
PUT /api/enforcement/v1/bindings
```

- 输入：[binding-direct-flow-unsupported.request.json](../fixtures/pcp-agentsight/binding-direct-flow-unsupported.request.json)
- 输出：[binding-direct-flow-unsupported.response.json](../fixtures/pcp-agentsight/binding-direct-flow-unsupported.response.json)
- 结果：`UNSUPPORTED` Mapping、Binding `REJECTED`、无 Target digest、无 PEP attach。

### 3.5 删除 Policy

```http
PUT /api/enforcement/v1/policies
```

- 输入：[policy-absent.request.json](../fixtures/pcp-agentsight/policy-absent.request.json)
- 输出：[policy-absent.response.json](../fixtures/pcp-agentsight/policy-absent.response.json)
- 结果：`ABSENT`。

### 3.6 查询 State

```http
GET /api/enforcement/v1/state?operationId=policy-high-op-1
```

- 输出：[state-policy-available.response.json](../fixtures/pcp-agentsight/state-policy-available.response.json)
- 包含 Service、CapabilitySnapshot、Operation 和当前 Policy 记录。

### 3.7 拉取 Receipt

首次：

```http
GET /api/enforcement/v1/receipts?limit=100
```

续拉：

```http
GET /api/enforcement/v1/receipts?cursor=cursor%3A3&limit=100
```

- 输出：[receipts-three-types.response.json](../fixtures/pcp-agentsight/receipts-three-types.response.json)
- 同时覆盖 Deployment、Enforcement 和 Effect Receipt；Receipt 不包含文件内容或敏感
  数据。

## 4. 固定规则

- `(policyId, revision)` 不可变；相同身份不同内容必须冲突；
- `operationId` 相同且 body 相同为幂等请求，相同 ID 不同 body 必须冲突；
- `payloadDigest` 在规范化算法冻结前不作为必填项；请求可省略，响应示例为 `null`；
- `ReconcilePolicy AVAILABLE` 只表示 IR 可保存和引用，不表示 Binding 已映射或激活；
- PCP 在调用 ReconcilePolicy 前完成多 Policy 组合；Binding 只引用一份不可变的
  Effective Policy Snapshot，不向 AgentSight提交 Source Policy 列表；
- 只有完整关联并通过 Mapping 门禁的 `BINDING_READY` 才表示可以释放 Worker；
- 第一阶段 Binding 只覆盖 root 和绑定后的 future members；不声明覆盖绑定前已经存在的
  子进程，也不追溯绑定前的行为；
- `WIDER/INCOMPARABLE/UNSUPPORTED/INVALID` 不允许激活；
- `NARROWER` 必须使用新的 operationId，并携带与聚合 Mapping digest 一致的显式批准；
- 修改任何 fixture 必须同步修改 Rust 类型/Lowerer，并通过
  `contract_fixtures.rs` round-trip 和语义校验。
