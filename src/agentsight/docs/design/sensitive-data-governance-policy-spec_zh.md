# AgentSecCore 敏感数据治理策略语义规范

版本：1.0

## 1. 目的

本规范定义 AgentSecCore 对敏感文件的两种防外泄策略语义：

1. **高敏数据禁止进入上下文**（`deny_context_admission`）
2. **中敏数据必须经统一治理 Gateway 外发**（`require_governance_gateway`）

本规范只定义产品层策略模型、判断规则、状态传播、冲突处理、失败行为和审计结果，
不规定具体的内核机制、代理机制、网络重定向方式或策略 DSL 语法。

低敏数据的全局基线策略不在本规范范围内。

### 1.1 规范归属与参考边界

本规范的归属方、策略执行方和最终实现目标均为 **AgentSecCore**。

AgentSight 仅作为以下设计原则的参考实现：

- 使用稳定、类型化的产品策略表达；
- 使用不可变的 policy ID 和 revision；
- 在策略生效前完成有界、失败关闭的校验；
- 区分策略请求的决策与实际观察到的执行结果；
- 使用不包含敏感内容的最小化审计事件。

本规范不继承 AgentSight 的 UDS command、`ApplyCredentialPolicy`、ActPlane DSL、
`PolicyMode` 或其他 wire protocol。除非 AgentSecCore 的后续接口规范明确声明，
本规范中的字段名也不构成与 AgentSight 协议的序列化兼容承诺。

## 2. 规范性术语

本文使用以下规范性术语：

- **必须（MUST）**：符合本规范的实现必须满足。
- **不得（MUST NOT）**：符合本规范的实现不得违反。
- **应该（SHOULD）**：除非存在明确并可审计的理由，否则应满足。
- **可以（MAY）**：可选能力。
- **拒绝（deny）**：目标操作不得成功。
- **允许（allow）**：本策略不阻止操作，不代表其他策略也允许。

## 3. 概念定义

### 3.1 受保护主体

受保护主体（Protected Subject）是策略约束的 Agent 执行实体，可以是：

- 一个 Agent 进程树；
- 一个 Agent session；
- 一个稳定的 Agent identity；
- 一组满足主体选择器的 Agent。

主体选择器只决定策略作用范围，不改变敏感数据本身的级别。

### 3.2 敏感资源

敏感资源（Sensitive Resource）是被资源选择器匹配的文件。资源具有以下敏感级别：

```text
high
medium
```

### 3.3 Agent 上下文

Agent 上下文是 Agent 在推理、生成模型请求、选择工具或构造外发请求时能够访问的信息集合，
包括但不限于：

- system、developer、user 或 assistant message；
- prompt 和模型请求输入；
- 工具调用结果；
- Agent 工作记忆；
- session memory；
- 子 Agent 或子进程接收的数据；
- 可用于后续推理或生成请求的其他数据结构。

仅观察到文件路径、资源 ID、操作类型或访问结果等最小化元数据，不等同于文件内容进入上下文。

### 3.4 上下文接纳

上下文接纳（Context Admission）是敏感资源内容首次进入受保护主体上下文的行为。

对于文件资源，受保护主体发起能够获得文件内容的操作时，必须视为一次上下文接纳尝试，
除非系统能够证明读取结果不会被主体或其派生执行访问。

### 3.5 数据 lineage

数据 lineage 是敏感资源、上下文、派生执行和外发请求之间的可追溯关联。

lineage 至少包含：

- 策略 ID 和 revision；
- 资源 ID；
- 敏感级别；
- 受保护主体；
- 唯一 lineage ID。

lineage 不得包含敏感资源内容。

### 3.6 派生请求

如果一个请求的内容、参数、工具选择、目的地选择或发送决策直接或间接受中敏数据影响，
该请求就是中敏数据的派生请求。

本规范采用保守传播语义：

> 当系统无法证明一个请求与当前上下文中的中敏数据无关时，必须将其视为派生请求。

### 3.7 外发请求

外发请求（Egress Request）是离开受保护主体信任边界的请求，包括但不限于：

- LLM API 请求；
- HTTP 或 HTTPS 请求；
- RPC 请求；
- 远程 MCP 调用；
- WebSocket 建连或消息；
- 策略列入治理范围的其他网络请求。

纯本地计算、本地文件操作和策略明确排除的本地 IPC 默认不属于外发请求。

### 3.8 治理 Gateway

治理 Gateway 是中敏数据派生请求唯一允许的治理出口。Gateway 负责：

- 内容检查；
- 数据脱敏或转换；
- 目的地策略判断；
- 用户或组织审批；
- 请求准入或拒绝；
- 合规审计；
- 在允许时向最终目的地转发请求。

请求正常进入 Gateway 不属于数据外泄风险。

## 4. 策略文档模型

策略文档的顶层结构如下：

```yaml
spec_version: "1.0"
kind: sensitive_data_governance

metadata:
  id: string
  revision: integer
  description: string

subjects:
  agents: []
  sessions: []
  process_scope: process_tree

resources: []
gateways: []

defaults:
  unmatched_resources: allow
  unknown_lineage: fail_closed
  unavailable_gateway: deny
```

## 5. 顶层字段语义

### 5.1 `spec_version`

必须为：

```yaml
spec_version: "1.0"
```

`spec_version` 标识本文定义的策略语义版本，不表示 AgentSight 或 AgentSecCore
现有 wire protocol 的版本。

### 5.2 `kind`

必须为：

```yaml
kind: sensitive_data_governance
```

`kind` 是本规范定义的策略族判别符。它与 AgentSecCore 现有策略中使用判别字段的风格一致，
但不是从 AgentSight 当前 enforcement policy 复制的字段。

### 5.3 `metadata.id`

策略的稳定标识符：

- 必须非空；
- 必须在策略管理域内唯一；
- 不得因策略内容更新而改变。

### 5.4 `metadata.revision`

不可变策略版本：

- 必须为大于零的整数；
- 相同 `metadata.id + metadata.revision` 必须对应完全相同的规范化策略内容；
- 修改主体、资源、Gateway、控制方式或默认行为时必须使用新的 revision。

### 5.5 `subjects`

`subjects` 定义策略保护的 Agent 范围：

```yaml
subjects:
  agents:
    - qoder
    - claude-code
  sessions: []
  process_scope: process_tree
```

语义如下：

- `agents` 为空表示主体由策略绑定过程指定；
- `sessions` 为空表示选中 Agent 的所有 session；
- `process_scope: process_tree` 表示主体及其派生子进程受相同策略约束；
- 无关 Agent 和无关进程树不得继承该主体的敏感数据状态。

## 6. 资源规则

每个资源规则包含资源身份、敏感级别、资源选择器和控制方式：

```yaml
resources:
  - id: production-private-keys
    sensitivity: high
    selectors:
      files:
        - /workspace/secrets/signing-key.pem
    control:
      type: deny_context_admission
```

### 6.1 资源 ID

`resources[].id`：

- 必须非空；
- 必须在一个策略 revision 内唯一；
- 必须稳定用于审计、决策解释和事件关联。

### 6.2 文件选择器

`selectors.files`：

- 必须至少包含一个文件模式；
- 必须匹配规范化后的文件身份；
- 符号链接和等价路径不得用于绕过匹配；
- 同一文件匹配多条规则时，必须按照第 12 节处理冲突。

### 6.3 敏感级别和控制类型

有效组合只有：

| `sensitivity` | `control.type` | 产品语义 |
|---|---|---|
| `high` | `deny_context_admission` | 禁止内容进入 Agent 上下文 |
| `medium` | `require_governance_gateway` | 允许进入上下文，但派生外发必须经过 Gateway |

任何其他组合都必须在策略生效前被拒绝。

## 7. 高敏策略：禁止进入上下文

### 7.1 策略结构

```yaml
sensitivity: high
control:
  type: deny_context_admission
  deny_operations:
    - read
    - map_read
  reason: High-sensitivity content must not enter Agent context
```

`deny_operations` 是声明性操作集合，不限制实现使用更强的方式保证上下文隔离。

### 7.2 核心语义

当受保护主体尝试将匹配资源的内容接纳到 Agent 上下文时：

```text
decision = deny
```

符合本规范的系统必须保证：

1. 高敏文件内容不得进入受保护 Agent 上下文；
2. 被拒绝内容不得出现在模型请求、prompt、工具结果、memory 或派生上下文中；
3. 治理 Gateway 不得覆盖高敏资源的上下文接纳拒绝；
4. 重试、子进程、符号链接或替代读取方式不得降低该保护；
5. 拒绝必须产生可审计的策略决策；
6. 无法可靠判断内容是否会进入上下文时必须拒绝。

### 7.3 允许的最小化操作

策略可以允许不暴露内容的最小化操作，例如：

- 判断文件是否存在；
- 获取经过批准的文件类型或资源分类；
- 记录脱敏后的资源路径；
- 记录访问操作和拒绝结果。

这些操作不得暴露：

- 文件内容；
- 可用于恢复内容的摘要；
- 密钥材料；
- 内容相关的内存片段。

### 7.4 高敏决策结果

高敏接纳尝试被拒绝时产生：

```yaml
decision:
  type: context_admission_denied
  sensitivity: high
  allowed: false
  risk: true
  reason: high_sensitivity_resource
```

该事件表示发生了被策略阻止的高敏访问尝试，不表示数据已经外泄。

## 8. 中敏策略：必须经过治理 Gateway

### 8.1 策略结构

```yaml
sensitivity: medium
control:
  type: require_governance_gateway
  gateway_refs:
    - central-governance
  governed_egress:
    - llm_api
    - http
    - https
    - remote_mcp
  direct_egress: deny
  gateway_unavailable: deny
  lineage_lifetime: process_tree
```

### 8.2 核心语义

受保护主体读取中敏资源时：

1. 读取操作可以成功；
2. 中敏内容可以进入 Agent 上下文；
3. 上下文必须获得该资源对应的中敏 lineage；
4. lineage 必须传播给派生上下文、工具调用和子进程；
5. 携带中敏 lineage 的受治理外发请求必须提交给策略指定的治理 Gateway；
6. 受保护主体不得直接向最终外部目的地发送该请求。

正常处理链路为：

```text
读取中敏文件
    → 中敏内容进入 Agent 上下文
    → 上下文获得 MEDIUM lineage
    → 派生请求提交治理 Gateway
    → Gateway 检查、脱敏、审批或拒绝
    → 允许时由 Gateway 转发到最终目的地
```

### 8.3 正常提交 Gateway

满足以下所有条件时，请求视为进入了有效治理路径：

- 请求提交至策略引用的 Gateway；
- Gateway 的服务身份经过验证；
- 请求携带或由可信边界补充完整的治理上下文；
- Gateway 明确接收请求并执行治理决策；
- 最终外发由 Gateway 控制，而不是由原 Agent 绕过 Gateway 完成。

正常提交结果为：

```yaml
decision:
  type: gateway_submission
  sensitivity: medium
  allowed: true
  risk: false
```

`gateway_submission` 是普通治理事实，不得被记为外发风险。

### 8.4 Gateway 决策

Gateway 必须对请求返回以下标准结果之一：

```text
allow
transform
deny
error
```

| 结果 | 语义 |
|---|---|
| `allow` | 请求通过治理，可以由 Gateway 转发 |
| `transform` | 请求经脱敏或改写后，可以由 Gateway 转发 |
| `deny` | 请求不符合治理要求，不得转发 |
| `error` | 无法可靠完成治理，按照 Gateway 失败策略处理 |

约束如下：

- `allow` 和 `transform` 只授权 Gateway 转发经过治理的请求；
- `deny` 不得被解释为允许 Agent 直接发送原始请求；
- `error` 不得静默降级为直接外发；
- 原始 Agent 不得绕过 Gateway 的最终决策。

### 8.5 绕过 Gateway

以下任一情况构成 `gateway_bypass`：

- 派生请求直接发送到最终外部目的地；
- 请求发送到未经策略授权的代理或 Gateway；
- Gateway 拒绝后改为直接外发；
- 通过子进程、替代协议或新连接绕过治理；
- 请求声称经过 Gateway，但无法验证 Gateway 身份；
- 将中敏数据复制到另一个上下文后丢弃或伪造 lineage；
- 只向 Gateway 发送元数据，而把实际内容直接发送到最终目的地。

当 `direct_egress: deny` 时，系统必须：

1. 阻止绕过请求；
2. 产生 `gateway_bypass_denied` 风险事件；
3. 记录主体、session、资源 lineage、目标和实际阻断结果；
4. 不记录中敏内容本身。

### 8.6 Gateway 不可用

以下情况均视为 Gateway 不可用：

- 无法连接；
- 请求超时；
- Gateway 身份验证失败；
- Gateway 无法返回可靠的治理结果；
- Gateway 声明自身处于降级或不可治理状态。

当策略声明：

```yaml
gateway_unavailable: deny
```

系统必须 fail closed：

- 请求不得直接发送到最终目的地；
- 必须向调用方返回治理不可用结果；
- 必须产生 `gateway_unavailable` 治理事件；
- 不得将该事件错误表述为数据已经外泄。

### 8.7 Lineage 生命周期

默认生命周期为：

```yaml
lineage_lifetime: process_tree
```

语义如下：

- 从中敏内容进入上下文时开始；
- 传播到该上下文派生的 Agent turn、工具调用和子进程；
- 持续到受保护进程树或 session 结束；
- 不得仅因经过固定时间而自动失效；
- 不得因序列化、复制、摘要、格式转换或跨工具调用而自动失效；
- 只有显式、可信且可审计的 declassification 才能提前清除。

本规范 1.0 不定义自动 declassification。

## 9. Gateway 定义

Gateway 定义格式如下：

```yaml
gateways:
  - id: central-governance
    identity:
      service: governance.internal
    endpoints:
      - host: governance.internal
        port: 8443
        protocol: https
    trust:
      require_authenticated_channel: true
```

### 9.1 Gateway ID

- 必须非空；
- 必须在策略内唯一；
- 资源规则只能引用当前策略中已经定义的 Gateway ID。

### 9.2 Gateway 身份

仅目标地址匹配不足以证明 Gateway 身份。有效 Gateway 应同时满足：

- 目标 endpoint 与策略匹配；
- 使用经过认证的安全通道；
- 对端服务身份与策略声明匹配；
- 请求确实进入 Gateway 的治理处理流程。

### 9.3 多 Gateway

一个规则可以引用多个 Gateway，用于高可用、地域或业务隔离。

所有被引用的 Gateway 必须提供等价的最低治理保证。选择备用 Gateway 不得降低：

- 内容检查要求；
- 身份验证要求；
- 审计要求；
- 拒绝和失败处理强度。

## 10. 治理上下文

中敏请求提交 Gateway 时，必须携带或由可信边界补充以下治理上下文：

```yaml
governance_context:
  policy_id: agentsight-sensitive-data-protection
  policy_revision: 1
  resource_ids:
    - customer-records
  sensitivity: medium
  subject:
    agent_id: qoder
    session_id: session-123
  lineage_id: 4c67821b-18ae-46a0-a3e4-8d75335927a6
  request_id: b6342e9c-2830-40ad-8c47-324a0702e180
```

要求如下：

- `lineage_id` 唯一标识敏感数据传播链；
- `request_id` 用于幂等处理和跨系统关联；
- `resource_ids` 必须包含所有影响当前请求的中敏资源；
- Gateway 不得将 Agent 自报信息作为唯一可信依据；
- 治理上下文不得包含敏感文件内容；
- 治理上下文不得包含完整 prompt、凭据或 authorization header。

## 11. Lineage 传播规则

中敏 lineage 必须按照以下规则传播：

1. 一个上下文接纳中敏内容后，该上下文获得对应 lineage；
2. 包含多个中敏资源时，lineage 必须形成资源集合，不得只保留最后一个资源；
3. 从该上下文产生的新 Agent turn 继承 lineage；
4. 工具调用参数受中敏数据影响时，工具执行继承 lineage；
5. 工具结果继续包含或派生自中敏数据时，返回上下文保留 lineage；
6. 派生子进程继承父主体的有效 lineage；
7. 摘要、编码、压缩、加密或格式转换不得自动清除 lineage；
8. 无法确定派生关系时按中敏处理；
9. 不相关主体不得因为系统中存在其他中敏上下文而获得 lineage。

## 12. 冲突与优先级

同一资源或上下文可能匹配多个规则。系统必须执行最严格的有效结果。

优先级为：

```text
deny_context_admission
    >
require_governance_gateway
    >
allow
```

具体规则：

1. 同一资源同时匹配高敏和中敏规则时，必须按高敏处理；
2. 任一规则要求拒绝上下文接纳时，Gateway 例外无效；
3. 多条中敏规则命中时，请求必须同时满足全部适用的治理约束；
4. 多条中敏规则的 Gateway 集合没有共同有效出口时，请求必须拒绝；
5. 未知或无法解析的敏感级别不得自动降级为普通数据；
6. `allow` 规则不得覆盖高敏或中敏规则。

## 13. 默认行为

推荐默认值为：

```yaml
defaults:
  unmatched_resources: allow
  unknown_lineage: fail_closed
  unavailable_gateway: deny
```

语义如下：

- 未匹配任何资源规则的文件不受本策略限制；
- 已知上下文存在敏感数据，但无法确定具体 lineage 时，必须按中敏治理；
- 无法证明请求经过有效 Gateway 时，必须视为未经过 Gateway；
- Gateway 不可用时不得静默直接连接最终目的地；
- 策略状态未知时不得报告数据已经得到保护。

## 14. 决策和事件分类

### 14.1 普通治理事实

以下情况不是风险事件：

- 中敏文件被允许读取；
- 中敏上下文成功建立 lineage；
- 中敏请求成功提交有效 Gateway；
- Gateway 对请求执行脱敏后允许；
- Gateway 正常拒绝不合规请求，且请求没有继续外发。

这些情况可以记录为普通治理事实。

### 14.2 风险或治理异常事件

| 事件类型 | 触发条件 | 是否表示已经外泄 |
|---|---|---|
| `context_admission_denied` | 高敏内容试图进入 Agent 上下文 | 否 |
| `gateway_bypass_denied` | 中敏派生请求试图绕过 Gateway | 否，前提是实际阻断成功 |
| `gateway_identity_invalid` | 目标声称是 Gateway，但身份验证失败 | 否 |
| `post_rejection_bypass` | Gateway 拒绝后又尝试直接外发 | 取决于实际阻断结果 |
| `lineage_evasion` | 尝试通过复制或派生执行规避 lineage | 取决于实际阻断结果 |
| `gateway_unavailable` | 必需 Gateway 不可用 | 否 |
| `policy_assurance_degraded` | 系统无法证明策略仍然有效 | 未知 |

事件必须分别记录：

- 策略请求的决策；
- 实际观察到的执行结果；
- 操作是否成功；
- 数据是否可能已经离开信任边界。

不得因为策略请求了拒绝，就自动声称实际操作已被阻止。

### 14.3 数据最小化

治理事件不得包含：

- 敏感文件内容；
- 完整 prompt；
- 完整请求 body；
- API key、cookie 或 authorization header；
- 可恢复敏感内容的进程内存片段。

治理事件可以包含：

- 脱敏后的资源路径；
- 资源 ID；
- 敏感级别；
- Agent、session 和进程身份；
- Gateway ID；
- 脱敏后的目的地；
- 请求的决策和实际结果；
- policy ID 和 revision；
- lineage ID 和 request ID。

## 15. 完整策略示例

```yaml
spec_version: "1.0"
kind: sensitive_data_governance

metadata:
  id: agentsight-sensitive-data-protection
  revision: 1
  description: Prevent high-sensitivity context admission and govern medium-data egress

subjects:
  agents:
    - qoder
    - claude-code
  sessions: []
  process_scope: process_tree

resources:
  - id: production-private-keys
    sensitivity: high
    selectors:
      files:
        - /workspace/secrets/prod-signing-key.pem
        - /root/.ssh/id_rsa
        - /root/.ssh/id_ed25519
    control:
      type: deny_context_admission
      deny_operations:
        - read
        - map_read
      reason: High-sensitivity content must not enter Agent context

  - id: customer-records
    sensitivity: medium
    selectors:
      files:
        - /workspace/customer-data/**
        - /workspace/reports/customer-*.csv
    control:
      type: require_governance_gateway
      gateway_refs:
        - central-governance
      governed_egress:
        - llm_api
        - http
        - https
        - remote_mcp
      direct_egress: deny
      gateway_unavailable: deny
      lineage_lifetime: process_tree

gateways:
  - id: central-governance
    identity:
      service: governance.internal
    endpoints:
      - host: governance.internal
        port: 8443
        protocol: https
    trust:
      require_authenticated_channel: true

defaults:
  unmatched_resources: allow
  unknown_lineage: fail_closed
  unavailable_gateway: deny
```

## 16. 规范化决策流程

```text
输入：
  subject
  operation
  optional resource
  current context lineage
  optional egress request

1. 判断 subject 是否属于策略作用范围。
   否：本策略不产生决策。

2. 将 resource 与资源规则匹配。

3. 如果命中任一 high + deny_context_admission：
   拒绝内容进入上下文；
   产生 context_admission_denied；
   结束本次接纳判断。

4. 如果命中 medium + require_governance_gateway：
   允许内容进入上下文；
   为上下文增加 medium lineage；
   将 lineage 传播给派生执行。

5. 当携带 medium lineage 的主体创建受治理外发请求：
   a. 请求提交有效 Gateway：
      允许提交；
      记录 gateway_submission；
      等待 Gateway 决策。

   b. 请求直接提交其他目标：
      拒绝请求；
      产生 gateway_bypass_denied。

   c. Gateway 不可用或身份无效：
      拒绝直接降级；
      产生对应治理异常事件。

6. Gateway 返回 allow 或 transform：
   由 Gateway 转发经过治理的请求。

7. Gateway 返回 deny：
   不得转发；
   Agent 后续直接外发视为 post_rejection_bypass。

8. Gateway 返回 error：
   按 gateway_unavailable 处理；
   不得静默直连最终目的地。
```

## 17. 策略校验规则

策略在生效前必须满足以下条件：

1. `spec_version` 和 `kind` 是本规范支持的值；
2. policy ID 非空，revision 大于零；
3. 资源 ID 在策略内唯一；
4. 每条资源规则至少包含一个文件选择器；
5. `high` 只能使用 `deny_context_admission`；
6. `medium` 只能使用 `require_governance_gateway`；
7. 每个 `gateway_ref` 都能解析到已定义的 Gateway；
8. Gateway ID 在策略内唯一；
9. 中敏规则至少引用一个 Gateway；
10. 中敏规则至少声明一种 `governed_egress`；
11. 未知控制类型、敏感级别和失败模式不得被忽略；
12. 同一 policy ID/revision 的规范化内容必须保持不可变。

任何校验失败都必须阻止该策略进入有效状态，不得只跳过无效规则后继续执行其余部分。

## 18. 安全不变量

符合本规范的系统必须同时满足：

1. 高敏内容不得进入受保护 Agent 上下文；
2. 高敏资源不得通过 Gateway 例外绕过接纳拒绝；
3. 中敏内容可以进入受保护 Agent 上下文；
4. 中敏数据进入上下文后必须建立并传播 lineage；
5. 中敏派生请求必须提交治理 Gateway；
6. 正常 Gateway 提交不得被表述为外发风险；
7. 中敏派生请求不得绕过 Gateway 直连最终目的地；
8. Gateway 拒绝或不可用时不得静默直连最终目的地；
9. 策略冲突时必须执行最严格的有效控制；
10. 请求的策略决策和实际执行结果必须分别记录；
11. 审计证据不得包含受保护的敏感内容；
12. 无法证明策略有效时不得报告“已保护”；
13. 相同 policy ID/revision 不得对应不同策略内容；
14. 子进程、替代协议、数据转换和重试不得降低策略强度。

## 19. 一致性场景

### 19.1 高敏文件访问

```text
Agent 尝试读取高敏文件
    → 拒绝上下文接纳
    → 内容未进入上下文
    → 记录 context_admission_denied
```

预期：操作被拒绝；不产生“已经外泄”的结论。

### 19.2 中敏请求正常进入 Gateway

```text
Agent 读取中敏文件
    → 建立 MEDIUM lineage
    → 派生请求提交 central-governance
    → Gateway 检查后允许或转换
    → Gateway 转发
```

预期：记录普通治理事实；不产生外发风险事件。

### 19.3 中敏请求绕过 Gateway

```text
Agent 读取中敏文件
    → 建立 MEDIUM lineage
    → Agent 尝试直连外部服务
    → 拒绝请求
    → 记录 gateway_bypass_denied
```

预期：产生绕过风险事件；实际阻断结果必须单独记录。

### 19.4 Gateway 拒绝后重试直连

```text
中敏请求提交 Gateway
    → Gateway 返回 deny
    → Agent 尝试直接发送原始请求
    → 拒绝请求
    → 记录 post_rejection_bypass
```

预期：第二次请求仍被拒绝，Gateway 的拒绝不得被降级。

### 19.5 同一文件同时命中高敏和中敏规则

```text
文件同时匹配 high 和 medium
    → high 优先
    → 拒绝上下文接纳
    → 不进入 Gateway 治理流程
```

预期：不得因为存在中敏 Gateway 规则而允许读取高敏内容。
