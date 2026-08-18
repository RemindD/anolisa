# AgentSecCore、AgentSight 与 ActPlane Payload 全链路

> 记录日期：2026-08-20。
> 范围：本轮 `prevent_file_deletion` Policy、OpenClaw PID 97144 Binding、AgentSight
> Canonical Mapping、Enforcer UDS 协议和 ActPlane runtime delta。文中的“实际提交”与
> “预期后续提交”严格区分，不把未进入内核的 rule 写成已安装。

## 1. 链路总览

```text
PAP 简化输入
  -> AgentSecCore Policy Template Lowering
  -> Canonical Policy IR
  -> PCP ReconcilePolicy
  -> AgentSight 保存不可变 Policy revision
  -> PCP ReconcileBinding（含 Identity 和 Scope）
  -> AgentSight Binding-time Mapping
  -> ActPlane DSL
  -> UDS ApplyPolicyLeased
  -> Enforcer 编译为 74,760-byte taint_config
  -> cap_req AppendUpdate
  -> cap_req AppendRule（只有 AppendUpdate 成功后才提交）
```

当前实际终点是 `AppendUpdate` 被 ActPlane BPF callback 计入 `CAP_STAT_REJECT`。因此正常
防误删链路没有提交 `AppendRule`，也没有形成 active Binding 或系统约束。

## 2. PAP 创建 Policy

请求：

```http
PUT /api/v1/policies/prevent-delete-e2e/revisions/1
Content-Type: application/json
Idempotency-Key: policy-delete-e2e-op-1
```

body：

```json
{
  "kind": "prevent_file_deletion",
  "files": [
    "/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2Ya2/protected.txt"
  ]
}
```

`Idempotency-Key` 进入控制面 `operationId`，不写入冻结的 Template body。

## 3. AgentSecCore Lowering 后的 Canonical Policy IR

```json
{
  "irSchemaVersion": 1,
  "profileId": "agentseccore-canonical-ir/v1alpha1-demo1",
  "policyId": "prevent-delete-e2e",
  "revision": 1,
  "payload": {
    "resources": [
      {
        "kind": "file",
        "id": "protected-file-entries",
        "matchers": [
          {
            "path": {
              "type": "exact",
              "path": "/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2Ya2/protected.txt"
            },
            "resolution": {
              "type": "final_object",
              "followFinalSymlink": true,
              "matchHardlinkIdentity": true
            }
          }
        ]
      }
    ],
    "rules": [
      {
        "id": "deny-protected-file-namespace-mutation",
        "when": {
          "type": "atom",
          "atom": {
            "type": "resource_operation",
            "operation": "namespace_mutation",
            "target": {
              "type": "in",
              "resourceSet": "protected-file-entries"
            }
          }
        },
        "outcome": {
          "decision": "deny",
          "obligations": ["audit", "emit_receipt"],
          "remediation": "none"
        },
        "enforcement": {
          "decisionTiming": "pre_effect",
          "requiredEvidence": ["binding_ready", "operation_denied"]
        }
      }
    ],
    "activation": "post_attach_allowed",
    "failurePolicy": {
      "runtime": "fail_closed",
      "update": "keep_last_known_good"
    }
  }
}
```

语义是：禁止目标资源集合发生 namespace mutation。Canonical IR 在这一层不包含 PID、
cgroup、namespace 或生命周期；这些信息属于 Binding。

## 4. PCP 发给 AgentSight 的 Policy payload

请求：

```http
PUT /api/enforcement/v1/policies
Authorization: Bearer <token>
Content-Type: application/json
```

body 结构如下；`policy` 字段实际承载第 3 节的完整 JSON 对象，下面的尖括号是文档省略标记，
不是线上字符串：

```text
{
  "operationId": "policy-delete-e2e-op-1",
  "desiredState": "PRESENT",
  "policy": <第3节的完整Canonical Policy IR对象>,
  "precondition": {
    "expectedCurrentRevision": null,
    "expectedPayloadDigest": null
  }
}
```

本轮 AgentSight 返回：

```text
state = AVAILABLE
validation.status = VALID
staticCompile.stage = DEFERRED_TO_BINDING
```

`DEFERRED_TO_BINDING` 表示 Policy 已可保存和引用，但尚未结合 target capability、Scope 和
运行进程生成 DSL，更不表示内核规则已安装。

## 5. AgentSecCore Binding payload

请求：

```http
PUT /api/v1/bindings
Content-Type: application/json
```

body：

```json
{
  "operationId": "binding-delete-openclaw-map-6",
  "desiredState": "READY",
  "bindingId": "binding-delete-openclaw-97144",
  "runId": "run-openclaw-97144",
  "effectivePolicy": {
    "policyId": "prevent-delete-e2e",
    "revision": 1,
    "profileId": "agentseccore-canonical-ir/v1alpha1-demo1"
  },
  "identity": {
    "executionDomainId": "openclaw-gateway-97144",
    "identityEpoch": 1,
    "rootProcess": {
      "pid": 97144,
      "startTimeTicks": 658309
    },
    "cgroupId": 22
  },
  "scope": {
    "processes": {
      "membership": "execution_domain",
      "includeRoot": true,
      "includeExistingMembers": false,
      "includeFutureMembers": true,
      "preserveAcrossExec": true,
      "nestedExecutionDomains": "inherit"
    },
    "namespaces": {
      "pidNamespaceId": 4026532221,
      "mountNamespaceId": 4026532219,
      "networkNamespaceId": 4026531833,
      "onChange": "deny"
    },
    "lifetime": {
      "activateAt": "binding_ready",
      "expiresAt": null,
      "endCondition": "execution_domain_drained"
    }
  },
  "scopeDigest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
  "runtimeContext": {
    "baselineId": "host:openclaw-e2e-v1",
    "runtimeProfileDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
  },
  "approval": {
    "allowNarrower": false,
    "approvalRef": null,
    "expectedMappingDigest": null
  },
  "precondition": {
    "expectedBindingRevision": null,
    "capabilitySnapshotDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

PCP 验证、持久化后，以相同 JSON 合同调用：

```http
PUT /api/enforcement/v1/bindings
Authorization: Bearer <token>
```

## 6. AgentSight Binding-time Mapping 和 DSL

AgentSight 根据不可变 Policy revision、Binding identity、Scope 和当前 ActPlane capability
完成 Mapping。本轮 namespace mutation 被映射为 `unlink`：

```text
source AGENT = exec "**"
rule canonical-namespace-mutation-0-0:
  block unlink file "/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2Ya2/protected.txt" if AGENT
  because "Canonical namespace-mutation policy"
```

这里有两层含义：

1. `source AGENT = exec "**"` 定义 `AGENT` label 的来源；
2. 第二条 rule 要求带 `AGENT` label 的执行域对目标执行 unlink 时被 block。

DSL 生成成功只证明 Mapping 和字符串编译入口通过，不证明 ActPlane runtime delta 已被内核
admit。

## 7. AgentSight 发给 Enforcer 的 ApplyPolicy

AgentSight 对逻辑 `bindingId` 求 SHA-256、截取前 16 bytes，并设置 UUID version 5/variant bits；
这是一套本地确定性编码，不是带 namespace 参数的标准 UUIDv5 API。Enforcer 再对 UUID 的四个
big-endian `u32` 做 XOR 得到非零 domain id。本轮：

```text
Canonical bindingId = binding-delete-openclaw-97144
runtime binding UUID = db25bd65-d06d-5808-8282-cd59d03ae317
ActPlane target/domain id = 1508952867
```

内部 `ApplyPolicy`：

```json
{
  "binding_id": "db25bd65-d06d-5808-8282-cd59d03ae317",
  "agent_id": "run-openclaw-97144",
  "session_id": "openclaw-gateway-97144",
  "root_pid": 97144,
  "process_start_time": 658309,
  "policy_id": "prevent-delete-e2e",
  "policy_revision": "1",
  "policy_dsl": "source AGENT = exec \"**\"\nrule canonical-namespace-mutation-0-0:\n  block unlink file \"/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2Ya2/protected.txt\" if AGENT\n  because \"Canonical namespace-mutation policy\"\n",
  "policy_mode": "enforce"
}
```

通过 UDS 发送的协议是 version 4 NDJSON。以下 `request_id` 和
`required_subscription_id` 是每次运行动态生成的 UUID，其余 `request` 字段为本轮实际值：

```json
{
  "protocol_version": 4,
  "request_id": "<每次请求新生成的UUID>",
  "command": "apply_policy_leased",
  "params": {
    "request": {
      "binding_id": "db25bd65-d06d-5808-8282-cd59d03ae317",
      "agent_id": "run-openclaw-97144",
      "session_id": "openclaw-gateway-97144",
      "root_pid": 97144,
      "process_start_time": 658309,
      "policy_id": "prevent-delete-e2e",
      "policy_revision": "1",
      "policy_dsl": "source AGENT = exec \"**\"\nrule canonical-namespace-mutation-0-0:\n  block unlink file \"/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2Ya2/protected.txt\" if AGENT\n  because \"Canonical namespace-mutation policy\"\n",
      "policy_mode": "enforce"
    },
    "required_subscription_id": "<当前必需的violation订阅UUID>"
  }
}
```

物理 framing 是一行 JSON 后跟一个换行符，单帧最大 1 MiB。

## 8. Scope 在边界上的收缩

Binding 的所有字段不会原样到达 Enforcer：

| Binding 字段 | AgentSight/Enforcer 处理 |
|---|---|
| `runId` | 转为 `ApplyPolicy.agent_id` |
| `executionDomainId` | 转为 `ApplyPolicy.session_id` |
| `rootProcess.pid` | 原样进入 `root_pid` |
| `rootProcess.startTimeTicks` | 原样进入 `process_start_time` |
| `cgroupId` | AgentSight 入口校验，未进入 `ApplyPolicy` |
| 三个 namespace ID | AgentSight 入口校验，未进入 `ApplyPolicy` |
| `namespaces.onChange` | 未进入 `ApplyPolicy`，当前没有持续 namespace transition 保证 |
| process membership/lifetime | 未以完整 Scope 结构进入 Enforcer |
| approval/digest/precondition | PCP/AgentSight 控制面使用，不进入 ActPlane rule |
| Canonical Policy body | 在 AgentSight 被消费并生成 DSL，不原样进入 Enforcer |

因此当前 Enforcer/ActPlane payload 能表达 PID root、start time、稳定 runtime domain 和 DSL，
但不能证明 Canonical Binding 中的全部 Scope 语义持续生效。

## 9. DSL 编译后的固定 ABI blob

Enforcer 内的 ActPlane compiler 将 DSL 编译为 `taint_config`：

```text
sizeof(taint_config) = 74,760 bytes
n_updates = 1
n_rules = 1

updates = 320 × 144-byte taint_update
rules   = 128 × 224-byte taint_rule
未使用槽位全部为 0
```

长度计算：

```text
8-byte header + 320 * 144 + 128 * 224 = 74,760
```

编译结果中的两个 active entry 是：

```text
update[0] = 给任意 exec 来源增加 AGENT(0x1) label
rule[0]   = 带 AGENT label 时 block TOP_WRITE exact-path
```

## 10. 实际首先下发到 ActPlane 的 AppendUpdate

Enforcer 不把整个 74,760-byte blob 一次写入内核，而是先做 userspace feature/capability
precheck，再依次向 `cap_req` user ring buffer 提交 record。

第一条 record 为 `AppendUpdate`，大小 168 bytes：

```json
{
  "tag": -4,
  "tagName": "CAP_REQ_APPEND_UPDATE",
  "caller_pid": "<当次Enforcer PID>",
  "target_id": 1508952867,
  "new_scope_id": 0,
  "required_mask": 0,
  "entry": {
    "op": 0,
    "opName": "TOP_EXEC",
    "match": 3,
    "matchName": "TAINT_MATCH_ANY",
    "target": "",
    "arg": "",
    "add": 1,
    "del": 0,
    "gates": 0,
    "invals": 0,
    "ipv4": 0,
    "ipv4_mask": 0,
    "gate_exit_code": -1,
    "domain_id": 0
  }
}
```

`add=1` 对应 `AGENT` label bit。record 内 `entry.domain_id=0`；BPF callback 成功接纳时会
复制 entry 并把 `domain_id` 覆盖为 `target_id`，然后写入 `ts_updates`。

本轮实际执行到这里，BPF callback 返回统一 reject：

```text
runtime policy delta update[0] was not admitted by the kernel;
count remained 0
```

`ts_updates[0]` 仍全零，`ts_counts[updates]` 仍为 0，随后 Enforcer 回滚本次 delta。

## 11. 预期后续下发、但正常流程未提交的 AppendRule

只有全部 update 成功后，Enforcer 才继续提交 rule。防误删 rule 对应 248-byte record：

```json
{
  "tag": -5,
  "tagName": "CAP_REQ_APPEND_RULE",
  "caller_pid": "<当次Enforcer PID>",
  "target_id": 1508952867,
  "new_scope_id": 0,
  "required_mask": 16,
  "requiredMaskName": "AUTH_BIND_RULE",
  "entry": {
    "op": 2,
    "opName": "TOP_WRITE",
    "match": 0,
    "matchName": "TAINT_MATCH_EXACT",
    "cond_kind": 0,
    "condKindName": "TCOND_NONE",
    "cond_neg": 0,
    "cond_match": 0,
    "effect": 1,
    "effectName": "TEFFECT_BLOCK",
    "target": "/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2",
    "arg": "",
    "cond_pat": "",
    "req": 1,
    "forbid": 0,
    "gate": 0,
    "rule_id": 0,
    "ipv4": 0,
    "ipv4_mask": 0,
    "cond_ipv4": 0,
    "cond_ipv4_mask": 0,
    "gate_idx": 0,
    "domain_id": 0,
    "since_mask": 0
  }
}
```

`required_mask=16` 是 `AUTH_BIND_RULE`；`req=1` 表示进程必须带 `AGENT` label；`TOP_WRITE`
是 ActPlane 对 write/unlink/rename mutation 的统一 kernel operation。

重要：这份 `AppendRule` 是根据已成功编译的 ABI blob 解码出的“预期后续 payload”，但正常
Binding 流程因 `AppendUpdate` 先失败，没有实际提交它。临时 rule-only 隔离实验曾证明 rule
record 也会被当前 callback 统一拒绝，但它不属于正常安装顺序。

## 12. 80-byte 路径被截断为 63 bytes

Canonical/DSL 中的路径长度为 80 bytes：

```text
/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2Ya2/protected.txt
```

ActPlane ABI 的 `target` 固定为 64 bytes，并保留末尾 NUL。compiler 使用：

```text
min(input_length, PAT - 1)
```

因此实际 `taint_rule.target` 只有前 63 bytes：

```text
/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2
```

同时 rule 的 matcher 是 `TAINT_MATCH_EXACT`。即使 admission 成功，这条截断后的 rule 也不会
精确匹配原 `protected.txt`。当前 Demo 必须使用 UTF-8 字节长度小于 64 的短路径，例如：

```text
/tmp/asc-p
```

正式方案需要让 AgentSight 在 Mapping/DSL 阶段拒绝 `len >= 64`，不能依赖 ActPlane 静默截断。

## 13. 当前真实状态

```text
PAP Template                         成功
Canonical IR Lowering                成功
ReconcilePolicy                      AVAILABLE
Binding identity 初始校验            成功
Binding-time Mapping                 成功
namespace_mutation -> unlink DSL      成功
UDS ApplyPolicyLeased                到达 Enforcer
DSL -> taint_config                   成功（1 update / 1 rule）
userspace capability precheck         成功
AppendUpdate BPF admission            失败（CAP_STAT_REJECT）
AppendRule 正常提交                   未发生
Binding                              failed, domain_id=null
文件系统约束                          未安装
```

因此不能用“DSL 已生成”或“74,760-byte blob 已编译”代替“规则已下发成功”。当前成功标准必须
至少包含：`cap_stats.accept` 增长、update/rule count 增长、Binding 为 `enforced` 且
`domain_id != null`、目标 unlink 返回 EPERM/EACCES，以及 violation 可关联 Policy/Binding。

## 14. AgentSight / ActPlane 协作修改清单

本节只记录需要由 AgentSight 或 ActPlane 协作方正式修改的产品/代码问题。重新编译、
重启服务、清理 pin root、换短测试路径等联调操作不列为协作方交付项。

### 14.1 AgentSight 需修改

| ID | 问题 | 需要的修改 | 优先级/状态 |
|---|---|---|---|
| AS-01 | Canonical `namespace_mutation` 原先无法翻译 | 正式支持 `namespace_mutation -> block unlink file`，并用 SecCore 合同 JSON 做回归测试 | P0；当前本地 AgentSight 已实现，需协作方合入/确认语义 |
| AS-02 | AgentSight 允许小于 127 bytes 的 DSL 路径，ActPlane ABI 实际只能保存 63 bytes | 按 ActPlane 公开的 `maxPatternBytes` 在下发前拒绝过长路径；第一阶段固定为 UTF-8 字节长度 `< 64` | P0；未修改 |
| AS-03 | Enforcer `HealthStatus.capabilities` 只公开 credential 类布尔值，不公开文件 rule/profile 能力 | 扩展 AgentSight-Enforcer 协议，至少公开 `read/open`、`namespace_mutation/unlink`、block 能力、active profile、policy feature mask 和最大路径字节数；Binding 前必须 preflight | P0；未修改 |
| AS-04 | ActPlane/Enforcer 失败对 HTTP 调用方统一收敛为 `503 enforcer_unavailable` | 保留稳定、非敏感的阶段与原因码（例如 `feature_missing`、`admission_denied` 及 record 类型/索引），写入 Binding diagnostic 并返回 PCP | P0；当前只有日志能看到部分原始错误 |
| AS-05 | Canonical Scope 的 cgroup/namespace identity 在 AgentSight 入口校验后，`ApplyPolicy` 只传 `root_pid + process_start_time` | 第一阶段至少明确 PID Scope 契约：PID 退出或 start time 变化后自动 detach，Binding 转为终态；后续如要保证 namespace/cgroup 不变，需扩展特权边界协议 | P0（PID 生命周期）/P1（完整 identity 持续校验）；未完整实现 |
| AS-06 | `namespace_mutation` 当前标为 `exact`，但 ActPlane `unlink` 会 lower 到共享 `TOP_WRITE` | 根据 ActPlane 最终语义校正 Mapping relation；在 ActPlane 不能区分 unlink 前，不得宣称“只禁止删除”的 exact mapping | P0 口径；未修改 |

### 14.2 ActPlane 需修改

当前代码中没有 `WRITE_FILE` 这个 flag。文件删改 rule 对应 `FEAT_WRITE_RULES`，文件
读取 rule 对应 `FEAT_OPEN_RULES`；两者都不等于负责真正 deny 的 `FEAT_BLOCK_FILE`。

| ID | 问题 | 需要的修改 | 优先级/状态 |
|---|---|---|---|
| AP-01 | full pinned profile 有文件 hook，但正式 feature budget 不能同时接受第一阶段的 `block open` 和 `block unlink` | 提供稳定、可选的 AgentSight profile，同时预留 `FEAT_OPEN_RULES` + `FEAT_WRITE_RULES` + `FEAT_BLOCK_FILE` + 所需 file-flow/write-path hooks；不再依赖本地 cache 的一行 flag 修改 | P0 阻塞；未正式支持 |
| AP-02 | 合法的 runtime delta 在 source-only `AppendUpdate` 和 rule-only `AppendRule` 上都被 callback 拒绝 | 定位并修复 runtime capability admission，使 AgentSight 向已运行 PID 动态安装 policy delta | P0 根阻塞；当前 `accept=0` |
| AP-03 | callback 把 dynptr 读取、submitter、feature、authority/scope 和 map write 失败都折叠为 `CAP_STAT_REJECT` | 增加稳定的 per-reason admission 计数/响应码，并经 Enforcer 协议返回 AgentSight；不得只留内核 debug log | P0 可诊断性；未实现 |
| AP-04 | `PAT=64` 时 compiler 会把过长 exact path 静默截成 63 bytes | compiler 必须显式拒绝，或升级 ABI；同时向 AgentSight 公开实际 pattern 上限 | P0 安全正确性；未修改 |
| AP-05 | DSL 的 `unlink` 与 write/rename 共享 `TOP_WRITE`，无法证明规则只阻断删除 | 二选一：增加独立 unlink operation/匹配语义；或者将对外能力明确定义为更宽的“不可修改”，由 AgentSight 据此报告 Mapping relation | P0 口径；Demo 可接受更宽约束，但不能标记为只阻断 unlink |

### 14.3 双方联合验收条件

上述修改完成后，AgentSight/ActPlane 协作交付至少满足：

- Enforcer health 能精确声明 `open`/`unlink`/block/profile/path limit，AgentSight 在 Binding 前校验；
- 高敏读取策略不再缺 `FEAT_OPEN_RULES`，防误删策略不再缺 `FEAT_WRITE_RULES`；
- runtime `AppendUpdate`/`AppendRule` 成功，Binding 为 `enforced` 且 `domain_id != null`；
- 拒绝时 PCP 能拿到稳定原因码，不再只有泛化 503 或 `CAP_STAT_REJECT`；
- 超长路径在 userspace 明确失败，不安装截断后的规则；
- PID 退出后 Binding 自动脱离，不把旧 runtime state 继续报告为生效。

## 15. 相关实现和证据

- [实际 OpenClaw Binding 请求](../target/e2e/run.Fj2Ya2/openclaw-prevent-delete-binding.request.json)
- [PAP/PCP/AgentSight 合同场景](pap-pcp-agentsight-contract-scenarios_zh.md)
- [完整 E2E 测试流程](seccore-agentsight-actplane-e2e-test-flow_zh.md)
- [真实联调故障记录](seccore-agentsight-actplane-e2e-troubleshooting_zh.md)
- AgentSecCore Policy Lowering/转发：`v2/crates/asc-policy-service/src/lib.rs`
- AgentSight Canonical Binding 组装：`src/agentsight/src/enforcement/canonical.rs`
- AgentSight DSL 翻译：`src/agentsight/src/enforcement/canonical/translation.rs`
- AgentSight-Enforcer NDJSON 协议：`src/agentsight/crates/enforcement-protocol/src/lib.rs`
- ActPlane runtime delta：`src/agentsight/target/actplane-src/<revision>/bpf/src/lib.rs`
