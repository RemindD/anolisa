# SecCore V2、AgentSight 与 ActPlane 端到端测试流程

## 1. 目的与当前结论

本文固定第一阶段 Demo 的完整验证顺序：

```text
PAP 简化输入
  -> asc-policy-service / asc-policy-engine
  -> Canonical Policy IR
  -> asc-pcp
  -> AgentSight Canonical V1 API
  -> Binding-time Mapping 和 ActPlane DSL
  -> agentsight-enforcer
  -> ActPlane/BPF-LSM
  -> Agent 系统调用结果和 violation 证据
```

覆盖两个场景：

| 场景 | Policy 创建 | Binding/Mapping | 内核执行 | 当前预期 |
|---|---|---|---|---|
| `high_sensitivity_read_deny` | 支持 | `read` 被翻译为 `block open`，关系为 `narrower`，需要审批 | 有文件打开拦截 hook，但当前 full policy feature budget 缺 `FEAT_OPEN_RULES` | 先由 ActPlane 补齐 profile/feature，再做 runtime delta 和内核验收 |
| `prevent_file_deletion` | 支持 | `namespace_mutation` 被翻译为 `block unlink`，Demo 关系为 `exact` | full profile 有 write/unlink/rename hook；本地 Demo 临时补了 `FEAT_WRITE_RULES` | runtime delta 仍被统一 reject 阻塞，尚未进入系统调用验收 |

Policy 可以先创建；Binding 之前必须有仍在运行的 Agent 进程，因为当前 Binding 需要校验
该进程的 PID start time、cgroup v2 ID，以及 PID、mount、network namespace ID。Scope 没有
独立的创建接口，它完整内嵌在 Binding 请求中。

本轮真实联调遇到的构建、权限、Profile、路径截断和 runtime delta admission 问题，统一记录在
[真实联调故障记录](seccore-agentsight-actplane-e2e-troubleshooting_zh.md)。其中
重启 drain-pump 实验版本后 source-only Binding 仍被内核拒绝，该假设已被否定为唯一根因。
被动日志确认 control/target domain 相同；临时 rule-only 隔离提交也被拒，说明错误不是 update
特有。实际 pinned map/BTF 未发现明显 ABI 不一致，但 ActPlane 将剩余 callback 分支统一计为
`CAP_STAT_REJECT`。perf 文件没有样本，无法提供 consumer TGID 动态证据。获得可区分原因的
内核证据并复验成功前，不得把防误删场景写成已经交付。删除临时隔离探针、重建并重启 clean
Enforcer 后，source-only 回归仍得到相同 503，确认阻塞不由诊断代码造成。

## 2. 联调前置条件和剩余阻塞

真实联调前必须区分以下已实现能力和接口缺口。

### 2.1 SecCore 到 AgentSight 的 token-file 认证已接通

AgentSight 的两个 Canonical mutation 接口始终要求显式凭据：

- `PUT /api/enforcement/v1/policies`
- `PUT /api/enforcement/v1/bindings`

`asc-policy-service` 已支持以下启动参数：

```text
asc-policy-service --agentsight-token-file <PATH>
  -> HttpAgentSightClient 读取 token
  -> 四个 Canonical 请求统一携带 Authorization: Bearer <token>
```

AgentSight 使用数据库所在目录下的 `.dashboard_token`；本文示例对应
`$RUN_ROOT/.dashboard_token`。client 在启动时读取并校验 token，日志和 `Debug` 输出不会
包含 token 内容；凭据轮换后需要重启 `asc-policy-service`。如果 AgentSight 由 root 启动，
应向 SecCore 服务账号安全投递一份 mode `0600` 的凭据副本，不能把原文件改成 world-readable。
当前不需要、也不应关闭 AgentSight mutation 鉴权。

### 2.2 State 和 Receipt 接口尚未在 AgentSight 注册

SecCore client 定义了四个最小接口，但当前 AgentSight 只注册了其中两个 mutation
接口，尚未注册：

- `GET /api/enforcement/v1/state`
- `GET /api/enforcement/v1/receipts`

因此真实联调启动 `asc-policy-service` 时必须使用
`--reconcile-interval-seconds 0`，避免后台恢复和 Receipt 拉取持续访问不存在的接口。
这也意味着重启恢复和 Receipt 闭环暂不计入本轮通过项。

### 2.3 Demo digest 不是生产口径

第一阶段 `payloadDigest` 仍为可选。示例中的 `scopeDigest`、
`runtimeProfileDigest` 和 `capabilitySnapshotDigest` 是满足合同格式的 Demo 值，不代表
其规范化计算算法已经冻结。验收时不得把这些占位值宣传为真实可信摘要。

### 2.4 Scope 的运行期保证尚未全部闭环

AgentSight 当前会在 Binding 入口核对 live process 的 start time、cgroup ID 和三个
namespace ID，因此可以验证绑定对象没有被 PID 复用或初始 identity 替换。但发给 enforcer
的现有 `ApplyPolicy` 不携带 cgroup/namespace identity，本文没有证据证明运行中 namespace
变化会按 `onChange=deny` 被持续拒绝。第一阶段 Demo 只能验收初始 identity 校验、root
process 和绑定后子进程的实际约束；namespace transition 的运行期证据应单独补测和补齐。

### 2.5 ActPlane target ABI 和 runtime admission 仍有 Demo 限制

- ActPlane 文件 pattern ABI 为 64 字节并保留末尾 NUL，因此当前测试路径的 UTF-8 字节长度
  必须小于 64。AgentSight translator 当前仍允许小于 127 字节，正式修复前必须人工选用短
  测试路径，不能依赖 compiler 的静默截断。
- 当前 full profile 的正式 policy feature budget 需要同时补齐 `FEAT_OPEN_RULES`
  和 `FEAT_WRITE_RULES`；本地只做过 Demo-only write flag 兼容改动，且尚未纳入
  `make build-enforcer` 的受审 patch/hash 队列。
- runtime policy delta 稳定出现内核 `reject`。授权 TGID drain pump 的真实复验没有改变结果，
  已撤回该 workaround；AgentSight 被动日志已排除 domain 绑定遗漏，rule-only 实验也被拒。
  当前阻塞是 ActPlane callback 只暴露统一 reject：需要 per-reason 诊断，或支持 BPF JIT 动态
  追踪的宿主内核。不得用直接写 pinned map 的方式绕过 admission 充当 E2E 成功。

需要由 AgentSight/ActPlane 协作方正式修改的 feature、runtime admission、能力声明和错误
协议问题见 [Payload 全链路第 14 节](seccore-agentsight-actplane-payload-flow_zh.md#14-agentsight--actplane-协作修改清单)。

## 3. 服务拓扑与权限

需要启动三个常驻进程，ActPlane 嵌入在 `agentsight-enforcer` 中，不另开 HTTP 服务。

| 进程 | 示例地址 | 是否需要 root | 作用 |
|---|---|---|---|
| `agentsight-enforcer` | `$RUN_ROOT/enforcer.sock` | 是 | 加载/复用 BPF-LSM，编译和安装 ActPlane 规则，采集 violation |
| `agentsight serve` | `127.0.0.1:17400` | 隔离联调建议用 root | 托管 Canonical API、Binding 状态和 violation，并连接 enforcer UDS |
| `asc-policy-service` | `127.0.0.1:17460` | 否 | 接收 PAP 简化输入、Lowering、持久化 PCP 状态并调用 AgentSight |

`agentsight-enforcer` 创建 mode `0660` 的 UDS。手工隔离测试时让 AgentSight 也以 root
运行最直接；生产部署应通过固定用户/组授权访问 UDS，而不是依赖所有服务均为 root。

启动顺序固定为：

1. `agentsight-enforcer`；
2. `agentsight serve`；
3. `asc-policy-service`；
4. 创建 Policy；
5. 启动 Agent 并采集 identity；
6. 创建 Binding。

同一真实 ActPlane backend 当前最多允许一个 active Binding。两个场景必须串行执行，并在
下一个正向场景开始前 detach 上一个 Binding。

### 3.1 请求顺序总览

| 顺序 | 调用方 | 接口/动作 | 输入或用途 |
|---|---|---|---|
| 1 | 测试者 | `GET SecCore /healthz` | 确认测试服务存活 |
| 2 | 测试者 | `PUT SecCore /api/v1/policies/{policyId}/revisions/{revision}` | PAP `PolicyTemplate` 简化输入和 `Idempotency-Key` |
| 3 | 测试者 | 启动 Agent，读取 `/proc`、cgroup 和 namespace identity | Scope 没有单独的创建请求 |
| 4 | 测试者 | `PUT SecCore /api/v1/bindings` | 完整 `ReconcileBindingRequest`，其中内嵌 Scope |
| 5 | 测试者 | 再次 `PUT SecCore /api/v1/bindings` | 仅在 `narrower` 时，用新 operation ID 提交 digest-bound approval |
| 6 | 测试者 | `GET SecCore /api/v1/state` | 检查本地 desired/observed 状态 |
| 7 | 测试者 | `GET AgentSight /api/enforcement/bindings` | 检查真实 runtime Binding 和 ActPlane domain |
| 8 | Agent | 执行 `open`、`unlink` 或 `rename` | 验证系统调用结果 |
| 9 | 测试者 | `GET AgentSight /api/enforcement/violations` | 检查 PEP 证据 |
| 10 | 测试者 | `DELETE AgentSight /api/enforcement/bindings/{uuid}` | 当前 Canonical ABSENT 未实现时的临时 detach |

正常链路的 Policy/Binding mutation 都应先进入 SecCore，由
`--agentsight-token-file` 配置的 service credential 调用 AgentSight。

## 4. 前置检查和构建

### 4.1 内核和进程检查

```bash
grep -w bpf /sys/kernel/security/lsm
mountpoint /sys/fs/bpf
test -d /sys/kernel/security
pgrep -af agentsight-enforcer
ss -ltnp | grep -E ':(17400|17460)\b'
```

要求：

- `/sys/kernel/security/lsm` 包含 `bpf`；
- bpffs 已挂载；
- 不存在另一个占用 ActPlane singleton/runtime lock 的 enforcer；
- 17400 和 17460 没有被其他进程占用。

### 4.2 构建 AgentSight 和 enforcer

```bash
cd /home/xingdong/ANOLISA/src/agentsight
make build
make build-enforcer
```

`make build-enforcer` 是仓库包装好的一行构建入口。它负责取得固定 ActPlane revision、应用
AgentSight 的补丁并构建真实 backend，不应手工拼装 Cargo feature。

如果当前 checkout 为本轮手工启用 `FEAT_WRITE_RULES` 的 dirty-cache Demo，构建脚本会因
blob attestation 拒绝它。不要关闭校验；当前 Demo 的显式 path override 和正式产品化方案见
[故障记录第 4 节](seccore-agentsight-actplane-e2e-troubleshooting_zh.md#4-当前可复现的构建和检查命令)。

### 4.3 构建 SecCore V2 测试服务

```bash
cd /home/xingdong/ANOLISA/src/agent-sec-core/v2
cargo build -p asc-policy-service
```

### 4.4 创建隔离测试资产

只使用临时测试文件，不要指向真实密钥或重要文件：

```bash
RUN_ROOT=$(mktemp -d /var/tmp/agentsec-policy-e2e.XXXXXX)
SECRET_FILE="$RUN_ROOT/high-sensitive.txt"
PROTECTED_FILE="$RUN_ROOT/prevent-delete.txt"

printf '%s\n' 'e2e-secret-value' >"$SECRET_FILE"
printf '%s\n' 'e2e-important-value' >"$PROTECTED_FILE"
chmod 600 "$SECRET_FILE" "$PROTECTED_FILE"
export RUN_ROOT SECRET_FILE PROTECTED_FILE
```

记录 `RUN_ROOT` 的实际值。后续如果为服务另开终端，先在该终端重新设置同一个值并派生文件
变量，例如：

```bash
export RUN_ROOT=/var/tmp/agentsec-policy-e2e.实际后缀
export SECRET_FILE="$RUN_ROOT/high-sensitive.txt"
export PROTECTED_FILE="$RUN_ROOT/prevent-delete.txt"
```

## 5. 启动服务

建议为三个进程分别打开终端，保留 stdout/stderr 作为测试证据。

### 5.1 启动 agentsight-enforcer

```bash
cd /home/xingdong/ANOLISA/src/agentsight
sudo env \
  AGENTSIGHT_ENFORCER_SOCKET="$RUN_ROOT/enforcer.sock" \
  ACTPLANE_PINNED_PROFILE=full \
  target/release/agentsight-enforcer
```

高敏读取只需要 file-open hook，但防误删还需要 runtime write-rule feature 和
`path_unlink/path_rename` BPF-LSM hook，因此两个场景串行联调时统一使用 `full` profile。
启动失败时先检查 BPF LSM、bpffs singleton、pinned profile marker 和遗留 runtime lock，
不要切换到 mock backend 做系统约束验收。切换 profile 前必须停止所有 Enforcer；只有确认
无人使用后才能清理不匹配的 pin root。

### 5.2 启动 AgentSight

```bash
cd /home/xingdong/ANOLISA/src/agentsight
sudo env \
  AGENTSIGHT_ENFORCER_SOCKET="$RUN_ROOT/enforcer.sock" \
  target/release/agentsight serve \
    --host 127.0.0.1 \
    --port 17400 \
    --db "$RUN_ROOT/agentsight.db" \
    --config agentsight.json
```

验证 backend 必须是真实 ActPlane：

```bash
curl -fsS http://127.0.0.1:17400/api/enforcement/health | jq .
```

通过条件：

```text
ready == true
backend == "actplane"
capabilities.test_development == false
capabilities.max_active_bindings == 1
```

AgentSight 以 root 运行时，原 token 文件为 root-owned mode `0600`。为非 root 的 SecCore
测试服务制作一份同内容、仅当前测试账号可读的凭据副本：

```bash
SECCORE_TOKEN_FILE="$RUN_ROOT/seccore-agentsight.token"
sudo install \
  -m 0600 \
  -o "$(id -u)" \
  -g "$(id -g)" \
  "$RUN_ROOT/.dashboard_token" \
  "$SECCORE_TOKEN_FILE"
test -r "$SECCORE_TOKEN_FILE"
```

不要输出 token 内容，也不要把原 token 文件改成 `0644`。生产部署应使用 systemd
credential 或独立 service credential，避免手工复制。

### 5.3 启动 SecCore V2 测试服务

使用 token 文件启动：

```bash
cd /home/xingdong/ANOLISA/src/agent-sec-core/v2
cargo run -p asc-policy-service -- \
  --listen 127.0.0.1:17460 \
  --agentsight-url http://127.0.0.1:17400 \
  --agentsight-token-file "$RUN_ROOT/seccore-agentsight.token" \
  --state-file "$RUN_ROOT/seccore-state.json" \
  --reconcile-interval-seconds 0
```

存活检查：

```bash
curl -fsS http://127.0.0.1:17460/healthz
```

token 在进程启动时读取；文件不存在、不可读、为空或包含非法 HTTP header 字符时，服务
启动失败。轮换 token 后应重启该测试服务。

## 6. 场景一：高敏文件禁止读取

### 6.1 通过 PAP 简化输入创建 Policy

用户输入只声明策略类型和文件，不直接编写 Canonical IR：

```bash
jq -n --arg file "$SECRET_FILE" '{
  kind: "high_sensitivity_read_deny",
  files: [$file]
}' >"$RUN_ROOT/high-sensitive-policy.json"

curl -fsS -X PUT \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: policy-high-e2e-op-1' \
  --data @"$RUN_ROOT/high-sensitive-policy.json" \
  http://127.0.0.1:17460/api/v1/policies/high-read-e2e/revisions/1 \
  | tee "$RUN_ROOT/high-policy.response.json" \
  | jq .
```

SecCore 负责把简化输入 Lowering 为 Canonical Policy IR。AgentSight 的预期响应核心字段是：

```text
state == "AVAILABLE"
validation.status == "VALID"
staticCompile.stage == "DEFERRED_TO_BINDING"
```

`AVAILABLE` 只表示 Policy revision 合法并已保存，不表示任何具体 target 一定能执行；真正的
能力判定发生在 Binding-time Mapping。

### 6.2 启动可控 Agent 进程

使用 FIFO 控制一个长期存活的 bash。它在 Binding 前启动，真正的文件操作在
`BINDING_READY` 后才发送；这样操作来自被绑定 root process 本身或其绑定后创建的子进程。

```bash
AGENT_FIFO="$RUN_ROOT/agent.commands"
AGENT_OUTPUT="$RUN_ROOT/agent.output"
mkfifo "$AGENT_FIFO"

bash --noprofile --norc <"$AGENT_FIFO" >"$AGENT_OUTPUT" 2>&1 &
AGENT_PID=$!
exec 9>"$AGENT_FIFO"
export AGENT_PID AGENT_FIFO AGENT_OUTPUT

kill -0 "$AGENT_PID"
```

不要在测试者自己的 shell 中执行 `cat` 或 `rm` 来代替 Agent 测试；Scope 只约束指定
execution domain。

### 6.3 采集 live process identity

```bash
START_TIME=$(python3 -c '
import pathlib, sys
value = pathlib.Path(f"/proc/{sys.argv[1]}/stat").read_text()
print(value.rsplit(")", 1)[1].split()[19])
' "$AGENT_PID")

CGROUP_REL=$(awk -F: '$1 == "0" {print $3}' "/proc/$AGENT_PID/cgroup")
CGROUP_ID=$(stat -Lc %i "/sys/fs/cgroup${CGROUP_REL}")
PID_NS=$(stat -Lc %i "/proc/$AGENT_PID/ns/pid")
MOUNT_NS=$(stat -Lc %i "/proc/$AGENT_PID/ns/mnt")
NETWORK_NS=$(stat -Lc %i "/proc/$AGENT_PID/ns/net")

export START_TIME CGROUP_ID PID_NS MOUNT_NS NETWORK_NS
```

在构造请求前再次执行 `kill -0 "$AGENT_PID"`。PID 存活但 start time 不一致也必须拒绝，
不能仅靠 PID 判断进程身份。

### 6.4 构造带 Scope 的 Binding

第一阶段固定 Scope 语义：

- root process 在 `BINDING_READY` 后生效；
- 不追溯纳入绑定前已有成员；
- 纳入绑定后产生的 future members；
- exec 后继续保持；
- 声明 namespace identity 变化时拒绝；当前仅验收激活前的 identity 一致性；
- execution domain drained 时结束。

生成第一次、尚未批准 narrower Mapping 的请求：

```bash
jq -n \
  --argjson pid "$AGENT_PID" \
  --argjson start "$START_TIME" \
  --argjson cgroup "$CGROUP_ID" \
  --argjson pidns "$PID_NS" \
  --argjson mntns "$MOUNT_NS" \
  --argjson netns "$NETWORK_NS" \
  '{
    operationId: "binding-high-e2e-map-1",
    desiredState: "READY",
    bindingId: "binding-high-e2e",
    runId: "run-high-e2e",
    effectivePolicy: {
      policyId: "high-read-e2e",
      revision: 1,
      profileId: "agentseccore-canonical-ir/v1alpha1-demo1"
    },
    identity: {
      executionDomainId: "domain-high-e2e",
      identityEpoch: 1,
      rootProcess: {pid: $pid, startTimeTicks: $start},
      cgroupId: $cgroup
    },
    scope: {
      processes: {
        membership: "execution_domain",
        includeRoot: true,
        includeExistingMembers: false,
        includeFutureMembers: true,
        preserveAcrossExec: true,
        nestedExecutionDomains: "inherit"
      },
      namespaces: {
        pidNamespaceId: $pidns,
        mountNamespaceId: $mntns,
        networkNamespaceId: $netns,
        onChange: "deny"
      },
      lifetime: {
        activateAt: "binding_ready",
        expiresAt: null,
        endCondition: "execution_domain_drained"
      }
    },
    scopeDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    runtimeContext: {
      baselineId: "host:e2e-v1",
      runtimeProfileDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    },
    approval: {
      allowNarrower: false,
      approvalRef: null,
      expectedMappingDigest: null
    },
    precondition: {
      expectedBindingRevision: null,
      capabilitySnapshotDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }' >"$RUN_ROOT/high-binding-map.request.json"
```

### 6.5 第一次 Binding：取得 Mapping 和审批摘要

```bash
curl -fsS -X PUT \
  -H 'Content-Type: application/json' \
  --data @"$RUN_ROOT/high-binding-map.request.json" \
  http://127.0.0.1:17460/api/v1/bindings \
  | tee "$RUN_ROOT/high-binding-map.response.json" \
  | jq .
```

预期：

```text
state == "APPROVAL_REQUIRED"
mappings[0].targetId == "actplane-v1"
mappings[0].policyRelation == "narrower"
error.code == "NARROWER_MAPPING_REQUIRES_APPROVAL"
mappingDigest != null
targetDigests == []
pepInstances == []
effectiveAt == null
```

原因是 Canonical IR 只要求禁止 `read`，当前 translator 生成的 DSL 是 `block open file`，
实际限制更强。PCP 不能静默接受这次 Mapping，必须由调用方显式批准并绑定第一次返回的
`mappingDigest`。

### 6.6 第二次 Binding：批准同一 Mapping 并安装

每次不同意图必须使用新的 `operationId`。保持 Binding、Policy、Scope 和 identity 不变，
只加入审批信息：

```bash
MAPPING_DIGEST=$(jq -r '.mappingDigest' "$RUN_ROOT/high-binding-map.response.json")

jq \
  --arg digest "$MAPPING_DIGEST" \
  '.operationId = "binding-high-e2e-approve-1"
   | .approval.allowNarrower = true
   | .approval.approvalRef = "e2e-manual-approval-1"
   | .approval.expectedMappingDigest = $digest' \
  "$RUN_ROOT/high-binding-map.request.json" \
  >"$RUN_ROOT/high-binding-approved.request.json"

curl -fsS -X PUT \
  -H 'Content-Type: application/json' \
  --data @"$RUN_ROOT/high-binding-approved.request.json" \
  http://127.0.0.1:17460/api/v1/bindings \
  | tee "$RUN_ROOT/high-binding-approved.response.json" \
  | jq .
```

预期：

```text
state == "BINDING_READY"
scopeState == "VERIFIED"
mappings[0].policyRelation == "narrower"
targetDigests 非空
pepInstances 包含 "actplane-pep-1"
effectiveAt != null
error == null
```

只有收到 `BINDING_READY` 后才能开始 Agent 侧系统调用测试。

### 6.7 检查 AgentSight 和 ActPlane 状态

查询 AgentSight 持久化的 runtime Binding：

```bash
curl -fsS http://127.0.0.1:17400/api/enforcement/bindings \
  | tee "$RUN_ROOT/agentsight-bindings.json" \
  | jq .
```

找到 `request.policy_id == "high-read-e2e"` 的项，检查：

```text
state == "enforced"
request.root_pid == AGENT_PID
request.policy_revision == "1"
domain_id != null
```

这里没有单独的 ActPlane HTTP 查询接口。`BINDING_READY`、AgentSight runtime Binding 的
`enforced + domain_id`、实际 errno 和 violation 四项共同构成安装和执行证据。

### 6.8 从已绑定 Agent 验证系统约束

向 FIFO 中的 Agent 发送读取命令，并记录 exit code：

```bash
printf '%s\n' \
  'cat -- "$SECRET_FILE"; printf "READ_RC=%s\n" "$?"' >&9
```

查看 `$AGENT_OUTPUT`。通过条件：

- `cat` 返回非零；
- 错误为 `Operation not permitted` 或 `Permission denied`；
- 文件内容 `e2e-secret-value` 没有出现在输出中；
- Agent 进程仍存活，因为该规则是 block，不是 kill。

同时做三个边界对照：

1. 未绑定的测试者进程仍可读取 `$SECRET_FILE`；
2. 已绑定 Agent 可读取未受保护的其他文件；
3. 已绑定 Agent 在 Binding 前已有的 sibling/无关进程不应被误纳入。

### 6.9 检查 violation

```bash
curl -fsS 'http://127.0.0.1:17400/api/enforcement/violations?limit=100' \
  | tee "$RUN_ROOT/agentsight-violations.json" \
  | jq .
```

找到本次事件并检查：

```text
policy_id == "high-read-e2e"
policy_revision == "1"
operation == "open"
effect == "block"
blocked == true
killed == false
pid 属于绑定 Agent execution domain
binding_id 与 runtime Binding 一致
actplane_revision 非空
```

### 6.10 Detach 和恢复验证

Canonical V1 的 `desiredState=ABSENT` 当前在 AgentSight 返回 unsupported，因此本轮使用
兼容 DELETE 接口清理真实 runtime Binding。先从列表中取 runtime UUID：

```bash
AGENTSIGHT_TOKEN=$(<"$RUN_ROOT/seccore-agentsight.token")
RUNTIME_BINDING_UUID=$(jq -r '
  .bindings[]
  | select(.request.policy_id == "high-read-e2e")
  | .request.binding_id
' "$RUN_ROOT/agentsight-bindings.json")

curl -fsS -X DELETE \
  -H "Authorization: Bearer $AGENTSIGHT_TOKEN" \
  "http://127.0.0.1:17400/api/enforcement/bindings/$RUNTIME_BINDING_UUID" \
  -o /dev/null -w '%{http_code}\n'
unset AGENTSIGHT_TOKEN
```

预期 HTTP 204。然后再次让同一 Agent 读取 `$SECRET_FILE`，应成功；这验证规则已真正卸载，
而不是仅删除控制面记录。

## 7. 场景二：文件防误删

### 7.1 创建 Policy

```bash
jq -n --arg file "$PROTECTED_FILE" '{
  kind: "prevent_file_deletion",
  files: [$file]
}' >"$RUN_ROOT/prevent-delete-policy.json"

curl -fsS -X PUT \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: policy-delete-e2e-op-1' \
  --data @"$RUN_ROOT/prevent-delete-policy.json" \
  http://127.0.0.1:17460/api/v1/policies/prevent-delete-e2e/revisions/1 \
  | tee "$RUN_ROOT/prevent-delete-policy.response.json" \
  | jq .
```

SecCore 将该 Template Lowering 为
`resource_operation(namespace_mutation) + deny`。Policy 仍应返回
`AVAILABLE / VALID / DEFERRED_TO_BINDING`，这只是静态合同有效。

### 7.2 创建 Binding 并安装防误删规则

可复用第 6.4 节的 live identity 和 Scope 结构。生成完整请求：

```bash
jq '
  .operationId = "binding-delete-e2e-map-1"
  | .bindingId = "binding-delete-e2e"
  | .runId = "run-delete-e2e"
  | .effectivePolicy.policyId = "prevent-delete-e2e"
  | .identity.executionDomainId = "domain-delete-e2e"
  | .scopeDigest = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
  | .approval.allowNarrower = false
  | .approval.approvalRef = null
  | .approval.expectedMappingDigest = null
' "$RUN_ROOT/high-binding-map.request.json" \
  >"$RUN_ROOT/prevent-delete-binding.request.json"

curl -fsS -X PUT \
  -H 'Content-Type: application/json' \
  --data @"$RUN_ROOT/prevent-delete-binding.request.json" \
  http://127.0.0.1:17460/api/v1/bindings \
  | tee "$RUN_ROOT/prevent-delete-binding.response.json" \
  | jq .
```

如果上一场景的 Agent 或 identity 已失效，应新建 Agent 并重新采集全部 identity，不能复用
旧 PID 数据。

调用 `PUT /api/v1/bindings` 后，修复版本的预期终态是：

```text
state == "BINDING_READY"
scopeState == "VERIFIED"
mappings[0].targetId == "actplane-v1"
mappings[0].policyRelation == "exact"
targetDigests 非空
pepInstances 包含 "actplane-pep-1"
effectiveAt != null
error == null
```

该 Mapping 在当前 Demo 中不需要 narrower 审批。AgentSight 内部生成的关键 DSL 应为：

```text
source AGENT = exec "**"
rule canonical-namespace-mutation-0-0:
  block unlink file "<PROTECTED_FILE>" if AGENT
  because "Canonical namespace-mutation policy"
```

查询 AgentSight runtime Binding，要求对应记录为 `state=enforced` 且 `domain_id != null`。
如果返回 503 或 Binding 为 `failed + domain_id=null`，不能继续执行文件操作；按
[故障记录](seccore-agentsight-actplane-e2e-troubleshooting_zh.md)检查 journal、profile、
path 长度和 `cap_stats`。

### 7.3 从已绑定 Agent 验证 unlink 和 rename

ActPlane ABI 当前要求路径的 UTF-8 字节长度小于 64。先检查测试路径：

```bash
test "$(printf '%s' "$PROTECTED_FILE" | wc -c)" -lt 64
```

然后由已绑定 Agent 本身或其绑定后创建的子进程执行：

```bash
printf '%s\n' \
  'rm -- "$PROTECTED_FILE"; printf "DELETE_RC=%s EXISTS=%s\n" "$?" "$(test -e "$PROTECTED_FILE" && echo yes || echo no)"' >&9

printf '%s\n' \
  'mv -- "$PROTECTED_FILE" "$PROTECTED_FILE.moved"; printf "RENAME_RC=%s OLD_EXISTS=%s NEW_EXISTS=%s\n" "$?" "$(test -e "$PROTECTED_FILE" && echo yes || echo no)" "$(test -e "$PROTECTED_FILE.moved" && echo yes || echo no)"' >&9
```

通过条件：

- `DELETE_RC` 和 `RENAME_RC` 均非零，errno 对应 `EPERM` 或 `EACCES`；
- 原文件仍存在；
- rename 目标不存在；
- Agent 仍存活，因为规则是 block，不是 kill。

### 7.4 边界对照和 Demo 语义限制

至少检查：

1. 已绑定 Agent 仍可读取 `$PROTECTED_FILE`；
2. 已绑定 Agent 可删除一个未受保护的短路径测试文件；
3. 未绑定测试进程可删除自己的测试副本；
4. Binding 生效前已有的无关 sibling 不被误纳入。

当前 ActPlane compiler 把 DSL `unlink` lower 为统一的 `TOP_WRITE`，而 full profile 的
write、unlink、rename、truncate hook 会使用同一 mutation operation。因此当前 Demo 将
`namespace_mutation` Mapping 标为 `exact` 是阶段性约定，可能比“只防删除”更宽。验收记录
必须注明该限制，正式合同冻结前应重新评估 Mapping relation。

### 7.5 检查 violation

```bash
curl -fsS 'http://127.0.0.1:17400/api/enforcement/violations?limit=100' \
  | tee "$RUN_ROOT/prevent-delete-violations.json" \
  | jq .
```

找到本次事件并检查：

```text
policy_id == "prevent-delete-e2e"
policy_revision == "1"
operation == "write"       # 当前 ActPlane 统一 mutation operation 名
effect == "block"
blocked == true
killed == false
target 对应 PROTECTED_FILE
binding_id、pid、domain 和 ActPlane revision 可关联
```

### 7.6 Detach 后验证约束解除

按第 6.10 节方式 DELETE 对应 runtime Binding，预期 HTTP 204。确认 Binding 已清理后，再由
同一个 Agent 对重新创建的测试副本执行 unlink/rename，应成功。

本场景最终通过条件为：

| 检查 | 预期 |
|---|---|
| Binding-time Mapping | 当前 Demo 为 `exact`；生产 relation 仍需审计 |
| kernel admission | `cap_stats.accept` 随本次 delta 增长，`reject` 不增长 |
| `unlink`/`unlinkat` 受保护文件 | 已绑定 Agent 得到 EPERM/EACCES，文件仍存在 |
| `rename`/`renameat`/`renameat2` 受保护文件 | 已绑定 Agent 得到 EPERM/EACCES，原路径仍存在 |
| 普通读取 | 允许，不把防误删误实现为禁止读取 |
| 未绑定进程 | 允许删除测试副本 |
| 无关文件 | 已绑定 Agent 仍可删除 |
| violation | operation/effect/blocked、Binding、PID、revision 全部可关联 |
| detach 后 | 同一 Agent 可删除测试副本 |

如果 `cap_stats.accept` 未增长、Binding 不是 `enforced`，或目标路径长度大于 63 字节，则本轮
不能判定通过。“静态资源管理”只声明被保护文件集合，不能代替系统调用执行证据。

## 8. SecCore 本地状态检查

每个阶段可以查看测试服务持久化的 controller 状态：

```bash
curl -fsS http://127.0.0.1:17460/api/v1/state \
  | tee "$RUN_ROOT/seccore-controller-state.json" \
  | jq .
```

检查 operation ID、Policy/Binding 请求和 observed response 是否一致。由于 AgentSight 尚未
提供 Canonical state/receipt 接口，本轮不要调用
`POST /api/v1/receipts/pull`，也不验收 UNKNOWN 自动恢复。

## 9. 清理

先 detach active Binding，再停止 Agent 和三个服务：

```bash
exec 9>&-
wait "$AGENT_PID" 2>/dev/null || true
```

依次向 `asc-policy-service`、AgentSight、`agentsight-enforcer` 发送 SIGINT。确认没有测试
进程后，再删除 `$RUN_ROOT`。如果存在 active Binding 或无法确认 enforcer 是否仍在使用
该目录，不要直接删除 socket 或状态文件。

## 10. 最终验收清单

### 10.1 当前版本已有证据的项目

- PAP 简化输入准确 Lowering 为对应 Canonical IR；
- SecCore 使用 token file 认证调用 AgentSight，凭据不进入请求 body 或日志；
- Scope 内嵌于 Binding，且 live process identity 校验生效；
- 高敏读取 Mapping 首次要求 digest-bound narrower 审批；
- SecCore/PCP 可以把批准后的 Binding 请求发送到 AgentSight，AgentSight 可以生成 ActPlane DSL；
- 文件 `NamespaceMutation` 已能生成 `block unlink file` DSL，当前 Demo Mapping 为 `exact`；
- update-only 与 rule-only runtime delta 都已定位到 ActPlane 内核 callback 的统一 reject；
- `ts_updates/ts_rules` 首槽和对应 count 均未写入，AgentSight Binding 未达到 `enforced`。

### 10.2 完整生命周期 Demo 仍必须补齐

- AgentSight Canonical `GET state` 和 `GET receipts`；
- Canonical Binding `ABSENT` 的 detach 支持；
- 取得 per-reason callback 证据并修复 runtime delta reject；
- 分别完成高敏读取与 `NamespaceMutation` 的真实 `accept/enforced/EPERM/violation` 证据；
- 在成功安装之后补做 detach，并证明约束解除；
- 修正 ActPlane 64 字节 pattern 与 AgentSight 127 字节校验边界不一致；
- 审计 `NamespaceMutation -> TOP_WRITE` 的生产 Mapping relation；
- 由 ActPlane 提供同时声明 `FEAT_OPEN_RULES` 和 `FEAT_WRITE_RULES` 的正式 profile；
- digest 规范化计算口径以及相应 golden fixture；
- 自动化 root E2E runner，将本文断言转为机器可执行测试并保存脱敏证据。

## 11. 相关合同和样例

- [PAP、PCP 与 AgentSight 第一阶段接口场景](pap-pcp-agentsight-contract-scenarios_zh.md)
- [Canonical Policy IR 第一阶段实现计划](canonical-policy-ir-phase1-implementation-plan_zh.md)
- [真实联调故障记录](seccore-agentsight-actplane-e2e-troubleshooting_zh.md)
- [Policy、Binding、UDS 与 ActPlane Payload 全链路](seccore-agentsight-actplane-payload-flow_zh.md)
- [Binding 完整请求样例](../fixtures/pcp-agentsight/binding-exact.request.json)
- [高敏读取 PAP 输入](../fixtures/pap/high-sensitivity-read.json)
- [文件防误删 PAP 输入](../fixtures/pap/prevent-file-deletion.json)
