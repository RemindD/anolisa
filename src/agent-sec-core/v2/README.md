# AgentSecCore Policy V2

该 workspace 实现 SecCore 侧第一阶段 Policy 控制面。共享 Canonical IR 是 PCP 与
AgentSight 的唯一策略语义边界；Product Template 和 ActPlane DSL 均不进入共享接口。

## Workspace

- `asc-policy-types`：Canonical IR、Resource、Scope、Reconcile、Mapping、State 与 Receipt
  的严格 Rust/JSON 合同；
- `asc-policy-engine`：高敏禁止读取、文件防误删、低敏直接信息流外泄三类 Template 的
  Lowering，以及多 Policy 单调组合；
- `asc-pcp`：单进程持久化 Store、幂等 reconcile controller、真实 AgentSight HTTP
  client、UNKNOWN 状态恢复、Mapping 激活门禁和 Receipt cursor 去重；
- `asc-policy-service`：仅用于测试和 Demo 的常驻 HTTP 服务，托管单个 PCP Controller、
  文件状态存储、未完成操作恢复和 Receipt 周期拉取。

第一阶段 Profile 为
`agentseccore-canonical-ir/v1alpha1-demo1`。`payloadDigest` 在 JSON 规范化算法冻结前为
可选；不能伪造摘要参与激活判断。

## 最小外部接口

PCP client 只调用四个接口：

- `PUT /api/enforcement/v1/policies`
- `PUT /api/enforcement/v1/bindings`
- `GET /api/enforcement/v1/state`
- `GET /api/enforcement/v1/receipts`

HTTP 请求/响应类型位于 `asc-policy-types`，路径常量和 client 位于 `asc-pcp`。
共享 golden JSON 位于 `fixtures/`，场景索引见
[PAP、PCP 与 AgentSight 第一阶段接口场景](docs/pap-pcp-agentsight-contract-scenarios_zh.md)。
真实服务启动、Agent Scope identity、Binding、ActPlane 证据和系统调用验收见
[SecCore V2、AgentSight 与 ActPlane 端到端测试流程](docs/seccore-agentsight-actplane-e2e-test-flow_zh.md)。
本轮真实内核联调遇到的权限、构建、Profile、路径 ABI、runtime delta admission 和重启边界见
[SecCore、AgentSight 与 ActPlane 真实联调故障记录](docs/seccore-agentsight-actplane-e2e-troubleshooting_zh.md)。

各层 JSON、UDS NDJSON、固定 ABI blob 和 `cap_req` record 的逐层 payload 见
[AgentSecCore、AgentSight 与 ActPlane Payload 全链路](docs/seccore-agentsight-actplane-payload-flow_zh.md)。

## 测试服务

先启动 AgentSight，再从 `v2/` 启动服务：

```bash
cargo run -p asc-policy-service -- \
  --listen 127.0.0.1:7460 \
  --agentsight-url http://127.0.0.1:7396 \
  --agentsight-token-file /run/credentials/agentsight-token \
  --state-file ./target/asc-policy-service/state.json
```

`--agentsight-token-file` 在进程启动时读取 Bearer token，并为四个 AgentSight Canonical
请求统一设置 `Authorization` header；真实 AgentSight mutation 必须配置。只连接无需认证的
mock 时可以省略。token 不会出现在 `Debug` 输出中，凭据轮换后需要重启服务。

该进程不需要 root；真实 attach 是否需要 root 由 AgentSight/enforcer 决定。默认每 5 秒
恢复本地 `observed = null` 的 Policy/Binding operation，并拉取一页 Receipt。状态文件由
该进程独占，不应同时启动多个实例写入同一路径。

测试接口：

| 接口 | 请求 | 用途 |
|---|---|---|
| `GET /healthz` | 无 | 进程存活检查 |
| `PUT /api/v1/policies/{policyId}/revisions/{revision}` | `PolicyTemplate`，并携带 `Idempotency-Key` header | Lowering、持久化并向 AgentSight 创建 Policy |
| `PUT /api/v1/bindings` | `ReconcileBindingRequest` | 持久化并向 AgentSight创建或删除 Binding |
| `GET /api/v1/state` | 无 | 查询 SecCore 本地持久化状态 |
| `POST /api/v1/receipts/pull?limit=100` | 无 | 立即拉取并持久化一页 Receipt |

创建高敏文件策略时，请求主体继续使用冻结的简化输入：

```bash
curl -X PUT \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: policy-high-op-1' \
  --data @fixtures/pap/high-sensitivity-read.json \
  http://127.0.0.1:7460/api/v1/policies/high-sensitive-read/revisions/1
```

Binding 请求可从 `fixtures/pcp-agentsight/binding-exact.request.json` 开始修改，但与真实
AgentSight 联调时必须替换其中的 PID、start time、cgroup 和 namespace identity。

这是测试服务；出站 AgentSight token 已支持，但 PAP 入站接口仍不承诺调用方认证、授权、
多租户、数据库并发访问、滚动升级或生产可用性。CLI 只负责启动/调用该服务，不代替常驻
状态所有者。

## 当前边界

SecCore 侧的合同、Lowering、组合、状态存储、控制循环和测试用常驻服务已经实现。当前
fake AgentSight 测试可以跑通控制面；真实 Mapping、Target 编译、attach/detach 和
BPF-LSM 执行仍属于 AgentSight 阶段，SecCore 不会把未验证能力标记为 `EXACT`。

## 校验

```bash
cd v2
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

其中 `asc-policy-service/tests/e2e_contract.rs` 会启动真实 Service 子进程和 mock
AgentSight，验证两种 Policy 请求以及 `EXACT`、`UNSUPPORTED` 两种 Binding 请求与
`fixtures/pcp-agentsight/*.request.json` 在 JSON 语义上完全相等。
