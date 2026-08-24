# Ollama 与 SkillFS 联合部署的构建和部署差异

本文整理 AgentSecCore sidecar 部署在引入独立 Ollama container，并增加 daemon 与
SkillFS 联动后的构建、发布、安装和验证差异。内容以当前仓库代码和 Helm render 结果为
准，不把尚未落盘或仅讨论过的方案视为已实现能力。

对比基线如下：

- 之前：Pod 主要由 Qoder/CLI 与 daemon 两个 container 组成；
- 增加独立 Ollama 模型服务 container, SkillFS native sidecar、Skill Ledger bootstrap、Warden 模型配置
  和 prompt scan 联动。


## 1. 当前运行时拓扑

Ollama 与 SkillFS 不直接通信。Ollama 为 Prompt Scanner 提供 HTTP 模型服务；SkillFS
与 daemon 使用两个经过 HMAC 认证的 Unix domain socket。它们在 CLI 和 daemon 处汇合。

```text
Qoder hook
    |
    v
agent-sec-cli scan-prompt ---- HTTP localhost:11434 ----> Ollama

agent-sec-cli --------------- daemon.sock -------------> agent-sec-daemon
SkillFS --------------------- daemon.sock/notify ------> agent-sec-daemon
SkillFS <-------------------- control.sock ------------ agent-sec-daemon
```

完整启用 SkillFS 时，一个 Pod 包含：

| Kubernetes 类型 | Container | 职责 |
| --- | --- | --- |
| regular init container | `prepare` | 创建空 source、Skill Ledger 配置、identity 文件和 Pod 级 HMAC key |
| native sidecar init container | `skillfs` | 建立 FUSE mount，向 daemon 发送 Skill 变更通知 |
| app container | `agent-sec-cli` | 运行 Qoder CLI、hook 和 `agent-sec-cli scan-prompt` |
| app container | `agent-sec-daemon` | 提供 daemon UDS、处理 SkillFS notify、扫描并签名 Skill |
| app container | `ollama` | 提供本 Pod 内的 Warden 模型推理服务 |

实际 `values.yaml` 当前设置 `skillfs.enabled: false`，因此默认 render 只有三个 app
container；只有显式设置 `skillfs.enabled=true` 才会增加 `prepare` 和 `skillfs`。

## 2. 构建和镜像发布差异

| 项目 | 之前 | 当前版本 |
| --- | --- | --- |
| 需要构建和推送的主要镜像 | Qoder/CLI、daemon | Qoder/CLI、daemon、Ollama，共三个 |
| sec-core 安装来源 | 已发布 RPM/raw artifact | 先从当前 checkout 生成本地 Anolisa raw repo |
| 模型服务 | daemon 侧预加载配置 | 独立 Ollama container |
| 模型 | Qwen3Guard 配置 | `modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF` |
| SkillFS | 无 | 镜像由外部提供，agent-sec-core 不负责构建或发布 |
| prepare | 无 | 直接使用纯 Alinux 4 镜像，不需要构建专用镜像 |

SkillFS 镜像不属于 agent-sec-core 的镜像交付范围，需要由部署方提供。Chart 只通过
`skillfs.image.repository` 和 `skillfs.image.digest` 引用该镜像，不会在本仓库中构建
或发布 SkillFS 镜像。

### 2.1 Ollama 镜像与模型生命周期

Ollama 镜像基于 Alinux 4，安装 CPU-only Ollama RPM，但不把 Warden 模型 layer 烘焙进
镜像。entrypoint 在 container 启动时依次：

1. 启动 `ollama serve`；
2. 等待 server ready；
3. 当持久化模型目录中不存在目标模型时执行 `ollama pull`；
4. 用临时 Modelfile 执行 `ollama create`，写入 `PARAMETER num_ctx 4096`；
5. 执行一次 `ollama run` 完成模型预热；
6. 等待 server 进程并处理终止信号。

因此构建阶段不需要访问 ModelScope 下载模型，但新 PVC 上的第一次部署需要访问
ModelScope。模型下载到 PVC 后，后续 Pod 替换会复用已有 layer。

## 3. Helm 部署差异

### 3.1 Container 数量和启动顺序

之前 kubelet 直接启动 Qoder/CLI 和 daemon。当前启用 SkillFS 后的顺序是：

1. `prepare` 一次性完成 bootstrap；
2. `skillfs` 以 `initContainers[].restartPolicy: Always` 启动；
3. SkillFS startup probe 确认 FUSE mount 建立；
4. kubelet 启动 CLI、daemon 和 Ollama app containers。

Ollama 不创建 Kubernetes Service，只监听 Pod 共享 loopback 的
`127.0.0.1:11434`。daemon UDS 和 SkillFS control UDS 也只在当前 Pod 的 runtime
`emptyDir` 中存在。

### 3.2 新增平台要求

启用 Ollama 本身不要求 privileged，但启用 SkillFS 额外要求：

- Kubernetes `1.29` 或更高版本，以支持 native sidecar；
- namespace/admission policy 允许 privileged container；
- 节点提供 `/dev/fuse`；
- container runtime 支持 `Bidirectional` mount propagation；
- `runtime.volume.type=emptyDir`，保持 socket 的 Pod-local 语义；
- CLI、daemon 和 SkillFS 使用统一 UID/GID/fsGroup `10001`。

Chart 顶层仍声明兼容 Kubernetes `1.24+`，但模板在
`skillfs.enabled=true` 时会额外拒绝低于 `1.29` 的集群。

### 3.3 新增配置注入

CLI 和 daemon 同时获得：

```text
AGENT_SEC_MODEL_SERVICE_BACKEND=ollama
AGENT_SEC_MODEL_SERVICE_BASE_URL=http://localhost:11434
AGENT_SEC_MODEL_SERVICE_TIMEOUT=30
```

CLI 还获得：

```text
PROMPT_SCANNER_L2_MODEL=modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF
```

Qoder hook 启动的 `agent-sec-cli scan-prompt` 会继承该变量，因此不需要在
`hooks.json` 中重复声明。`PROMPT_SCANNER_L2_MODEL` 必须和 `ollama.model` 完全一致，
否则 Ollama `/api/chat` 会因模型不存在返回 `404`。

Ollama container 获得：

```text
OLLAMA_HOST=127.0.0.1:11434
OLLAMA_MODEL=modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF
OLLAMA_FLASH_ATTENTION=1
OLLAMA_KV_CACHE_TYPE=q8_0
OLLAMA_NUM_PARALLEL=1
OLLAMA_NUM_CTX=4096
```

`OLLAMA_NUM_CTX` 不是只作为 server 全局环境变量使用。entrypoint 将它写成模型级
`PARAMETER num_ctx`，避免模型原有 Modelfile 参数覆盖全局设置。

SkillFS 和 daemon 新增：

| 方向 | Socket | 认证 key | 方法/用途 |
| --- | --- | --- | --- |
| SkillFS -> daemon | `/run/agent-sec/runtime/daemon.sock` | `notify.key` | `skill_ledger.skillfs_notify_change` |
| daemon -> SkillFS | `/run/agent-sec/skillfs/control.sock` | `control.key` | live source resolve 和 activation refresh |

## 4. Volume、持久化和密钥生命周期

| 数据 | Volume | 生命周期 |
| --- | --- | --- |
| daemon UDS、SkillFS control UDS | runtime `emptyDir` | Pod 级；Pod 删除后消失 |
| `control.key`、`notify.key` | memory `emptyDir` | Pod 级；由 prepare 生成，container restart 不会重建 |
| SkillFS source、FUSE shared mount | `emptyDir` | Pod 级；source 初始为空，等待后续 provisioning |
| Qoder config/workspace | data PVC | 跨 Pod 保留 |
| Ollama model layers | data PVC | 跨 Pod 保留，避免重复下载 |
| daemon events | data PVC | 跨 Pod 保留，默认在 `events/10001` |
| Skill Ledger Ed25519 key 和版本链 | data PVC | 跨 Pod 保留，维持 signing identity 和审计链 |

启用 persistence 时，daemon 使用：

```text
XDG_CONFIG_HOME=/var/lib/agent-sec/persistent/.config
XDG_DATA_HOME=/var/lib/agent-sec/persistent/.local/share
```

Ed25519 `key.enc`、`key.pub` 和 `keyring/` 因此位于：

```text
/var/lib/agent-sec/persistent/.local/share/agent-sec/skill-ledger/
```

Pod 级 HMAC key 和持久化 Ed25519 key 是两套独立身份。前者允许随 Pod 重建轮换；后者
必须保留，否则旧 Skill Ledger signature 无法继续由相同 key identity 验证。

当前 Chart 默认 data PVC 为 `20Gi`、`ReadWriteOnce`、
`alicloud-disk-ssd`。当前测试集群的 `cn-hangzhou-k` 不支持 `cloud_ssd`，部署时必须覆盖：

```yaml
persistence:
  persistentVolumeClaim:
    storageClassName: alicloud-disk-essd
```

## 5. 安装参数差异

当前默认 render 会启动 CLI、daemon 和 Ollama，但不会启动 SkillFS。完整联合部署至少需要：

```bash
helm upgrade --install agent-sec-sidecar \
  charts/agent-sec-sidecar \
  --namespace agent-sec \
  --create-namespace \
  --set skillfs.enabled=true \
  --set-string persistence.persistentVolumeClaim.storageClassName=alicloud-disk-essd
```

`helm upgrade --install` 使用目标 API Server 报告的 Kubernetes 版本。离线执行
`helm lint` 或 `helm template` 时，才需要通过 `--kube-version 1.29.0` 提供渲染版本。


## 6. 验证差异

之前主要验证 daemon health 和 CLI -> daemon UDS。当前版本至少需要覆盖四层。

### 6.1 Chart admission 和拓扑

```bash
helm lint --strict charts/agent-sec-sidecar \
  --set skillfs.enabled=true \
  --kube-version 1.29.0

helm template agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --set skillfs.enabled=true \
  --kube-version 1.29.0
```

### 6.2 Ollama server、模型和实际推理

```bash
kubectl exec -n agent-sec deployment/agent-sec-sidecar -c ollama -- ollama list
kubectl exec -n agent-sec deployment/agent-sec-sidecar -c ollama -- \
  ollama show modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF
```

只执行 `ollama show` 不能证明推理可用。还需要调用 `/api/chat` 或从 CLI container 执行
一次 L2 Prompt Scanner。

### 6.3 Qoder hook 和 Prompt Scanner

```bash
kubectl exec -n agent-sec deployment/agent-sec-sidecar -c agent-sec-cli -- \
  agent-sec-cli scan-prompt --mode standard --text "hello"
```

验证点包括：没有模型 `404`、实际使用 Warden、请求超时足够、hook 的 deny/allow 行为和
CLI 直接调用一致。

### 6.4 SkillFS -> daemon UDS

对 `/var/lib/skillfs/shared/mount/skills/<skill>/` 下的 Skill 做一次受控 FUSE mutation 后，
daemon event log 应出现：

```text
method=skill_ledger.skillfs_notify_change
ok=true
exit_code=0
```

随后 `.skill-meta/latest.json` 的 `versionId` 应增加，SkillFS 日志应出现
`activation reload: new target observed`。普通 `.skillfs-inbox/.../SKILL.md` 写入只触发
本地 reparse，不适合作为 notify UDS 验证，除非使用协议规定的 install-complete sentinel。

早期 privileged 测试 Pod 使用固定 fixture 实测了两次 notify UDS，daemon 均返回
`ok=true`，并生成 `v000002`、`v000003`；probe 内容已还原，但 append-only Ledger 保留
测试版本历史。新 manifest 不再创建该 fixture，后续应使用部署方 provision 的测试 Skill
重复验证。

## 7. 当前已知限制

1. SkillFS native sidecar 早于 daemon app container 启动。首次 startup reconcile 可能在
   daemon UDS 创建前执行并记录失败；Pod 就绪后的 notify 已实测成功。要消除启动告警，
   需要 SkillFS retry/reconcile 或调整 daemon 启动拓扑。
2. Ollama startup/liveness probe 只检查 server，readiness probe 使用 `ollama show`；它们
   不能证明实际 inference、warmup 和 `num_ctx` 生效。
3. `ollama create` 失败时 entrypoint 当前只输出 warning 并继续，因此 readiness 可能在
   `num_ctx` override 未生效时通过。
4. source 初始为空；生产部署仍需定义真实 Skill provisioning 和更新流程。