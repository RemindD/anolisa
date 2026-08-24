# agent-sec-sidecar Helm Chart

该 Chart 创建一个 Deployment。每个 Pod 包含：

- `agent-sec-cli` caller container；
- `agent-sec-daemon` sidecar container；
- `ollama` 模型服务 sidecar container；
- 可选的 `prepare` 一次性 init container 与 `skillfs` native sidecar；
- CLI 与 daemon 同时挂载到 `/run/agent-sec` 的 Pod runtime volume；
- 三个 container 同时挂载到 `/var/lib/agent-sec/persistent` 的持久化数据 PVC；
- CLI 与 daemon 同时注入
  `AGENT_SEC_DAEMON_SOCKET=/run/agent-sec/runtime/daemon.sock`；
- CLI 与 daemon 同时注入
  `AGENT_SEC_DATA_DIR=/var/lib/agent-sec/persistent/events/<runAsUser>`；默认
  `runAsUser=10001`，因此默认路径是
  `/var/lib/agent-sec/persistent/events/10001`。

Chart 不创建 Service，也不开放网络端口。caller 通过本 Pod 的 Unix domain socket
访问 daemon；Rust prompt scanner 通过 Pod 共享 loopback 的
`http://localhost:11434` 访问 Ollama。

CLI container 默认设置 `stdin: true` 和 `tty: true`，用于运行 Qoder CLI 的交互式
TUI。仓库提供的 Qoder CLI 镜像通过 entrypoint 安装 agent-sec-core 插件后，默认
`exec qodercli` 作为前台主进程。

当持久化 PVC 启用时，Chart 默认将 CLI container 的 Qoder 路径设置为：

```text
HOME=/var/lib/agent-sec/persistent
QODER_CONFIG_DIR=/var/lib/agent-sec/persistent/qoder-config
QODER_WORKING_DIR=/var/lib/agent-sec/persistent/qoder-workspace
```

`QODER_CONFIG_DIR` 是 Qoder CLI 官方支持的配置目录覆盖变量，默认值为 `~/.qoder`；
设置、会话、memory 等本地数据会随 PVC 保留。`QODER_WORKING_DIR` 指定持久化工作目录。
可通过 `cli.qoder.persistentPaths` 修改相对路径或关闭该行为；
`persistence.enabled=false` 时不会注入这些变量。

## 部署

先按 [`deploy/sidecar/README.md`](../../deploy/sidecar/README.md) 构建并推送三个镜像；
若使用不会自动创建 repository 的 registry，需要预先创建这三个镜像仓库。
本地 kubeconfig 指向目标集群后执行：

```bash
helm upgrade --install agent-sec-sidecar \
  charts/agent-sec-sidecar \
  --namespace agent-sec \
  --create-namespace \
  --set-string cli.image.repository=<REGISTRY>/agent-sec-qodercli \
  --set-string cli.image.tag=0.10.2 \
  --set-string daemon.image.repository=<REGISTRY>/agent-sec-daemon \
  --set-string daemon.image.tag=0.10.1 \
  --set-string ollama.image.repository=<REGISTRY>/agent-sec-ollama \
  --set-string ollama.image.tag=0.32.1
```

私有 registry 的认证信息通过标准 `imagePullSecrets` 配置：

```yaml
imagePullSecrets:
  - name: registry-credentials
```

从 Chart `0.2.x` 升级到 `0.3.0` 时，应使用
`--reset-then-reuse-values`。它先载入新 Chart 的默认值，再合并旧 release
的自定义值。不要在这次升级中使用 `--reuse-values`，否则新增的
`persistence.*` 默认字段可能缺失。

## 持久化数据和 daemon 日志

Chart 默认使用 ACS 的 `alicloud-disk-ssd` StorageClass，创建一个 `20Gi`、
`ReadWriteOnce` 的数据 PVC，并挂载到 CLI、daemon 和 Ollama 三个 container。daemon
的结构化日志写入：

```text
/var/lib/agent-sec/persistent/events/10001/daemon.jsonl
```

`events` 下的数字 UID 子目录来自 `podSecurityContext.runAsUser`。当前 Chart 默认使用
SkillFS 与 daemon 共用的 UID `10001`，因此数据写入 `events/10001`。

默认 PVC 名称由 release 名稳定生成，例如 release 为 `agent-sec` 时是
`agent-sec-agent-sec-sidecar-data`：

- 同名 PVC 不存在时，Chart 创建它；
- 同名外部 PVC 已存在时，Chart 自动复用它，不要求用户传入 `existingClaim`；
- 当前 release 已管理该 PVC 时，升级仍继续渲染和管理它。

Chart 创建的 PVC 随 release 卸载。自动复用的外部 PVC 不属于该 release 的资源，
卸载时不会被删除。

默认 Deployment 使用 `RollingUpdate`，设置 `maxSurge=0`、
`maxUnavailable=1`。升级时先终止旧 Pod、释放 RWO 云盘，再启动新 Pod。

使用其他 StorageClass：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set-string persistence.persistentVolumeClaim.storageClassName=<STORAGE_CLASS>
```

只有已有 PVC 使用不同名称时，才需要显式覆盖：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set-string persistence.persistentVolumeClaim.existingClaim=<PVC_NAME>
```

只要 `existingClaim` 非空，Chart 就不会创建数据 PVC；该字段优先于默认的
`create=true`。未指定 `existingClaim` 时，默认安装仍会动态创建 PVC。

如果不需要持久化，可以设置：

```yaml
persistence:
  enabled: false
```

所有长期运行的 container 使用相同数字 UID/GID，并复用应用原有的本地文件读写逻辑；Chart
不额外引入容器间同步组件。

## SkillFS native sidecar

SkillFS 默认关闭。它要求 Kubernetes 1.29 或更高版本、namespace 允许 privileged
container、节点提供 `/dev/fuse`，并允许 `Bidirectional` mount propagation。需要启用时：

```yaml
skillfs:
  enabled: true
```

启用后，Chart 按以下顺序启动 Pod：

1. `prepare` regular init container 使用纯 Alinux 4 镜像创建空 source、Skill Ledger
   配置、容器 identity 文件及两个随机 HMAC key；
2. `skillfs` 以 `restartPolicy: Always` 作为 native sidecar 启动，startup probe 确认
   FUSE mount 已建立；
3. kubelet 再启动 CLI、daemon 和 Ollama app containers。

`prepare` 不创建内置 Skill。source 初始为空，配置使用
`activationPolicy=pass_warn_only`、`enableDefaultSkillDirs=false` 和
`managedSkillDirs=[]`；新 Skill 应通过 SkillFS FUSE inbox 或部署方的 provisioning 流程
加入。`prepare` 只在 Pod 初始化阶段写入 `skillfs-auth` memory `emptyDir`；daemon 与
SkillFS 均以只读方式挂载 key。daemon 或 SkillFS 单独重启不会重新生成 key。

`control.key` 与 `notify.key` 仅用于 Pod 内 daemon/SkillFS HMAC 认证，随 Pod 重建轮换。
Skill Ledger 的 Ed25519 `key.enc`、`key.pub` 和 `keyring/` 使用独立生命周期：启用默认
数据 PVC 时，daemon 设置
`XDG_CONFIG_HOME=/var/lib/agent-sec/persistent/.config` 和
`XDG_DATA_HOME=/var/lib/agent-sec/persistent/.local/share`，因此 signing key 持久化在
`/var/lib/agent-sec/persistent/.local/share/agent-sec/skill-ledger/`。prepare 会先在 PVC
创建相同的 config/data 目录并写入空 discovery 配置；Pod 重建后 daemon 复用原 signing key。
关闭 `persistence.enabled` 时，signing key 回退到 Pod 级 `skillfs-data` emptyDir。

SkillFS 镜像直接使用已发布并固定 digest 的 registry 镜像，Chart 不在部署时构建
SkillFS。`prepare` 镜像可独立覆盖；默认是纯 Alinux 4，必须包含 `/bin/bash`、`install`、
`head`、`chmod` 和 `chown`：

```yaml
skillfs:
  enabled: true
  image:
    repository: <REGISTRY>/skillfs
    tag: ""
    digest: sha256:<64-hex-digest>
  prepare:
    image:
      repository: alibaba-cloud-linux-4-registry.cn-hangzhou.cr.aliyuncs.com/alinux4/alinux4
      tag: latest
      digest: ""
```

完整部署使用两个 socket：daemon socket 为
`/run/agent-sec/runtime/daemon.sock`，SkillFS control socket 为
`/run/agent-sec/skillfs/control.sock`。daemon 与 SkillFS 使用 UID/GID `10001`，并分别加载
`control.key` 与 `notify.key` 完成双向 HMAC 认证。CLI 只挂载传播后的 FUSE view，不挂载
物理 source 或认证 key。

## Runtime volume

默认值是 `emptyDir`。这不是持久化存储，但它是 socket、lock 等 Pod runtime 文件的
推荐介质：

- 同一 Pod 的两个 container 看到同一个 socket 文件；
- Deployment 扩为多个 replica 时，每个 Pod 自动得到独立 volume 和 daemon；
- Pod 删除后 stale socket 一并消失。

多副本示例：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set replicaCount=3 \
  --set-string 'persistence.persistentVolumeClaim.accessModes[0]=ReadWriteMany' \
  --set-string persistence.persistentVolumeClaim.storageClassName=<RWX_STORAGE_CLASS>
```

每个 Pod 的 runtime `emptyDir` 和 daemon socket 仍相互独立。多个 Pod 共享数据 PVC
时，PVC 及其 StorageClass 必须支持 `ReadWriteMany`。

如果平台策略明确要求 PVC，可以让 Chart 动态创建一个：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set runtime.volume.type=persistentVolumeClaim \
  --set-string runtime.volume.persistentVolumeClaim.storageClassName=<STORAGE_CLASS>
```

也可以挂载已有 PVC：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set runtime.volume.type=persistentVolumeClaim \
  --set runtime.volume.persistentVolumeClaim.create=false \
  --set-string runtime.volume.persistentVolumeClaim.existingClaim=<PVC_NAME>
```

PVC 模式只允许 `replicaCount=1`。Unix socket 不是跨 Pod 服务协议，不能用共享 PVC
把多个 Pod 连接到同一个 daemon。PVC 的底层文件系统也必须支持创建 Unix socket；
若无平台强制要求，应继续使用 `emptyDir`。

## Ollama 模型服务和 readiness

Chart 默认启动 `ollama` sidecar，并设置：

```text
OLLAMA_HOST=127.0.0.1:11434
OLLAMA_MODEL=modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF
OLLAMA_FLASH_ATTENTION=1
OLLAMA_KV_CACHE_TYPE=q8_0
OLLAMA_NUM_PARALLEL=1
OLLAMA_NUM_CTX=4096
PROMPT_SCANNER_L2_MODEL=modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF
AGENT_SEC_MODEL_SERVICE_BASE_URL=http://localhost:11434
```

`AGENT_SEC_MODEL_SERVICE_BACKEND`、`AGENT_SEC_MODEL_SERVICE_BASE_URL` 和
`AGENT_SEC_MODEL_SERVICE_TIMEOUT` 同时注入 CLI 与 daemon。Chart 还把
`ollama.model` 作为 `PROMPT_SCANNER_L2_MODEL` 注入 Agent CLI container，确保 scanner
请求的模型与 sidecar 拉取、预热的模型完全相同。当前 Qoder prompt hook 直接执行 CLI
中的 Rust scanner，因此 CLI 必须能访问该地址。

Ollama startup/liveness probe 检查 server，readiness probe 通过 `ollama show` 确认
目标模型已经存在。模型默认保存在数据 PVC 的
`/var/lib/agent-sec/persistent/ollama-models`，Pod 替换后无需重新下载。

模型下载完成后，entrypoint 会基于已有 layer 原地重建同名本地 tag，并写入
`PARAMETER num_ctx 4096`。这是因为模型 Modelfile 中的 `num_ctx` 优先于 Ollama 的全局
context 环境变量；仅设置 `OLLAMA_CONTEXT_LENGTH` 不能可靠覆盖模型参数。该操作不会在
warm PVC 上重新下载模型，但每次 container 启动都会幂等地确认覆盖值。

`ollama.numCtx` 控制该 `num_ctx` 值，必须为正整数。Chart 同时限制
`ollama.numParallel=1`，默认启用 Flash Attention，并把 K/V cache 量化为 `q8_0`。
如需调整内存与精度，可将 `ollama.kvCacheType` 改为 `q4_0` 或 `f16`，并同步评估 Pod
内存规格；`f16` 占用更高，`q4_0` 精度更低。

如果部署方提供 Pod 外部模型服务，可以设置 `ollama.enabled=false`，并覆盖顶层
`modelService.baseUrl`。Agent CLI 仍会从 `ollama.model` 获得
`PROMPT_SCANNER_L2_MODEL`；外部服务使用其他模型时，应同时覆盖该值。

## 验证

```bash
helm lint charts/agent-sec-sidecar

kubectl rollout status \
  deployment/agent-sec-sidecar \
  --namespace agent-sec

kubectl exec \
  --namespace agent-sec \
  deployment/agent-sec-sidecar \
  --container agent-sec-cli \
  -- \
  agent-sec-cli scan-prompt --mode fast --text "hello"
```

Chart 默认将长期运行的 container 运行成数字 UID/GID `10001:10001`。Pod
SecurityContext 会覆盖镜像 `USER`；UDS 与 SkillFS HMAC key owner 校验要求 CLI、daemon
和 SkillFS 使用相同数字 UID，PVC 写权限由 `fsGroup` 提供。

验证 Qoder CLI 主进程和插件注册：

```bash
kubectl logs \
  --namespace agent-sec \
  deployment/agent-sec-sidecar \
  --container agent-sec-cli

kubectl exec \
  --namespace agent-sec \
  deployment/agent-sec-sidecar \
  --container agent-sec-cli \
  -- \
  qodercli plugins list --json
```
