# Agent 纵深防护 Demo：执行流程与输入文件

本目录用于复现“Qoder 在 Sandbox 内处理合成客户数据，经 Host Gateway 提交聚合报告”的演示。按顺序完成 Host 准备、创建策略、启动 Sandbox、等待防护就绪，再在同一个 Qoder 会话逐条发送 13 条 prompt。

这是内部联调材料，基于 `formal-7jmaa8br` 的真实录像和证据整理。原运行 13/13 通过；本次整理进行了输入文件、代码语法、补丁、交叉引用检查及已有安装的只读核对，没有重新执行整轮实机测试。环境版本和源码基线见 [manifest.json](manifest.json)，本包检查记录见 [validation.json](validation.json)，原运行结果见 [recorded-results.json](evidence/recorded-results.json)。本文中的“应看到”是验收条件，不是本次执行的预制输出。

[架构图](architecture/defense-in-depth-demo.png) · [可编辑 draw.io](architecture/defense-in-depth-demo.drawio)

解压或复制材料后，在本目录执行 `sha256sum -c SHA256SUMS` 校验文件。准备工作从第 2 节开始，正式展示从第 3 节开始，Qoder 的逐条输入见第 5 节。

## 1. 材料清单与执行位置

| 文件 | 用途 |
|---|---|
| [baseline.cedar](policies/baseline.cedar)、[baseline.json](policies/baseline.json) | 启动时的 Sandbox Cedar 基线及 CLI 输入封装 |
| [file.cedar](policies/file.cedar)、[file.json](policies/file.json) | AgentSight 文件保护 Cedar 及 CLI 输入封装 |
| [credential.json](policies/credential.json) | Gateway 凭据用途策略；当前唯一使用原生 JSON 的 Policy |
| [permissions.json](config/permissions.json) | PEP 请求的 OS 权限，不是第四份 Policy |
| [authorization-template.json](config/authorization-template.json) | daemon 的 PDP 配置模板；运行时填入新建基线 Policy ID |
| [skillsec.json](config/skillsec.json) | 演示 daemon 配置，关闭无关的默认 Skill 目录扫描 |
| [AgentSight profile 配置](config/agentsight-file-guard.conf) | 专用 enforcer 使用的文件保护 profile |
| [customers.json](data/customers.json) | 两条合成客户记录；金额合计 30，包含测试卡号 |
| [customers-escaped.json](data/customers-escaped.json) | 同一个测试卡号的 JSON Unicode 转义样本 |
| [report.json](data/report.json) | C09 用的普通报告；C12 会在工作目录中将它替换为聚合报告 |
| [prompts.json](prompts/prompts.json) | 录制时使用的 C01～C13 完整 prompt |
| [Qoder 操作单](prompts/README_zh.md) | 可直接复制的 prompt、验收点和参考工具命令 |
| [Gateway addon](gateway/asc_gateway_addon.py)、[凭据匹配模块](gateway/asc_gateway_policy.py) | 实际部署的 Gateway 代码，包含 PII、原文回退及精确模型白名单 |
| [Gateway unit](gateway/agent-sec-gateway.service)、[诊断 addon](gateway/diagnostics.py) | 服务启动配置及元数据日志 |
| [测试上游](upstream/upstream.py) | 同机 HTTPS 接收服务及仅监听 loopback 的计数接口 |
| [CLI/凭据补丁](patches/cli-credential-locations.patch) | 多 Policy Scope、假值文件导出及 Gateway 凭据位置清单所需的源码修改 |

准备两个 Host 终端：**终端 A** 运行 root 配置命令，随后进入 Qoder；**终端 B** 保持 root，用于就绪检查和取证。进入 Qoder 后，终端 A 只发送自然语言 prompt，由 Qoder 自己调用工具。

daemon、AgentSight/enforcer 在 Host 以 root 运行；Gateway 使用独立服务账号 `agent-sec-gw`；Qoder 使用 `asc-pii-demo`。所有路径都是本 Demo 的专用路径；不使用任何实际机器名。不要在已有业务使用这些服务、端口或路径的主机上直接覆盖配置。

以下文件由实际运行生成，不提供带历史 ID 或秘密的预填版本：

| 运行时文件 | 产生方式 |
|---|---|
| `$DEMO_RUN/evidence/*-create.json` | CLI create 的完整真实返回，供后续读取本轮 ID/revision |
| `$DEMO_RUN/authorization.json` | 用本轮基线 Policy ID 实例化授权配置模板 |
| `/opt/asc-demo/private/github.token` | Host 生成一次性合成业务真值；不是真实账号密钥 |
| `$DEMO_RUN/data/credentials/store.json` | daemon 导入并托管业务真值；实际路径由 policy get 查询 |
| `$DEMO_RUN/evidence/gateway-grant.json` | 本轮 Scope 的实际凭据签发结果 |
| `/run/asc-demo/work/keyfile`、`keyfile.alias` | 原生 CLI 导出本轮假值，再建立硬链接 |
| `/run/agent-sec-gateway/ca-bundle.pem` | Gateway 启用后生成的公开信任包，由实际 grant 提供 |
| `/run/asc-demo/work/qoder-config/.auth` | 本机已授权账号的认证材料，不包含在分发包中 |
| `$DEMO_RUN/agentsight-header` | 仅 Host 查询 AgentSight 所用的认证头文件；不包含在分发包中 |

## 2. 版本、代码与前置条件

录制基线为 ANOLISA `5dfaf4d4158c9b1d7254b2aac5f725137074ecc6` 加本目录中的 CLI/凭据补丁；SecCore 显示版本为 1.2.0，Qoder CLI 为 1.1.85，mitmproxy 为 12.2.3。录制用 AgentSight 为 0.15.3，内核为 Linux 6.6.102 系列。版本号相同不代表具备这里使用的未合入补丁。

Host 需要 systemd、cgroup v2、BPF-LSM、BTF、nftables、bubblewrap、Python 3、jq、curl、openssl、util-linux，以及已经安装的 AgentSight 与 enforcer。首次安装 AgentSight 按组件部署指南完成；本流程从其服务已安装开始，不包含操作系统、内核或账号订阅的安装。

**已有演示主机不需要从头构建。** 2026-11-11 已通过只读查询确认以下安装与运行状态；这些是检查时的快照，开始下一轮前仍须重新查询。

| 组件 | 已安装入口与检查结果 |
|---|---|
| Demo daemon | `/opt/asc-demo/bin-formal/agent-sec-daemon`；`asc-demo-formal-agent-7jmaa8br.service` 正在运行，使用 `/run/asc-demo/control/daemon.sock` |
| Demo CLI | `/opt/asc-demo/bin-formal/agent-sec-cli`；版本 1.2.0，支持重复 `--policy`、`--export-file`，可通过 `gateway key list` 查询凭据位置 |
| Gateway | `/opt/agent-sec-gateway/current/mitmdump` 12.2.3；`agent-sec-gateway.service` 正在运行，Demo daemon 查询 `enabled=true`、`ready=true` |
| AgentSight / enforcer | 两个服务均正在运行 |

Demo CLI、daemon 和 Gateway addon 的 SHA-256 与本包记录一致。当前 `binding list` 为 0，Gateway 中保留旧 Scope 但没有 Binding；这只说明服务已安装且可查询，不代表新一轮 Sandbox/Qoder 已启动并受保护。可跳过源码构建和依赖安装，保留第 2 节的必要检查，再按第 3～6 节准备和执行本轮演示。

开始新一轮前先按旧一轮真实 ID、配置和服务名完成撤销。当前占用 Demo socket 的是 `asc-demo-formal-agent-7jmaa8br.service`，不是后文新一轮使用的 `asc-demo-agent.service`；清理旧轮时应使用前者。不要同时启动第二个 daemon 争用该 socket，也不要停止另外运行的系统 `agent-sec-core.service`。本次材料检查没有清理、重启或替换任何服务。

### 2.1 取得匹配的二进制

已有演示二进制时直接核对下列路径，无须重编译。Qoder 的可执行文件由已安装的官方 CLI 提供，登录认证不包含在材料包内。

```bash
/opt/asc-demo/bin-formal/agent-sec-cli --version
/opt/asc-demo/bin-formal/agent-sec-cli policy get --help
/opt/asc-demo/bin-formal/agent-sec-cli gateway key list --help
/opt/asc-demo/bin-formal/agent-sec-cli scope create --help
/opt/asc-demo/bin-formal/agent-sec-cli gateway credentials --help
/opt/asc-demo/bin-native/qodercli --version
/opt/asc-demo/bin-native/authorized_sandbox --help
/opt/agent-sec-gateway/current/mitmdump --version
```

必须能看到可重复的 `--policy ID@REVISION` 和 `--export-file`。连接本轮 daemon 后，还须核对 `gateway key list` 返回 `storeFile` 和 `details`；帮助信息不能证明 daemon 支持位置元数据。`policy get` 仅查询策略定义。原二进制摘要保存在 [recorded-provenance.json](evidence/recorded-provenance.json)。重新构建的二进制不要求与历史构建字节一致，但需要通过相关功能检查。

当前补丁已移除历史 CLI 的 `policy get --credential-locations` 特例，位置查询统一使用现有 `gateway key list`。已安装的演示二进制也支持该查询，无须为这项流程调整重新构建。材料更新没有替换二进制或修改历史录像、哈希与证据；补丁重建得到的是当前流程版本，不是历史二进制的逐字节复现。

只有缺少匹配二进制、迁移环境或修改实现时，才需要从源码构建。`manifest.json` 的 `source_base` 记录用于还原演示实现的基线，不要求宿主仓库当前 HEAD 与它相同。

需要构建当前材料对应实现时，使用**基线 `5dfaf4d4` 的独立 checkout**。以下命令以材料已放在 `~/anolisa/defense-in-depth-demo` 为例，创建新的构建目录，不切换现有仓库分支。`DEMO_REPO` 目标必须尚不存在；不要再次应用到已经包含相同修改的工作区。

```bash
export DEMO_KIT="$HOME/anolisa/defense-in-depth-demo"
export DEMO_REPO="$HOME/anolisa-demo-build-5dfaf4d4"
git -C "$HOME/anolisa" worktree add --detach "$DEMO_REPO" 5dfaf4d4158c9b1d7254b2aac5f725137074ecc6
cd "$DEMO_REPO"
test "$(git rev-parse HEAD)" = 5dfaf4d4158c9b1d7254b2aac5f725137074ecc6
git apply --check "$DEMO_KIT/patches/cli-credential-locations.patch"
git apply "$DEMO_KIT/patches/cli-credential-locations.patch"

cd "$DEMO_REPO/src/agent-sec-core/v2"
cargo build --locked --release -p asc-cli -p asc-daemon
cargo build --locked --release -p asc-pep-runtime --example authorized_sandbox

cd "$DEMO_REPO/src/agent-sec-core/linux-sandbox"
cargo build --locked --release
```

检查时宿主 `~/anolisa` 的 HEAD 为 `ca7dfc79b3203b41e376f5380e527f333d255629`；在该 HEAD 上执行 `git apply --check` 也通过，但本次没有实际应用、构建或验证该组合。检查补丁可应用，不等于已有 Scope 多策略、假值导出与 Gateway 位置查询能力，也不证明新版行为与录制基线一致。若选择迁移到新版，仍须实际应用修改、构建并核对 CLI 帮助及整轮行为；为了运行现有 Demo 无须做这次迁移。

在 Host 以 root 安装上述 Linux 构建产物。下面将 helper 安装为历史使用的文件名 `linux-sandbox-static`；文件名不保证链接方式，运行依赖须在 Host 可用。若构建和运行主机不同，先核对架构和 libc 兼容性。

```bash
install -d -m 0755 /opt/asc-demo/bin-formal /opt/asc-demo/bin-native
install -m 0755 "$DEMO_REPO/src/agent-sec-core/v2/target/release/agent-sec-cli" /opt/asc-demo/bin-formal/agent-sec-cli
install -m 0755 "$DEMO_REPO/src/agent-sec-core/v2/target/release/agent-sec-daemon" /opt/asc-demo/bin-formal/agent-sec-daemon
install -m 0755 /opt/asc-demo/bin-formal/agent-sec-cli /opt/asc-demo/bin-native/agent-sec-cli
install -m 0755 "$DEMO_REPO/src/agent-sec-core/v2/target/release/examples/authorized_sandbox" /opt/asc-demo/bin-native/authorized_sandbox
install -m 0755 "$DEMO_REPO/src/agent-sec-core/linux-sandbox/target/release/linux-sandbox" /opt/asc-demo/bin-native/linux-sandbox-static
export DEMO_QODER_BIN=/absolute/path/to/installed/qodercli
install -m 0755 "$DEMO_QODER_BIN" /opt/asc-demo/bin-native/qodercli
```

Qoder 必须是 `/opt/asc-demo/bin-native/qodercli` 这一真实入口；若换路径，须同时修改 `baseline.cedar`、`baseline.json` 与启动命令，并重新验证。PII addon 直接使用材料包的部署副本，不需要把旧 PII 提交整笔合并到当前分支；[manifest.json](manifest.json) 保留其来源和哈希。

### 2.2 新环境才执行的 Host 准备

以下命令在 Host root 终端执行。先进入材料目录，再保存路径；后续 `DEMO_RUN` 是本次新建的 root 私有运行目录。

```bash
cd /absolute/path/to/defense-in-depth-demo
export DEMO_KIT="$PWD"
export DEMO_RUN="/opt/asc-demo/session-$(date +%Y%m%d-%H%M%S)"
export AGENT_SEC_DAEMON_SOCKET=/run/asc-demo/control/daemon.sock
export PATH=/opt/asc-demo/bin-formal:/usr/sbin:/usr/bin:/sbin:/bin
umask 077
set -o pipefail

id -un
getent passwd asc-pii-demo
```

若专用用户不存在，先创建；已存在时跳过 `useradd`。UID 从实际账号读取，不要求必须为历史的 1001，也不能使用 root。

```bash
useradd --create-home --user-group --shell /bin/bash asc-pii-demo
```

```bash
export DEMO_UID="$(id -u asc-pii-demo)"
test "$DEMO_UID" -ne 0
id asc-pii-demo
install -d -m 0755 /opt/asc-demo /opt/asc-demo/live /opt/asc-demo/launcher
install -d -m 0700 "$DEMO_RUN" "$DEMO_RUN/evidence" "$DEMO_RUN/data" /opt/asc-demo/private /opt/asc-demo/evidence
install -d -m 0755 /run/asc-demo /run/asc-demo/control /run/asc-demo/readonly
install -d -m 0700 -o asc-pii-demo -g asc-pii-demo /run/asc-demo/work
install -d -m 0700 -o asc-pii-demo -g asc-pii-demo /run/asc-demo/work/home /run/asc-demo/work/tmp /run/asc-demo/work/qoder-config
install -m 0644 "$DEMO_KIT/config/permissions.json" /opt/asc-demo/live/permissions.json
install -m 0600 "$DEMO_KIT/config/skillsec.json" "$DEMO_RUN/skillsec.json"
```

`permissions.json` 保留了实测快照中的只读兼容路径 `/opt/asc-demo/launcher`、`/opt/asc-demo/live` 和 `/opt/asc-demo/agent-command.json`。它们不作为本轮启动包装器。新环境为最后一个路径创建空 JSON 即可；已有演示主机保留原文件。

```bash
test -e /opt/asc-demo/agent-command.json || printf '{}\n' > /opt/asc-demo/agent-command.json
chmod 0644 /opt/asc-demo/agent-command.json
```

AgentSight 必须已启用文件保护 profile，且服务在宿主初始 PID namespace。先准备 Host 查询所用的认证头；下面是录制环境的 Dashboard token 文件位置，自定义 storage 目录时改为实际路径。认证内容保留在 root 私有目录，不打印、不注入 Qoder。

```bash
export DEMO_SIGHT_TOKEN_FILE=/var/log/sysak/.agentsight/.dashboard_token
test -r "$DEMO_SIGHT_TOKEN_FILE"
printf 'Authorization: Bearer %s\n' "$(cat "$DEMO_SIGHT_TOKEN_FILE")" > "$DEMO_RUN/agentsight-header"
chmod 0600 "$DEMO_RUN/agentsight-header"
```

准备阶段查询，不把进程启动当成防护验收：

```bash
cat /sys/kernel/security/lsm
test -r /sys/kernel/btf/vmlinux
stat -fc %T /sys/fs/cgroup
systemctl status agentsight.service agentsight-enforcer.service --no-pager
curl --fail --silent --show-error -H @"$DEMO_RUN/agentsight-header" http://127.0.0.1:7396/api/enforcement/health | jq .
```

健康结果至少核对 `ready`、`file_entry_delete_protection`、`ordinary_write_protection` 与 `static_mount_topology` 的实际能力。已核对本次演示使用 `ACTPLANE_PINNED_PROFILE=agent-file-guard`；如果专用环境尚未启用，在没有 Agent/Binding 的准备阶段安装以下 drop-in 并重启。重启会影响已有绑定，不能对共享业务直接执行。

```bash
install -d -m 0755 /etc/systemd/system/agentsight-enforcer.service.d
install -m 0644 "$DEMO_KIT/config/agentsight-file-guard.conf" /etc/systemd/system/agentsight-enforcer.service.d/demo-file-guard.conf
systemctl daemon-reload
systemctl restart agentsight-enforcer.service
systemctl start agentsight.service
curl --fail --silent --show-error -H @"$DEMO_RUN/agentsight-header" http://127.0.0.1:7396/api/enforcement/health | jq .
```

采用此 profile 的文件保护与独立 Gateway 凭据保护各有职责，不能据此宣称 AgentSight 的 `credential_enforce` 也开启。本次健康接口中该值为 false。

### 2.3 测试数据、只读目标与合成真密钥

若已有同一路径的旧 Sandbox/Scope，先按第 8 节撤销并确认清理完成。不要覆盖有效绑定正在保护的文件。以下步骤在新一轮开始前执行。

```bash
install -m 0600 -o asc-pii-demo -g asc-pii-demo "$DEMO_KIT/data/customers.json" /run/asc-demo/work/customers.json
install -m 0600 -o asc-pii-demo -g asc-pii-demo "$DEMO_KIT/data/customers-escaped.json" /run/asc-demo/work/customers-escaped.json
install -m 0600 -o asc-pii-demo -g asc-pii-demo "$DEMO_KIT/data/report.json" /run/asc-demo/work/report.json
printf 'HOST_WRITABLE_BASELINE\n' > /run/asc-demo/readonly/sentinel
chown asc-pii-demo:asc-pii-demo /run/asc-demo/readonly/sentinel
chmod 0600 /run/asc-demo/readonly/sentinel
runuser -u asc-pii-demo -- sh -c 'printf "host-baseline\n" >> /run/asc-demo/readonly/sentinel'
sha256sum /run/asc-demo/readonly/sentinel | tee "$DEMO_RUN/evidence/sentinel-before.sha256"
```

Host 同 UID 可以写 sentinel；稍后的失败才有依据归因于 Sandbox 只读挂载。不要在这里执行 C01～C13 的 Agent 验证。

只在全新演示环境生成一次合成真密钥。它仅被本地测试上游接受，不是真实 GitHub 密钥。已有该文件且上游/凭据 store 使用它时不要重写。

```bash
test ! -e /opt/asc-demo/private/github.token
python3 -c 'from pathlib import Path; import secrets; p=Path("/opt/asc-demo/private/github.token"); f=p.open("x"); f.write("ghp_" + secrets.token_hex(18) + "\n"); f.close(); p.chmod(0o600)'
stat -c '%U %a %n' /opt/asc-demo/private/github.token
```

不要把这个文件放进材料包、工作目录或 Qoder 的环境。Qoder 账号认证与此业务测试凭据是两件事。

### 2.4 HTTPS 测试上游

先确认 `198.18.0.1`、TCP 443 和 18081 未被其他用途占用。`report.demo.test` 是固定测试域名，地址来自专用测试网段。已有相同配置时复用，不重复添加。

```bash
ip -brief address
ss -ltnp 'sport = :443 or sport = :18081'
getent hosts report.demo.test
```

仅在没有该测试地址/映射的新环境执行：

```bash
ip address add 198.18.0.1/32 dev lo
cp -a /etc/hosts "$DEMO_RUN/evidence/hosts.before"
printf '\n198.18.0.1 report.demo.test\n' >> /etc/hosts
```

创建仅用于本次测试的证书和私钥。再次运行时保留现有有效证书，不覆盖运行中的 Gateway CA 或测试服务私钥。

```bash
install -d -m 0755 /opt/asc-demo/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout /opt/asc-demo/private/server.key \
  -out /opt/asc-demo/certs/server.pem \
  -subj '/CN=report.demo.test' \
  -addext 'subjectAltName=DNS:report.demo.test,IP:198.18.0.1' \
  -addext 'basicConstraints=critical,CA:TRUE'
chmod 0600 /opt/asc-demo/private/server.key
chmod 0644 /opt/asc-demo/certs/server.pem
```

Gateway 仍须信任公网模型的 CA。因此 `upstream-trust.pem` 要包含**系统 CA + 测试证书**，不是只信任本地测试证书。下列系统 CA 路径是示例，按发行版确认（Debian 系通常为 `/etc/ssl/certs/ca-certificates.crt`，其他系统可能为 `/etc/pki/tls/certs/ca-bundle.crt`）。

```bash
export DEMO_SYSTEM_CA=/etc/ssl/certs/ca-certificates.crt
test -r "$DEMO_SYSTEM_CA"
cat "$DEMO_SYSTEM_CA" /opt/asc-demo/certs/server.pem > /opt/asc-demo/certs/upstream-trust.pem
chmod 0644 /opt/asc-demo/certs/upstream-trust.pem
install -m 0644 "$DEMO_KIT/upstream/upstream.py" /opt/asc-demo/live/upstream.py
touch /opt/asc-demo/evidence/upstream.jsonl
systemd-run --unit=asc-demo-upstream --collect /usr/bin/python3 /opt/asc-demo/live/upstream.py
curl --fail --silent --show-error http://127.0.0.1:18081/stats | jq .
```

若最后一步连接失败，检查 `journalctl -u asc-demo-upstream --no-pager -n 30`，等监听就绪再继续。上游只记录请求方法、路径、长度、摘要和认证结果，不保存 Authorization 或客户正文。

**这份实测上游代码只校验合成 token，没有实施路径/方法白名单，也没有 chunked body 解码器。** Demo 的 curl 从文件提交有限长度正文，路径/方法的拒绝由 Gateway 验证。不能拿此服务证明流式上传或上游访问控制能力。

### 2.5 部署 Demo Gateway

如未安装 mitmproxy，复用材料中的仓库安装器（下载版本和 SHA-256 已固定）；它仅安装依赖和专用服务用户，不包装 Demo 业务步骤。

```bash
sh "$DEMO_KIT/gateway/install-mitmproxy.sh"
```

如已安装 12.2.3，则跳过安装器。之后复制**已核对的完整 addon**和服务配置；既有专用配置先备份，不能覆盖其他 Gateway 实例。

```bash
install -d -m 0755 /opt/asc-demo/addon
install -d -m 0700 -o agent-sec-gw -g agent-sec-gw /opt/asc-demo/gateway-conf
install -m 0644 "$DEMO_KIT/gateway/asc_gateway_addon.py" /opt/asc-demo/addon/asc_gateway_addon.py
install -m 0644 "$DEMO_KIT/gateway/asc_gateway_policy.py" /opt/asc-demo/addon/asc_gateway_policy.py
install -m 0644 "$DEMO_KIT/gateway/diagnostics.py" /opt/asc-demo/diagnostics.py
install -m 0644 "$DEMO_KIT/gateway/agent-sec-gateway.service" /run/systemd/system/agent-sec-gateway.service
systemctl daemon-reload
systemctl show agent-sec-gateway.service -p User -p ExecStart
```

暂不直接启动 Gateway；后面由 daemon 的 `gateway enable` 创建运行目录并启动。`/run/systemd/system` 下是临时演示 unit，重启后须重新安装。unit 中 PII 调用的是 `/opt/asc-demo/bin-native/agent-sec-cli`，必须同步安装与 daemon 匹配的版本。

此 addon 的业务正文处理为：凭据授权 → 最多 256 KiB 完整缓冲 → 原文扫描 → 可解析 JSON 的解码文本扫描 → 完整 pass 后转发原始 body。正文超限、扫描超时或不完整不放行；不支持压缩正文或无限上传流。`responseRewrite=buffered` 是另一个方向的响应密钥回写保护。

模型豁免只匹配 `POST https://api2.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation`，并核对 TLS SNI/Host。该接口保持流式转发、跳过 PII；业务 `report.demo.test` 不在豁免内。PII 日志位于 `/opt/asc-demo/gateway-conf/pii-trace.jsonl`，HTTP 元数据位于同目录 `metadata.jsonl`。

### 2.6 Qoder 登录准备

在 Host 私有配置目录完成 Qoder 1.1.85 登录，确认账号可用，再把**本次授权使用的 `.auth` 文件**复制到 `/run/asc-demo/work/qoder-config/.auth`。认证必须在发送业务 prompt 之前完成，不展示认证内容，不把原始客户记录用于登录测试。

```bash
export DEMO_AUTH_FILE=/absolute/path/to/authorized/qoder-config/.auth
test -f "$DEMO_AUTH_FILE"
install -m 0600 -o asc-pii-demo -g asc-pii-demo "$DEMO_AUTH_FILE" /run/asc-demo/work/qoder-config/.auth
```

如果安装的 Qoder 使用不同认证格式，应先完成该版本的登录适配，不能把任意配置文件改名成 `.auth`。历史联调发现过期认证会调用另一个刷新接口并被 PII 拒绝；不要通过扩大整个模型域名豁免来掩盖认证问题。

## 3. 阶段一：Host 创建三份策略

此处起是实际 Demo 的第一段。终端 A 仍为 Host root，变量沿用第 2 节；本轮使用新的 `DEMO_RUN/data`。不要与使用同一 socket/Gateway 运行目录的其他 daemon 并行启动。

```bash
systemd-run --unit=asc-demo-setup --collect \
  --setenv="AGENT_SEC_DATA_DIR=$DEMO_RUN/data" \
  /opt/asc-demo/bin-formal/agent-sec-daemon serve \
  --socket /run/asc-demo/control/daemon.sock \
  --skillsec-config "$DEMO_RUN/skillsec.json"
agent-sec-cli gateway status
agent-sec-cli policy list
```

若 socket 尚未就绪，停止后续步骤，查看 `journalctl -u asc-demo-setup --no-pager -n 30`，就绪后重新查询。`systemd-run` 返回成功不代表 daemon 已可用。

### 3.1 Sandbox 基线（Cedar）

```bash
agent-sec-cli policy create --name demo-sandbox-baseline \
  --file "$DEMO_KIT/policies/baseline.json" | tee "$DEMO_RUN/evidence/baseline-create.json"
export SANDBOX_POLICY_ID="$(jq -er .policyId "$DEMO_RUN/evidence/baseline-create.json")"
export SANDBOX_POLICY_REVISION="$(jq -er .revision "$DEMO_RUN/evidence/baseline-create.json")"
agent-sec-cli policy get --policy-id "$SANDBOX_POLICY_ID" --revision "$SANDBOX_POLICY_REVISION"
```

讲解：允许指定 Qoder 启动、读取运行依赖、联网；只能写工作目录，禁止读取 `/root`。这份 Policy 供启动 PDP 使用，不加入文件/凭据 Scope。JSON 的 `language=cedar` 和 `content.text` 是 Cedar 的传输封装。

### 3.2 指定文件保护（Cedar）

```bash
agent-sec-cli policy create --name demo-keyfile-protection \
  --file "$DEMO_KIT/policies/file.json" | tee "$DEMO_RUN/evidence/file-create.json"
export FILE_POLICY_ID="$(jq -er .policyId "$DEMO_RUN/evidence/file-create.json")"
export FILE_POLICY_REVISION="$(jq -er .revision "$DEMO_RUN/evidence/file-create.json")"
agent-sec-cli policy get --policy-id "$FILE_POLICY_ID" --revision "$FILE_POLICY_REVISION"
```

讲解：工作目录整体可写，但 `keyfile` 和 `keyfile.alias` 两个路径禁止普通写入和删除。两个硬链接名称均明确列入 Cedar；不承诺自动保护任意新增别名。

### 3.3 凭据用途（原生 JSON）

```bash
agent-sec-cli gateway key list
agent-sec-cli gateway key add github --secret-file /opt/asc-demo/private/github.token
agent-sec-cli policy create --name demo-report-credential \
  --file "$DEMO_KIT/policies/credential.json" | tee "$DEMO_RUN/evidence/credential-create.json"
export CREDENTIAL_POLICY_ID="$(jq -er .policyId "$DEMO_RUN/evidence/credential-create.json")"
export CREDENTIAL_POLICY_REVISION="$(jq -er .revision "$DEMO_RUN/evidence/credential-create.json")"
agent-sec-cli policy get --policy-id "$CREDENTIAL_POLICY_ID" \
  --revision "$CREDENTIAL_POLICY_REVISION"
agent-sec-cli gateway key list
```

先说清授权组合：只允许真密钥用于 `GET /v1/ping` 和 `POST /v1/reports`，域名均为 `report.demo.test`、协议为 HTTPS。满足对应方法与路径组合才替换 Authorization 中的假值。完整显示 `effect/category/action/target` 及 `responseRewrite`，长输出使用分页，不过滤字段。

真值输入在 `/opt/asc-demo/private/github.token`，导入后存放于本次 `$DEMO_RUN/data/credentials/store.json`；以 `gateway key list` 实际返回为准。`details[].id` 对应 Policy 的 `credentialId`，`importFile` 是导入源，`storeFile` 是托管位置。阶段一尚未签发 Scope 假值，没有本 Scope 的导出记录；不能提前填入历史 Scope 的记录。

## 4. 阶段二 A：Host 创建 Scope 并启动 Sandbox

### 4.1 加载刚创建的 PDP 基线

```bash
jq --arg id "$SANDBOX_POLICY_ID" '.baseline_policy = $id' \
  "$DEMO_KIT/config/authorization-template.json" > "$DEMO_RUN/authorization.json"
systemctl stop asc-demo-setup.service
systemd-run --unit=asc-demo-agent --collect \
  --setenv="AGENT_SEC_DATA_DIR=$DEMO_RUN/data" \
  /opt/asc-demo/bin-formal/agent-sec-daemon serve \
  --socket /run/asc-demo/control/daemon.sock \
  --skillsec-config "$DEMO_RUN/skillsec.json" \
  --authorization-config "$DEMO_RUN/authorization.json"
agent-sec-cli policy get --policy-id "$SANDBOX_POLICY_ID" --revision "$SANDBOX_POLICY_REVISION"
agent-sec-cli gateway status
```

继续使用相同 data 目录，所以策略和已导入真密钥保留。再次等实际 CLI 查询成功再继续；TTL 60 秒是启动授权的接收期限，不是 Sandbox 的运行时长。

### 4.2 创建直接选择 Qoder 的 Scope

```bash
agent-sec-cli scope create --process-name qodercli --owner-uid "$DEMO_UID" \
  --policy "$FILE_POLICY_ID@$FILE_POLICY_REVISION" \
  --policy "$CREDENTIAL_POLICY_ID@$CREDENTIAL_POLICY_REVISION" \
  | tee "$DEMO_RUN/evidence/scope-create.json"
export SCOPE_ID="$(jq -er .scopeId "$DEMO_RUN/evidence/scope-create.json")"
agent-sec-cli scope get --scope-id "$SCOPE_ID"
agent-sec-cli gateway enable
agent-sec-cli gateway status
```

Scope.ownerUid 是 Qoder 的 UID，凭据 Scope 不能省略也不能填 0。Scope 只引用文件与凭据策略，且固定各自 revision；更新 Policy 不会自动更新已有 Scope。

确认 Gateway `enabled=true`、`ready=true` 后，签发本 Scope 的假值并落盘。`keyfile` 必须不存在；若是上一轮的文件，先完成第 8 节清理，不能在有效 Binding 期间删除重建。

```bash
agent-sec-cli gateway credentials --scope "$SCOPE_ID" \
  --export-file /run/asc-demo/work/keyfile | tee "$DEMO_RUN/evidence/gateway-grant.json"
ln /run/asc-demo/work/keyfile /run/asc-demo/work/keyfile.alias
ls -li /run/asc-demo/work/keyfile /run/asc-demo/work/keyfile.alias
agent-sec-cli policy get --policy-id "$CREDENTIAL_POLICY_ID" \
  --revision "$CREDENTIAL_POLICY_REVISION"
agent-sec-cli gateway key list
```

此时 `gateway key list` 应完整显示真值导入源、store，以及本 Scope 的 `fakes[].exportFile`；按 `scopeId` 区分历史记录。它们属于 Gateway 运行时清单，前一条 `policy get` 展示策略定义。假的业务 token 保存在 `keyfile`，同时通过下一步的环境变量提供给 Qoder。`gateway-grant.json` 只放在 root 私有证据目录；不 `eval` API 返回值。

如需展示内容，只展示已确认是本 Demo 合成的业务真假值，明确标注其位置；不要展示 Qoder `.auth`。从现在起，同一轮不修改 keyfile/alias 的内容或 inode。

### 4.3 直接启动 Qoder

下面是完整启动命令。`runuser` 切换专用用户；`env` 设置 Qoder 工作目录、假业务凭据和公开 CA；`authorized_sandbox` 请求 PDP、安装 Sandbox 并启动 Qoder。没有额外的演示启动脚本。

```bash
cd /run/asc-demo/work
runuser -u asc-pii-demo -- env \
  HOME=/run/asc-demo/work/home TMPDIR=/run/asc-demo/work/tmp \
  PATH=/opt/asc-demo/bin-native:/usr/bin:/bin \
  TERM=xterm-256color COLORTERM=truecolor LANG=C.UTF-8 \
  GITHUB_TOKEN="$(jq -er .environment.GITHUB_TOKEN "$DEMO_RUN/evidence/gateway-grant.json")" \
  GH_TOKEN="$(jq -er .environment.GH_TOKEN "$DEMO_RUN/evidence/gateway-grant.json")" \
  SSL_CERT_FILE=/run/agent-sec-gateway/ca-bundle.pem \
  REQUESTS_CA_BUNDLE=/run/agent-sec-gateway/ca-bundle.pem \
  CURL_CA_BUNDLE=/run/agent-sec-gateway/ca-bundle.pem \
  GIT_SSL_CAINFO=/run/agent-sec-gateway/ca-bundle.pem \
  NODE_EXTRA_CA_CERTS=/run/agent-sec-gateway/ca-bundle.pem \
  DENO_CERT=/run/agent-sec-gateway/ca-bundle.pem \
  /opt/asc-demo/bin-native/authorized_sandbox \
  --helper /opt/asc-demo/bin-native/linux-sandbox-static \
  --socket /run/asc-demo/control/daemon.sock \
  --permissions /opt/asc-demo/live/permissions.json \
  --agent-id demo-report-agent --agent-type qoder \
  -- /opt/asc-demo/bin-native/qodercli \
  --config-dir /run/asc-demo/work/qoder-config \
  --cwd /run/asc-demo/work --setting-sources user \
  --permission-mode bypass_permissions --max-model-request-retries 0
```

必须先 `cd /run/asc-demo/work`，否则 PEP 的实际 cwd 可能不在权限范围内。Qoder 不带 `-p` 或初始任务；先保持原生输入框待命。`bypass_permissions` 只关闭 Qoder 自身工具确认，不关闭三层防护。

### 4.4 Host 确认两个 Binding 后才发送 prompt

终端 B 设置与 A 相同的 `DEMO_RUN`、socket 和 PATH。用真实 `scope-create.json` 恢复 ID，完整查询，不复用历史 PID/Binding ID。

```bash
export DEMO_RUN=/opt/asc-demo/session-YYYYMMDD-HHMMSS
export AGENT_SEC_DAEMON_SOCKET=/run/asc-demo/control/daemon.sock
export PATH=/opt/asc-demo/bin-formal:/usr/sbin:/usr/bin:/sbin:/bin
export SCOPE_ID="$(jq -er .scopeId "$DEMO_RUN/evidence/scope-create.json")"
agent-sec-cli scope get --scope-id "$SCOPE_ID"
agent-sec-cli binding list --limit 100 --offset 0 | tee "$DEMO_RUN/evidence/bindings-ready.json"
agent-sec-cli gateway status | tee "$DEMO_RUN/evidence/gateway-ready.json"
curl --fail --silent --show-error -H @"$DEMO_RUN/agentsight-header" http://127.0.0.1:7396/api/enforcement/health | jq .
curl --fail --silent --show-error -H @"$DEMO_RUN/agentsight-header" http://127.0.0.1:7396/api/enforcement/bindings | jq .
```

查询沿用第 2.2 节生成的 Host 认证头文件；若服务 token 已轮换，先在 Host 更新此文件。不要把 Dashboard token 放入 Agent。

逐项核对：

1. Scope 的两份 Policy ID/revision 正确。
2. 本 Scope 的两个 Binding 都是 `READY`，均指向同一个真实 Qoder 宿主 PID/start time，UID 为专用用户。
3. AgentSight 实际部署对应文件 Binding；Gateway 的该 Scope `bindings` 包含凭据 Binding ID。全局 `ready=true` 不够。
4. 工作目录挂载为 rw，sentinel 所在挂载为 ro；保护文件与别名仍指向同一个 inode。

```bash
export QODER_PID=REPLACE_WITH_BINDING_PROCESS_PID
ps -p "$QODER_PID" -o pid,ppid,uid,comm,lstart
findmnt --task "$QODER_PID" --target /run/asc-demo/work --output TARGET,OPTIONS
findmnt --task "$QODER_PID" --target /run/asc-demo/readonly/sentinel --output TARGET,OPTIONS
stat -c '%d %i %u %a %n' /run/asc-demo/work/keyfile /run/asc-demo/work/keyfile.alias
sha256sum /run/asc-demo/work/keyfile /run/asc-demo/work/keyfile.alias | tee "$DEMO_RUN/evidence/keyfiles-before.sha256"
date --iso-8601=ns | tee "$DEMO_RUN/evidence/bindings-ready-at.txt"
```

满足上述条件后才向终端 A 的 Qoder 发送 C01。Scope 自动发现不会暂停进程；本 Demo 通过操作者控制首条任务时间。启动认证/遥测和此前建立的连接不因此自动成为受保护证据。

## 5. 阶段二 B、三、四：Qoder 执行 13 项任务

打开 [Qoder 操作单](prompts/README_zh.md)，逐条复制 C01～C13 到**同一个**原生 Qoder 会话。一次只发送一条，等待真实工具执行结束后继续。操作单提供参考命令，便于解释模型实际做了什么；Host 操作者不能拿这些命令代替 Qoder 操作。

| 阶段 | 用例 | 目标 |
|---|---|---|
| 2B | C01 | 普通文件可写、可读，证明任务还能工作 |
| 3 | C02 | sentinel 写入被 Sandbox 拒绝 |
| 3 | C03～C06 | 假密钥文件写入、删除、子进程删除、已登记硬链接删除被 AgentSight 拒绝 |
| 4 | C07～C09 | 允许的 ping 成功；未授权 admin 被 Gateway 拒绝；普通报告成功 |
| 4 | C10～C11 | 客户原文和 Unicode 转义样本被 PII 拒绝，上游计数不增加 |
| 4 | C12～C13 | Qoder 本地计算 count=2、total=30，直接提交后成功 |

模型口头拒绝不算系统拦截。遇到预期拒绝可继续下一条；若修改/删除意外成功、Qoder 会话退出、策略变化或拒绝无法归因，停止本轮并留证。不得编造 CLI 输出、由 Host 代执行后展示结果，或把两轮不同身份拼成同一次连续运行。

## 6. Host 后台取证与验收

每个用例前后在终端 B 记录时间、上游计数、文件身份与相关事件。以下仅查询状态，不执行 Agent 防护探针。

```bash
export CASE=C10
date --iso-8601=ns | tee "$DEMO_RUN/evidence/$CASE-before-time.txt"
curl --fail --silent --show-error http://127.0.0.1:18081/stats | tee "$DEMO_RUN/evidence/$CASE-upstream-before.json"
```

在 Qoder 执行该条 prompt 并结束后：

```bash
date --iso-8601=ns | tee "$DEMO_RUN/evidence/$CASE-after-time.txt"
curl --fail --silent --show-error http://127.0.0.1:18081/stats | tee "$DEMO_RUN/evidence/$CASE-upstream-after.json"
agent-sec-cli binding list --limit 100 --offset 0 | tee "$DEMO_RUN/evidence/$CASE-bindings.json"
agent-sec-cli gateway status | tee "$DEMO_RUN/evidence/$CASE-gateway.json"
agent-sec-cli events --event-type pii_scan \
  --since "$(cat "$DEMO_RUN/evidence/$CASE-before-time.txt")" \
  --limit 1000 -o json > "$DEMO_RUN/evidence/$CASE-pii.json"
curl --fail --silent --show-error -H @"$DEMO_RUN/agentsight-header" \
  'http://127.0.0.1:7396/api/enforcement/violations?limit=100' \
  > "$DEMO_RUN/evidence/$CASE-file-violations.json"
sha256sum --check "$DEMO_RUN/evidence/keyfiles-before.sha256"
sha256sum --check "$DEMO_RUN/evidence/sentinel-before.sha256"
```

列表超过一页时继续查询后续页；上面保留完整响应，分析时再按本 Scope、PID、操作路径和时间窗口关联。不要把同时发生的 Qoder 遥测扫描当成业务请求扫描。

| 对象 | 必须核对的证据 |
|---|---|
| Sandbox 拒绝 | 真实工具错误、Host 同 UID 可写基线、Qoder 挂载为只读、sentinel 摘要不变 |
| AgentSight 拒绝 | 本 Binding/进程后代/路径/操作/时间匹配的 blocked violation，两个目标 inode 与摘要不变 |
| 凭据用途拒绝 | 实际 `403 credential_not_allowed`，对应上游请求计数零增量 |
| PII 拒绝 | 实际 `403 pii_blocked`，关联扫描输入 hash/字节数/命中类型，上游零增量 |
| 允许提交 | 实际 HTTP 200、`auth_ok=true`、完整扫描 pass、上游收到本次正文摘要 |

原录制 C10 是 112 字节原文命中一个 `credit_card`；C11 是 107 字节原文通过、22 字节解码文本命中同类。C09 普通报告和 C13 聚合报告的序列化空格可能随模型工具而不同，因此以实际文件字节、扫描输入摘要和上游摘要关联，不硬编码历史长度。

Gateway 扫描审计主体是 Gateway 发起的 CLI，不是原始 Agent 身份。模型白名单日志 `scan_skipped` 不等于扫描 pass。网络路由覆盖本次接管的新建 IPv4 TCP 80/443；不宣称覆盖 IPv6、QUIC、其他端口或既有连接。

## 7. 分段暂停、恢复与录制

完成阶段一保留 daemon/Policy；完成阶段二 A 后保留 Scope、Sandbox、Qoder 进程、假值及两个 Binding；阶段二 B～四始终使用同一会话。重新连接终端时核对 PID、start time、UID、Scope 和 Policy revision。`qoder --resume` 创建的新进程不能视为旧进程仍连续存在。

录制直接展示上述命令、完整策略查询、Qoder prompt 和真实输出。每段独立保存 MP4，后续再拼接。失败时先保留错误证据、恢复检查点，再重录最早受影响的片段；若恢复改变进程/策略/凭据身份，相关后续片段也须重录。本材料包不包含录像回放器，不会产生预写的“通过”结果。

## 8. 结束或重新开始一轮

先让 Qoder 正常退出，等待 `authorized_sandbox` 返回实际执行回执；保持 daemon 运行。下面回到终端 A 的原 shell 执行，沿用本轮 Policy/Scope 变量；若换了终端，先从 `$DEMO_RUN/evidence/*-create.json` 恢复 ID/revision。仅操作本次运行保存的 ID。

```bash
agent-sec-cli scope delete --scope-id "$SCOPE_ID"
agent-sec-cli scope list
agent-sec-cli binding list
agent-sec-cli gateway status
```

等待本 Scope/Binding 和路由撤销。`completed=false` 表示仍在清理；若 `DELETE_FAILED`，保留错误后用 `agent-sec-cli scope retry --scope-id "$SCOPE_ID"` 重试。不能仅凭删除受理就重建 Scope 或删除文件。

确认撤销完成后，删除本次运行的文件/凭据 Policy；revision 取实际当前值：

```bash
agent-sec-cli policy delete --policy-id "$FILE_POLICY_ID" --revision "$FILE_POLICY_REVISION"
agent-sec-cli policy delete --policy-id "$CREDENTIAL_POLICY_ID" --revision "$CREDENTIAL_POLICY_REVISION"
```

PDP 基线仍被 daemon 配置引用，须先停止本次授权 daemon，再用同一 data 目录、不加载 `--authorization-config` 的维护实例执行基线删除。这里只重启专用 Demo daemon。

```bash
systemctl stop asc-demo-agent.service
systemd-run --unit=asc-demo-cleanup --collect \
  --setenv="AGENT_SEC_DATA_DIR=$DEMO_RUN/data" \
  /opt/asc-demo/bin-formal/agent-sec-daemon serve \
  --socket /run/asc-demo/control/daemon.sock --skillsec-config "$DEMO_RUN/skillsec.json"
agent-sec-cli policy list
agent-sec-cli policy delete --policy-id "$SANDBOX_POLICY_ID" --revision "$SANDBOX_POLICY_REVISION"
```

确认没有其他 Scope 使用全局 Gateway/业务凭据后，专用环境才执行：

```bash
agent-sec-cli gateway key remove github
agent-sec-cli gateway disable
systemctl stop asc-demo-cleanup.service
```

重录时，在后端清理完成后删除旧假值及普通输出，再按第 2.3 节重置数据：

```bash
rm -- /run/asc-demo/work/keyfile /run/asc-demo/work/keyfile.alias
rm -f -- /run/asc-demo/work/notes.txt
```

新的 Scope 会签发新假值，必须重新导出和注入环境。不要把旧进程交给新 Scope。上游计数可以保留，按每例的前后增量判断；不需要为了画面将全局计数归零。

彻底结束演示时，再停止本次创建的上游、移除本次新增的测试 IP/hosts 项、恢复 Gateway unit 备份并执行 `systemctl daemon-reload`。恢复 `/etc/hosts` 时只撤销本次条目，不覆盖其他人的后续修改。保留 `$DEMO_RUN/evidence`；Qoder 登录文件和真实账户配置不随演示包分发。

## 9. 常见阻塞

| 现象 | 处理 |
|---|---|
| `--policy`、`--export-file` 不识别，或 `gateway key list` 缺少位置字段 | CLI 或 daemon 缺少材料中的源码补丁；先核对二进制路径、帮助和实际响应，不改成脚本拼结果 |
| daemon socket 不存在 | 等实际 CLI 查询成功；看专用 unit 日志，不凭 systemd-run 成功继续 |
| 新 daemon 与旧 Gateway 运行目录冲突 | 回到旧实例撤销 Scope/路由并关闭专用 Gateway；不删除正在使用的运行目录 |
| Qoder 启动 `required launch path is not readable` | 检查实际 cwd 和解析后的可执行路径，先切换到工作目录 |
| Qoder 未登录或认证刷新被 PII 拒绝 | 回到 Host 的私有认证准备，重新同步授权配置，不扩大业务豁免 |
| 文件 Binding 未 READY | 查实际能力/profile、共享文件视图和 AgentSight 错误；不只看服务 active |
| Sandbox 内访问 daemon 返回 EPERM | 严格模式禁止 Host Unix socket 创建；本流程没有提交前 PII 预检，不需要放宽 |
| `pii_request_invalid` / `pii_request_unsupported` | 检查部署 addon、UTF-8、压缩方式和正文类型；不解释为已经命中 PII |
| `pii_scan_busy` / `pii_scan_incomplete` | 扫描繁忙或不完整，保留拒绝，不把它计作数据命中 |
| 上游 HTTP 401 | 检查本次 Scope 假值、Credential Store 真值与测试上游加载的真值是否对应 |
| Qoder 只解释、不调用工具 | 不计为测试通过，明确一次性测试目标后重新验证 |

本文件是材料包的完整操作入口，不依赖包外的设计文档。实现代码和输入文件已包含在本目录；历史版本依据见 [recorded-provenance.json](evidence/recorded-provenance.json)，历史用例结果见 [recorded-results.json](evidence/recorded-results.json)。当前执行结果必须由本轮实际请求产生。
