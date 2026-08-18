# SecCore、AgentSight 与 ActPlane 真实联调故障记录

> 记录日期：2026-08-20。
> 范围：本轮 `prevent_file_deletion`、live OpenClaw Scope、AgentSight real backend、
> ActPlane/BPF-LSM 联调。本文记录实际观察到的问题，不把 mock 结果当作内核约束证据。

## 1. 当前结论

本轮 Binding 失败已经定位到 ActPlane 运行时 policy delta 的内核 admission，且失败发生在
首条 runtime table record 成功写入之前，而不是 Canonical IR、DSL 编译、PID identity 或
`unlink` hook：

```text
AgentSight HTTP 503 enforcer_unavailable
  -> enforcer kernel_failure
  -> append policy delta
  -> runtime policy delta update[0] was not admitted by the kernel
  -> ts_updates[0] remained zero; ts_counts[updates] remained 0
```

一次中间快照的内核统计为：

```json
[
  {"key": 0, "value": 0},
  {"key": 1, "value": 7},
  {"key": 2, "value": 103690},
  {"key": 3, "value": 0}
]
```

后续快照中 `reject` 已增长到 9，`accept` 和 `drop` 仍为 0。`cap_stats` 的槽位依次是
`accept / reject / drain / drop`。因此可以确认：

- 多次 runtime delta record 被内核 callback 计入 `reject`，没有一次被计入 `accept`；
- `drop=0` 排除了 fallback/drop 分支；结合本地 ABI size 测试，未发现 Rust/C record
  大小或布局不一致；
- `cap_drain_tick` 正常运行，而且是一个非常频繁的系统全局 drain 点；
- `source AGENT = exec "**"` 的最小 DSL 也失败，因此问题与长文件路径、
  `namespace_mutation` 规则或目标 OpenClaw 进程无关。

曾根据系统全局 `sys_enter_getpid` tracepoint 提出“record 被其他 TGID 抢先消费”的假设，并在
AgentSight 中加入短生命周期 `CapabilityDrainPump`。2026-08-20 17:03 重启该版本 Enforcer 后，
再次提交 source-only Binding，HTTP 仍返回 503，journal 仍为同一个 `update[0]` admission
错误。因此该实验已经否定“全局 drain 抢消费是这次稳定失败的唯一根因”，pump 随后撤回，
不得把它记录成已完成修复。

被动日志进一步证明：提交前 Enforcer control PID 与目标 OpenClaw PID 都已绑定到同一 runtime
domain，control state 为 `scope_id=1`、`authority_mask=0x7e`。一次临时、显式开启的隔离探针
把同一 blob 改为 `0 updates / 1 rule` 后单独提交，仍得到 `rule[0] was not admitted`，而
`ts_rules[0]` 和 `ts_counts[rules]` 保持为 0。探针完成后已关闭并从源码清除，只保留无副作用的
摘要日志。

实际 pinned map 的 value size/flags 与 BTF 一致，实际加载的 `cap_drain_tick` 也引用这些 map。
因此当前能确认的是：update 和 rule 两类 record 都在实际内核 callback 中、首条 table record
成功写入前被统一拒绝。callback 把完整 dynptr 读取、submitter、feature、authority/scope 和
首次 map update 失败全部合并为同一个 `CAP_STAT_REJECT`，现有 AgentSight/ActPlane 接口不能再
区分具体分支。尝试通过 perf 追踪 `sys_enter_getpid`，最终文件明确报告 `data has no samples`，
不能作为动态证据。若不修改 ActPlane，就需要一个能对 BPF JIT callback 做动态追踪的内核环境，
否则这里是可观测性阻塞，不应继续猜测根因。

## 2. 问题总表

| 编号 | 现象 | 根因或结论 | 解决方式 | 状态 |
|---|---|---|---|---|
| P01 | AgentSight 连接不到 Enforcer UDS | Enforcer 创建的 UDS 为特权用户/组可访问，普通用户启动的 AgentSight 无权限 | Demo 中 AgentSight 与 Enforcer 都以 root 运行；生产使用固定用户组授权 | 已解决 |
| P02 | SecCore 无法读取 AgentSight token | AgentSight 以 root 创建 DB 同目录下 mode `0600` 的 `.dashboard_token` | 向 SecCore 服务账号投递 mode `0600` 的副本，用 `--agentsight-token-file` 启动 | 已解决 |
| P03 | 不清楚 `$RUN_ROOT` 是什么或为何放 `/tmp` | 它只是单次联调的 socket、DB、token、state 和证据目录，不是产品固定目录 | 使用显式、唯一且权限受控的目录；本轮为 `v2/target/e2e/run.Fj2Ya2`，不要求 `/tmp` | 已解决 |
| P04 | `systemctl stop/start` 报 unit not found | 重启时使用了旧 transient unit 名，实际运行的是带 `-full-` 的新 unit | 先用 `systemctl list-units`/`systemctl status` 确认精确 unit 名 | 已解决 |
| P05 | 修改 AgentSight 后执行 `make build`，Enforcer 行为没变化 | `make build` 只构建 `agentsight`；真实 ActPlane backend 在独立的 `agentsight-enforcer` 二进制 | AgentSight API 改动执行 `make build`；Enforcer/adapter 改动执行 `make build-enforcer` 或等价受控构建 | 已解决 |
| P06 | 构建看似在重复拉 submodule | AgentSight 没有把 ActPlane 作为 Git submodule；构建脚本浅拉固定 revision 到 `target/actplane-src/<revision>` | 使用 `make build-enforcer` 和缓存；无需 `git submodule update` | 已澄清 |
| P07 | 认为 `CARGO_HOME` 应放在 AgentSight 目录 | `CARGO_HOME` 是 registry/git cache，不是构建输出；输出默认在仓库 `target/` | 默认使用现有 Cargo 配置；网络受限时配置镜像或预拉取 `ACTPLANE_SOURCE_DIR`，不要为每次构建创建临时 CARGO_HOME | 已澄清 |
| P08 | `credential-exfiltration` profile 无法安装防误删规则 | 该 profile 只预留其声明的 hook/feature；防误删需要 write-rule 能力和 `path_unlink` hook | 本轮切换到 `ACTPLANE_PINNED_PROFILE=full` | 已解决 |
| P09 | 切换 profile 后仍复用旧 hook 集合 | `/sys/fs/bpf/actplane/v1` 的 pinned metadata 和 link 会跨进程退出存在 | 停止所有 Enforcer，确认无人使用后清理 pin root，再用目标 profile 启动；不要在线直接删除 | 已解决 |
| P10 | full profile 有 unlink hook，但 DSL 仍因 feature 不支持而失败 | full reserve 的 `PINNED_POLICY_FEATURES` 未包含 `FEAT_WRITE_RULES` | Demo 缓存源码临时改为 `ALL_HOOK_FEATURES \| FEAT_WRITE_RULES` 并重建 Enforcer | Demo 临时方案 |
| P11 | `make build-enforcer` 可能拒绝当前缓存源码 | 构建脚本会校验 ActPlane patch 后 blob；手工的一行 feature 改动不在受审 patch queue 中 | Demo 用显式 Cargo path override；正式方案应更新受审 patch/hash或升级上游 revision | 待产品化 |
| P12 | `namespace_mutation` 返回 unsupported | AgentSight translator 当时只处理 `read` | 已在 AgentSight 中把文件 `NamespaceMutation` 翻译为 `block unlink file`，并增加翻译测试 | 已解决 |
| P13 | 怀疑 ActPlane 没有删除能力 | ActPlane DSL 的 `unlink` 会 lower 为 `TOP_WRITE`，full profile 已有 `enforce_path_unlink` 和 `enforce_path_rename` | 不新增 BPF hook；启用既有 write-rule feature 和 full hook profile | 已澄清 |
| P14 | 只传 PID 不能创建当前 Binding | 当前合同防 PID 复用和 identity 替换，需要 start time、cgroup v2 ID、PID/mount/network namespace ID | 从 `/proc/<pid>`、cgroupfs 和 namespace inode 采集完整 identity；PID-only 是后续简化模式，不是当前接口 | 已解决 |
| P15 | API 重启后不清楚是否需要重建 Policy/Binding | AgentSight SQLite 行可持久化，但 Enforcer 启动会清理 runtime capability/policy state；失败 Binding 也会以 `failed + domain_id=null` 留在 DB | API-only 重启先查询状态；Enforcer/profile 重启后重新 PUT/Reconcile Binding，并以 `enforced + domain_id` 为准 | 已澄清 |
| P16 | HTTP 只返回泛化的 503，无法定位 | `serve` 路径加载配置后没有调用 `apply_verbose()`，`RUST_LOG=debug` 未真正初始化详细日志 | AgentSight `serve` 调用 `server_config.apply_verbose()`，从 journal 读取 coordinator 原始错误 | 已解决 |
| P17 | source-only、短路径、不同目标 PID 都同样失败 | 失败发生在通用 runtime delta `update[0]`，早于具体 rule 安装 | 用最小 DSL 和受控 PID 分层排除，最终读取 `cap_stats` | 已定位 |
| P18 | `cap_stats` 从 `accept=0/reject=7/drain=103690/drop=0` 增长到 `reject=9/drain=225021` | record 进入 callback 后被统一拒绝；全局 getpid 抢消费曾是候选原因 | 重启 drain-pump 版本后 source-only 仍失败，已否定其为唯一根因并撤回 pump | 假设已否定，具体分支待定位 |
| P19 | 长路径规则编译成功但实际匹配异常 | ActPlane ABI 的 `PAT=64`，compiler `set_pat` 静默截断到 63 字节；AgentSight 当前却允许小于 127 字节 | 当前 Demo 使用 UTF-8 字节长度不超过 63 的短测试路径；正式修复应让 AgentSight 拒绝 `len >= 64`，或升级 ActPlane ABI | 未完全解决 |
| P20 | `cargo test --features actplane` 使用了错误的 ActPlane 实现 | 默认 Cargo 解析固定 Git revision，不包含 AgentSight 本地兼容 patch | 测试时对 `ebpf-ifc-engine` 使用与 release 构建相同的 path override | 已解决 |
| P21 | `--no-default-features --features actplane` 跑测试时报 `MockBackend` 不存在 | 现有测试模块仍引用 mock backend；这是测试 feature 组合问题，不是 production build 问题 | 测试使用默认 features 加 `actplane`；release 构建继续用 `--no-default-features --features actplane` | 已绕过 |
| P22 | 只看 HTTP 503 无法确认提交内容和 capability state | API 收敛了 Enforcer 内核错误，原先也没有安全的 delta 摘要日志 | AgentSight Enforcer 记录数量、首条 update 的非敏感字段、control/target domain 和原始错误；不输出路径内容 | 已解决 |
| P23 | 不清楚 reject 是否只发生在 update | 正常 blob 总是先提交 source update，update 失败后不会到 rule | 临时显式开启 rule-only 隔离探针；`0 updates / 1 rule` 也被拒，`ts_rules[0]`、count 保持 0；实验后删除探针 | 已隔离，非 update 特有 |
| P24 | 怀疑 pinned map 或运行中 BPF 程序不是当前 ABI | 需要检查实际 pinned object，不能只读缓存源码 | `bpftool` 验证 map value size/flags、program map IDs、BTF 结构和实际 xlated callback | 已排除明显 ABI/陈旧对象问题 |
| P25 | 无法确认 callback 实际执行时的 consumer TGID | perf/kprobe 对 BPF JIT symbol 不可用；perf 文件只有元数据、没有样本 | 保留失败证据；下一步需 per-reason ActPlane 诊断或支持 BPF JIT 动态追踪的宿主环境 | 可观测性阻塞 |
| P26 | 担心临时 rule-only 探针影响正常链路 | 探针版本虽已取消环境变量，但旧进程仍映射重建前二进制 | 从源码删除探针，完成测试/Clippy/release 构建并重启；clean source-only 回归仍是原始 503，且无 probe 日志 | 已排除探针影响 |

## 3. 关键问题详解

### 3.1 UDS、root 和 token 是三件不同的事

真实链路有三个进程：

```text
asc-policy-service --HTTP--> agentsight serve --UDS--> agentsight-enforcer --BPF--> kernel
```

- Enforcer 需要 root 或等价的 BPF/LSM 权限。
- AgentSight API 本身不因 HTTP 功能必须是 root；本轮用 root 是为了直接访问 Enforcer UDS。
- SecCore/PAP 不需要 root。策略创建权限由 AgentSight/SecCore 的 service credential 控制，
  不能用“让所有调用者都成为 root”代替 API 鉴权。
- AgentSight mutation 请求仍使用 Bearer token；真实测试不关闭 token 校验。

### 3.2 `$RUN_ROOT` 的用途

`$RUN_ROOT` 是联调运行目录，包含：

```text
enforcer.sock
agentsight.db
.dashboard_token
seccore-state.json
请求、响应和日志证据
```

它不应指向仓库根、用户 HOME 或真实敏感文件目录。使用 `/var/tmp`、仓库
`target/e2e/run.<id>` 或 systemd `RuntimeDirectory` 都可以，关键要求是：唯一、权限受控、
清理目标明确。只有确认 Binding 已 detach、服务已停止后才能删除。

### 3.3 `target/actplane-src` 从哪里来

`scripts/build-enforcer.sh` 会：

1. 固定 ActPlane revision `a62e5d9d96f91101cda019519053e950d532380a`；
2. 浅拉到 `target/actplane-src/<revision>`，或使用 `ACTPLANE_SOURCE_DIR`；
3. 应用 `patches/actplane/` 中经过校验的兼容 patch；
4. 校验 revision、源码 blob、预编译 BPF object 和 dirty 文件；
5. 用真实 `actplane` feature 构建 `agentsight-enforcer`。

因此它不是 submodule，也不是应该手工复制的源码目录。国内 Cargo registry 镜像只能解决
crate 下载，不会自动解决 GitHub 上的 ActPlane Git fetch；后者应使用 Git mirror、代理或
预拉取的 `ACTPLANE_SOURCE_DIR`。

本轮为了 Demo 手工增加了一行 `FEAT_WRITE_RULES`，当前 cache 不再满足
`build-enforcer.sh` 的 blob attestation。可复现的正式方案不能长期依赖这棵 dirty cache。

### 3.4 Profile、feature 和 hook 的关系

三者不能混为一谈：

```text
DSL 能解析 `block unlink`
  + policy feature 允许 runtime write rule
  + profile 实际加载 path_unlink/path_rename BPF-LSM hook
  + 内核启用 BPF LSM
  = 才可能产生真实 EPERM
```

本轮 full profile 已能看到：

```text
/sys/fs/bpf/actplane/v1/links/enforce_path_unlink
/sys/fs/bpf/actplane/v1/links/enforce_path_rename
```

但 hook 存在不等于 policy delta 已经安装。最终必须同时检查 Binding
`state=enforced`、`domain_id != null`、系统调用 errno 和 violation。

`FEAT_WRITE_RULES` 也不是“只允许覆写文件”的标志。ActPlane 把 write、unlink、rename、
truncate 归入 `TOP_WRITE`。因此当前 Demo 把 Canonical `NamespaceMutation` 标成 `exact` 是
有意简化；从严格语义看，`block unlink file` lowering 到 `TOP_WRITE` 可能比“只禁止删除”更宽，
生产口径必须重新审计 Mapping relation，不能直接沿用 Demo 结论。

### 3.5 为什么最初看不到真实错误

AgentSight 对外故意把 Enforcer 内核错误收敛为：

```json
{
  "error": {
    "code": "enforcer_unavailable",
    "message": "enforcement service is unavailable",
    "retryable": true
  }
}
```

仅凭 503 无法判断是 UDS、编译、profile、PID 还是 kernel admission。启用 verbose 后，journal
出现了决定性错误：

```text
enforcement policy apply failed:
enforcer rejected request (kernel_failure):
kernel enforcement failed: append policy delta:
runtime policy delta update[0] was not admitted by the kernel;
count remained 0; rolled back partial runtime policy delta
```

查询方式：

```bash
journalctl -u agentsight-e2e-api-debug-Fj2Ya2.service \
  --since '2 minutes ago' --no-pager -l
```

### 3.6 如何证明失败不在 DSL 或 Scope

按以下顺序缩小范围：

1. 原始防误删 DSL 失败；
2. 把长文件路径换成 `/tmp/asc-p`，仍失败；
3. 只提交 `source AGENT = exec "**"`，仍失败；
4. 从 OpenClaw PID 换成受控 `sleep` PID，仍失败；
5. 非法 DSL 能稳定返回 `compile_failure`，说明编译错误和当前错误是不同阶段；
6. 本地编译最小 DSL 得到 `1 update / 0 rules`，需要的 profile feature 在允许集合内；
7. `cap_stats` 最终证明 record 到达内核 callback 后被 reject。

这组证据排除了：

- `namespace_mutation -> unlink` translator 本身；
- 80 字节长路径是这次 admission 失败的直接原因；
- OpenClaw 的 cgroup/namespace identity；
- `path_unlink` hook 是否触发；
- 原 source-only 失败不依赖 rule 阶段的 write feature 校验。

### 3.7 全局 drain 假设及其反证

ActPlane 的提交路径是：

```text
user_ring_buffer__submit(record)
  -> libc::syscall(SYS_getpid)
  -> tp/syscalls/sys_enter_getpid
  -> bpf_user_ringbuf_drain(cap_req, callback)
  -> callback 校验 current TGID 与 caller_pid/capability state
```

tracepoint 是系统全局的，并不只在 Enforcer 进程触发。统计中 `drain=103690` 说明该入口被
频繁调用。callback 对错误提交者是“消费并 reject”，不是“跳过并留给原提交者”，因此它在
设计上存在抢消费风险；但仅凭这个静态路径和统计不能证明本轮稳定失败就是该竞态。

本轮曾在 AgentSight Enforcer 内做以下隔离实验：

```text
bind Enforcer TGID capability state
  -> start authorized getpid drain pump
  -> append policy delta
  -> stop and join drain pump
  -> unbind Enforcer control state
```

重启该版本后，source-only Binding 仍以相同 `update[0]` 错误失败。实验结果说明缩小抢消费
窗口没有改变本轮现象，所以 pump 已从 AgentSight 源码撤回。全局 drain 仍是 ActPlane 协议的
潜在可靠性问题，但不能再作为这次 503 的已确认根因。

当前 callback 的统一 reject 还可能来自：完整 record dynptr 读取失败、submitter 校验、
feature 校验、authority/scope 校验或首个 table/count map 写入失败。在得到日志或隔离实验的
直接证据前，不在这些候选项中指定根因。

### 3.8 被动日志已经证明什么

AgentSight Enforcer 只记录结构摘要，不记录 target/path 内容。source-only Binding 的实测日志为：

```text
stage=prepared
byte_len=74760 updates=1 rules=0
first_update_op=0 first_update_match=3 first_update_target_len=0
first_update_add=1 del=0 gates=0 invals=0

stage=state_bound
control_pid=429879 control_domain=4026544128
root_pid=97144 target_domain=4026544128
scope_id=1 authority_mask=0x7e target_mask=0x3

stage=append_failed
runtime policy delta update[0] was not admitted by the kernel;
count remained 0
```

这排除了“AgentSight 忘记给 control PID 绑定 runtime domain”以及“control/target 被绑定到不同
domain”两种解释。它也证明提交的是固定大小的完整 compiled blob，header 为 `1 update / 0
rules`，首条 update 是给 source identity 增加 label 的最小记录。

日志仍不能证明 callback 执行时的 `current TGID`、完整 dynptr 读取结果或具体 map update errno；
这些值只存在于 ActPlane BPF callback 内部，不能从 AgentSight 提交前日志推导出来。

### 3.9 rule-only 隔离实验

为了判断错误是否只在 update 分支，本轮临时构造了同一 compiled blob 的副本，仅把 header 改为
`0 updates / 1 rule`，原 blob 不变。该探针只在显式环境变量开启时运行。实测结果：

```text
stage=rule_probe_started updates=0 rules=1
stage=rule_probe_failed
runtime policy delta rule[0] was not admitted by the kernel;
count remained 0
```

随后读取 `ts_rules[0]`，record 仍全零；`ts_counts[rules]` 仍为 0。结论是：当前问题不是
update-specific，rule record 也在第一条成功写入前失败。实验完成后已取消环境变量、重启
Enforcer，并从 AgentSight 源码删除会产生二次提交的探针；仅保留 `prepared/state_bound/
append_failed/append_succeeded` 被动日志。

### 3.10 pinned object、BTF 与动态追踪结果

实际 pinned object 的检查结果：

```text
ts_updates: id=157 array key=4B value=144B max_entries=320 flags=0
ts_rules:   id=143 array key=4B value=224B max_entries=128 flags=0
cap_state:  id=126 hash  key=4B value=56B  max_entries=4096 flags=0

cap_drain_tick: prog id=217 tag=2e9e599dad90970e
loaded_at=2026-08-20T16:01:34+0800 uid=0 btf_id=50
```

实际 BTF 中 `taint_update/rule/cap_state` 的大小分别为 `144/224/56` 字节；实际 xlated callback
引用 `ts_updates`、`ts_rules`、`cap_state` 等当前 map，并包含 caller/consumer、feature、capability
和 table update 分支。这排除了“只看了错误缓存源码”以及明显的 map value size/flags 不一致。

动态追踪没有得到可用证据：

- `perf probe` 对 BPF JIT callback symbol 报 `out of .text`；
- 直接写 `kprobe_events` 返回 `Invalid argument`；
- `perf record -a -e syscalls:sys_enter_getpid` 期间重现了相同 503，但最终
  `perf report` 明确返回 `The ... data has no samples!`。

所以这个 perf 文件不能证明 callback 的 consumer TGID。现阶段若坚持不修改 ActPlane，能继续
精确定位的前提是换到支持 BPF JIT symbol 动态追踪的宿主内核；否则需要 ActPlane 暴露
per-reason reject counter/错误码。直接写 pinned policy map 会绕开 admission 安全边界，不作为
修复或 E2E 成功证据。

### 3.11 长路径静默截断是独立问题

本轮原始保护路径：

```text
/home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2Ya2/protected.txt
```

长度超过 ActPlane `PAT=64`。compiler 的 `set_pat` 使用：

```text
min(input_length, PAT - 1)
```

因此会静默截为 63 字节。AgentSight 当前 `validate_dsl_literal` 却只拒绝长度大于等于 127
字节，两个边界不一致。即使 Binding 返回成功，实际规则也可能匹配截断后的路径而不是目标
文件。

当前测试必须满足：

```text
path.as_bytes().len() <= 63
```

推荐使用短的测试专用路径，例如 `/var/tmp/asc-p`，不要用真实重要文件。正式修复至少包括：

1. AgentSight 在翻译阶段按 UTF-8 字节长度拒绝 `len >= 64`；
2. 增加 63/64 字节边界测试；
3. 在 Mapping diagnostic 中明确 target ABI 限制；
4. 若产品需要长路径，升级 ActPlane ABI/匹配方案，而不是继续静默截断。

## 4. 当前可复现的构建和检查命令

### 4.1 AgentSight-only 代码检查

由于当前 Demo 使用了本地 ActPlane 兼容源码，测试必须带相同 path override：

```bash
cd /home/xingdong/ANOLISA/src/agentsight

cargo test -p agentsight-enforcer --features actplane \
  --config 'patch."https://github.com/eunomia-bpf/ActPlane.git".ebpf-ifc-engine.path="/home/xingdong/ANOLISA/src/agentsight/target/actplane-src/a62e5d9d96f91101cda019519053e950d532380a/bpf"'

cargo clippy -p agentsight-enforcer --all-targets --features actplane \
  --config 'patch."https://github.com/eunomia-bpf/ActPlane.git".ebpf-ifc-engine.path="/home/xingdong/ANOLISA/src/agentsight/target/actplane-src/a62e5d9d96f91101cda019519053e950d532380a/bpf"' \
  -- -D warnings
```

本轮最终 clean 结果：49 个 lib test、16 个 integration test 全部通过，Clippy 通过。

### 4.2 Demo release Enforcer 构建

```bash
cargo build --release -p agentsight-enforcer \
  --no-default-features --features actplane \
  --config 'patch."https://github.com/eunomia-bpf/ActPlane.git".ebpf-ifc-engine.path="/home/xingdong/ANOLISA/src/agentsight/target/actplane-src/a62e5d9d96f91101cda019519053e950d532380a/bpf"'
```

这条命令仅用于当前 dirty-cache Demo。正式、可交付构建仍应恢复为：

```bash
make build-enforcer
```

并让所有 ActPlane 兼容改动通过 patch queue 和 blob attestation。

### 4.3 重启与内核复验

```bash
sudo systemctl restart agentsight-e2e-enforcer-full-Fj2Ya2.service
```

重新 PUT Binding 后先读取 AgentSight 侧诊断日志：

```bash
sudo journalctl -u agentsight-e2e-enforcer-full-Fj2Ya2.service \
  --since "5 minutes ago" --no-pager \
  | rg 'actplane_delta stage='
```

其中 `prepared` 只记录 delta 数量、首条 update 的 op/matcher/位掩码和 target 字节长度，
不输出 target 内容；`state_bound` 记录 control/target domain lookup；`append_failed` 保留
ActPlane 原始错误。根据这些实测值排除分支，不只根据统一的 HTTP 503 推断。

随后检查内核统计：

```bash
sudo /usr/lib/linux-tools-6.8.0-138/bpftool map dump pinned \
  /sys/fs/bpf/actplane/v1/maps/cap_stats
```

通过条件不是“HTTP 不再 503”这么简单，而是：

```text
cap_stats.accept 增长
cap_stats.reject 不再随本次提交增长
AgentSight Binding state == enforced
domain_id != null
短路径目标的 unlink 返回 EPERM/EACCES
目标文件仍存在
无关文件和未绑定进程不受影响
violation 可关联 binding_id、policy_id、revision、pid 和 ActPlane revision
```

## 5. 重启和状态边界

| 操作 | 控制面数据 | 内核 runtime | 应做什么 |
|---|---|---|---|
| 只重启 `agentsight serve` | SQLite 中 Policy/Binding 行保留 | Enforcer 未重启时通常仍在 | 先查询 Binding，不盲目重复创建 |
| 重启 Enforcer | AgentSight/SecCore 持久化数据仍可能保留 | Enforcer `open()` 会清理 runtime capability/policy state | 重新 Reconcile/PUT Binding，并检查新 `domain_id` |
| 修改 profile | DB 行不代表新 profile 已接管 | 旧 pinned marker/link 与新 profile 冲突 | 停 Enforcer，确认后清理 pin root，再启动目标 profile |
| Binding 已失败 | 失败记录可保留，`domain_id=null` | 没有有效规则 | 修复原因后使用新的请求意图重新提交，不把旧失败行当成 active Binding |

## 6. 尚未闭环的事项

1. 由 ActPlane 提供 per-reason reject counter/错误码并修复 runtime admission；在修复前，
   统一 `CAP_STAT_REJECT` 既是功能阻塞，也是可观测性阻塞。
2. 定位并修复具体 admission 分支后，证明 `cap_stats.accept` 增长并完成真实 unlink 阻断。
3. 修正 AgentSight 的路径边界，从 `<127` 改为 ActPlane ABI 的 `<64`，增加边界测试。
4. 重新评估 `NamespaceMutation -> TOP_WRITE` 的 Mapping relation；Demo 的 `exact` 不能直接成为
   生产口径。
5. 由 ActPlane 提供稳定 profile，同时支持高敏读取所需的 `FEAT_OPEN_RULES`
   和防误删所需的 `FEAT_WRITE_RULES`；AgentSight 不再依赖 dirty cache 修改。
6. 正式方案需要为 runtime delta admission 增加可区分原因的统计或错误码；当前
   `CAP_STAT_REJECT` 把 dynptr、submitter、authority、feature 和 map update 失败合并在一起。
7. 自动化 root E2E：启动服务、创建短路径资产、绑定受控 Agent、验证 errno/violation、detach
   和清理，并保存脱敏证据。

## 7. 本轮证据快照

以下值只用于还原 2026-08-20 这次运行，进程重启后会失效，不能复制为新的 Binding：

```text
RUN_ROOT = v2/target/e2e/run.Fj2Ya2
AgentSight API unit = agentsight-e2e-api-debug-Fj2Ya2.service
Enforcer unit = agentsight-e2e-enforcer-full-Fj2Ya2.service
AgentSight API = 127.0.0.1:17400
SecCore service = 127.0.0.1:17460

OpenClaw PID = 97144
startTimeTicks = 658309
pidNamespaceId = 4026532221
mountNamespaceId = 4026532219
networkNamespaceId = 4026531833
cgroupId = 22

Policy = prevent-delete-e2e revision 1
原保护路径 = /home/xingdong/ANOLISA/src/agent-sec-core/v2/target/e2e/run.Fj2Ya2/protected.txt
短路径排除样例 = /tmp/asc-p
```

诊断期间观察到：

- 原防误删 Binding 失败；
- `/tmp/asc-p` 短路径 Binding 仍以相同错误失败；
- `source AGENT = exec "**"` 的 source-only Binding 仍失败；
- 换成受控 `sleep` PID 后仍失败；
- AgentSight journal 最终给出 `runtime policy delta update[0]` kernel admission 错误；
- `cap_stats` 中间快照为 `accept=0, reject=7, drain=103690, drop=0`，后续快照为
  `accept=0, reject=9, drain=225021, drop=0`；
- 重启 drain-pump 版本后又提交一次 source-only Binding，仍得到相同 503 和 journal 错误；该次
  实验后没有立即读取 `cap_stats`，因此本文不把后续快照拆分归因到某一条请求；
- 被动日志证明 control/target domain 相同，提交 blob 为 `74760 bytes / 1 update / 0 rules`；
- rule-only 隔离提交为 `0 updates / 1 rule`，同样被拒，`ts_rules[0]` 和 count 保持为 0；
- `ts_updates[0]` 和 update count 同样保持为 0；
- pinned map、BTF 和实际加载程序的 ABI/引用关系一致；
- `/tmp/actplane-cap-drain-217.txt` 与 `/tmp/actplane-btf-50.h` 保存了当次动态对象快照；
- `/tmp/actplane-getpid.data` 明确没有 perf samples，不能用于 consumer TGID 结论。
- 删除临时 rule-only 探针后完成 clean release 构建并于 17:39:17 重启，Enforcer PID 为
  `461435`；17:42:19 提交 Binding `aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa`，仍返回相同 503 和
  `update[0] not admitted`，日志中没有 `rule_probe_*`。

因此长路径和 OpenClaw identity 是需要单独处理的问题，但不是这些 runtime delta reject 的
直接触发条件。当前失败也不是 update record 特有；精确根因停在 ActPlane callback 的统一
reject 可观测性边界。

## 8. 相关文档

- [完整 E2E 测试流程](seccore-agentsight-actplane-e2e-test-flow_zh.md)
- [Policy、Binding、UDS 与 ActPlane Payload 全链路（含协作修改清单）](seccore-agentsight-actplane-payload-flow_zh.md)
- [PAP、PCP 与 AgentSight 第一阶段接口场景](pap-pcp-agentsight-contract-scenarios_zh.md)
- [Canonical Policy IR 第一阶段实现计划](canonical-policy-ir-phase1-implementation-plan_zh.md)
