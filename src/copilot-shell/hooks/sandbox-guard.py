#!/usr/bin/env python3
"""
sandbox-guard.py - PreToolUse hook
检测危险 shell 命令，自动替换为 linux-sandbox 沙箱内执行。

沙箱策略：
  - 文件系统：root 只读 + cwd 可写 + tmpdir 可写
  - 网络：根据命令类型自动选择（restricted 或 unrestricted）

stdin: PreToolUse JSON (tool_name, tool_input, cwd, ...)
stdout: HookOutput JSON (decision, systemMessage, hookSpecificOutput)
"""

import os
import sys
import json
import re


def _setup_middleware_path():
    """Add security_middleware to sys.path for import."""
    # Installed environment
    installed_path = "/usr/share/anolisa/skills/agent-sec-core/scripts/"
    if os.path.isdir(os.path.join(installed_path, "security_middleware")):
        if installed_path not in sys.path:
            sys.path.insert(0, installed_path)
        return
    # Development environment: hooks/ → copilot-shell/ → src/ → agent-sec-core/skill/scripts/
    dev_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),  # hooks/
        "..",   # copilot-shell/
        "..",   # src/
        "agent-sec-core", "skill", "scripts"
    )
    dev_path = os.path.normpath(dev_path)
    if os.path.isdir(os.path.join(dev_path, "security_middleware")):
        if dev_path not in sys.path:
            sys.path.insert(0, dev_path)


LINUX_SANDBOX = "/usr/local/bin/linux-sandbox"

# 危险命令检测规则：(regex_pattern, reason_label)
# 分为两类：
#   BLOCK_PATTERNS  - 直接阻止，不进沙箱（沙箱内也无法缓解的风险）
#   SANDBOX_PATTERNS - 替换为沙箱执行（文件系统/权限类风险，沙箱可有效隔离）

# 直接 block 的命令（沙箱无法缓解）
BLOCK_PATTERNS = [
    (r"\bshutdown\b", "shutdown 关机命令"),
    (r"\breboot\b", "reboot 重启命令"),
    (r"\bhalt\b", "halt 停机命令"),
    (r"\bpoweroff\b", "poweroff 断电命令"),
    (r":\(\)\s*\{", "fork bomb"),
]

# 替换为沙箱执行的命令（文件系统/权限/服务类）- 网络隔离
DANGEROUS_PATTERNS = [
    (r"\bsudo\b", "sudo 提权命令"),
    (r"\bsu\b", "su 切换用户"),
    (r"\bpkexec\b", "pkexec 提权"),
    # rm 危险操作：-rf、-fr、-r -f、--recursive、--force 各种写法
    (r"\brm\b.*(-[a-zA-Z]*[rf]|-[a-zA-Z]*[fr]|--recursive|--force)", "递归/强制删除"),
    (r"\bchmod\s+[0-7]{3,4}\s+/", "修改系统路径权限"),
    (r"\bchown\b", "修改文件所有者"),
    (r"\bmkfs\.?\w*\b", "格式化磁盘"),
    (r"\bdd\s+(if|of)=", "dd 磁盘读写操作"),
    # 写入系统目录：> / tee / cp / mv 等多种方式
    (r"(>|>>)\s*/etc/", "重定向写入 /etc"),
    (r"(>|>>)\s*/usr/", "重定向写入 /usr"),
    (r"(>|>>)\s*/var/", "重定向写入 /var"),
    (r"(>|>>)\s*/boot/", "重定向写入 /boot"),
    (r"\btee\s+.*/etc/", "tee 写入 /etc"),
    (r"\btee\s+.*/usr/", "tee 写入 /usr"),
    (r"\btee\s+.*/var/", "tee 写入 /var"),
    (r"\b(cp|mv)\s+.*\s+/etc/", "cp/mv 操作 /etc"),
    (r"\b(cp|mv)\s+.*\s+/usr/", "cp/mv 操作 /usr"),
    (r"\b(cp|mv)\s+.*\s+/var/", "cp/mv 操作 /var"),
    (r"\bsystemctl\s+(stop|disable|mask|restart|kill)", "systemctl 危险操作"),
    (r"\bservice\s+\w+\s+(stop|restart)", "service 危险操作"),
    (r"\bkill\s+-9\b", "强制杀进程 SIGKILL"),
    (r"\bkillall\b", "killall 批量杀进程"),
    (r"\bmount\b", "挂载文件系统"),
    (r"\bumount\b", "卸载文件系统"),
    (r"\biptables\b", "iptables 修改防火墙"),
    (r"\bnft\b", "nftables 修改防火墙"),
    (r"\bcrontab\s+(-[re]|.*\|)", "crontab 修改定时任务"),
]

# 网络相关命令 - 需要放开网络权限，但保留文件系统隔离
NETWORK_PATTERNS = [
    (r"\bcurl\b", "curl 网络请求"),
    (r"\bwget\b", "wget 网络下载"),
    (r"\bnc\b|\bnetcat\b", "netcat 网络工具"),
    (r"\bnmap\b", "nmap 网络扫描"),
    # ssh 远程连接命令（排除 .ssh 目录路径，如 ~/.ssh/config 只是查看本地配置）
    (r"\bssh\s+[^/\s]", "ssh 远程连接"),
    (r"\bscp\b", "scp 远程传输"),
    # 管道执行网络内容（curl/wget pipe to shell）
    (
        r"(curl|wget)\b.*(\|\s*(bash|sh|python|python3|perl|ruby|node))",
        "网络内容直接执行",
    ),
    (r"(\|\s*(bash|sh|python|python3)).*\b(curl|wget)\b", "网络内容直接执行(反向管道)"),
    # 脚本语言网络操作（Python socket / HTTP 库等）
    (r"python[23]?\b.*\bsocket\b", "Python socket 网络操作"),
    (
        r"python[23]?\b.*\b(requests|urllib|aiohttp|httpx|httplib)\b",
        "Python HTTP 网络请求",
    ),
    (r"python[23]?\b.*\.connect\(", "Python 建立网络连接"),
    (r"\bnode\b.*\b(http|https|net|dgram)\b", "Node.js 网络模块"),
    (r"\bperl\b.*\b(socket|IO::Socket|LWP)\b", "Perl 网络操作"),
]

# 沙箱文件系统策略 JSON
SANDBOX_FS_POLICY = json.dumps(
    {
        "kind": "restricted",
        "entries": [
            {"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"},
            {
                "path": {
                    "type": "special",
                    "value": {"kind": "current_working_directory"},
                },
                "access": "write",
            },
            {
                "path": {"type": "special", "value": {"kind": "tmpdir"}},
                "access": "write",
            },
            {
                "path": {"type": "special", "value": {"kind": "slash_tmp"}},
                "access": "write",
            },
        ],
    },
    separators=(",", ":"),
)  # compact JSON


def build_sandbox_command(original_command: str, cwd: str, network_policy: str = "restricted") -> str:
    """将原始命令包裹进 linux-sandbox 执行
    
    Args:
        original_command: 原始命令
        cwd: 当前工作目录
        network_policy: 网络策略，"restricted" 或 "unrestricted"
    """
    # 转义单引号：' → '\''
    escaped_cmd = original_command.replace("'", "'\\''")

    return (
        f"{LINUX_SANDBOX}"
        f' --sandbox-policy-cwd "{cwd}"'
        f" --file-system-sandbox-policy '{SANDBOX_FS_POLICY}'"
        f" --network-sandbox-policy '\"{network_policy}\"'"
        f" -- bash -c '{escaped_cmd}'"
    )


def detect_patterns(command: str, patterns: list) -> list[str]:
    """检测命令中的危险模式，返回匹配的原因列表"""
    reasons = []
    for pattern, reason in patterns:
        if re.search(pattern, command, re.IGNORECASE):
            reasons.append(reason)
    return reasons


def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # 无法解析输入，安全放行
        print(json.dumps({"decision": "allow"}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")
    cwd = input_data.get("cwd", "/tmp")

    # 只拦截 shell 工具
    if tool_name != "run_shell_command" or not command.strip():
        print(json.dumps({"decision": "allow"}))
        return

    # 第一优先级：直接 block 的命令
    block_reasons = detect_patterns(command, BLOCK_PATTERNS)
    if block_reasons:
        reasons_str = ", ".join(block_reasons)
        result = {
            "decision": "block",
            "reason": (
                f"🚫 安全策略已阻止执行 (检测到: {reasons_str})。此类命令不允许执行。\n"
                "💡 如确认当前命令无风险，可在聊天框输入 `/hooks disable sandbox-guard` 临时关闭沙箱防护（本会话有效），"
                "执行完毕后可用 `/hooks enable sandbox-guard` 恢复。"
            ),
        }
        # --- middleware prehook logging (additive) ---
        try:
            _setup_middleware_path()
            from security_middleware import invoke as _mw_invoke
            _mw_invoke("sandbox_prehook", decision="block", command=command,
                       reasons=", ".join(block_reasons), cwd=cwd)
        except Exception:
            pass  # logging failure must not affect hook behavior

        print(json.dumps(result, ensure_ascii=False))
        return

    # 第二优先级：替换为沙箱执行（文件系统/权限类风险）
    sandbox_reasons = detect_patterns(command, DANGEROUS_PATTERNS)
    network_reasons = detect_patterns(command, NETWORK_PATTERNS)
    
    if not sandbox_reasons and not network_reasons:
        # 安全命令，直接放行
        print(json.dumps({"decision": "allow"}))
        return

    # 判断是否需要放开网络权限
    if network_reasons and not sandbox_reasons:
        # 纯网络命令：放开网络，但保留文件系统隔离
        network_policy = "enabled"
        all_reasons = network_reasons
        policy_desc = "🔒 已替换安全沙箱执行（网络已放行）"
    else:
        # 文件系统危险命令或混合命令：网络隔离
        network_policy = "restricted"
        all_reasons = sandbox_reasons + network_reasons
        policy_desc = "🔒 已替换安全沙箱执行（网络隔离）"

    # 构建沙箱命令
    sandbox_cmd = build_sandbox_command(command, cwd, network_policy)
    reasons_str = ", ".join(all_reasons)

    result = {
        "decision": "allow",
        "systemMessage": (
            f"{policy_desc} (检测到: {reasons_str})\n"
            "💡 如沙箱执行出错且确认命令无风险，可在聊天框输入 `/hooks disable sandbox-guard` 临时关闭防护"
        ),
        "hookSpecificOutput": {"tool_input": {"command": sandbox_cmd}},
    }

    # --- middleware prehook logging (additive) ---
    try:
        _setup_middleware_path()
        from security_middleware import invoke as _mw_invoke
        _mw_invoke("sandbox_prehook", decision="sandbox", command=command,
                   reasons=", ".join(all_reasons), network_policy=network_policy, cwd=cwd)
    except Exception:
        pass  # logging failure must not affect hook behavior

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()