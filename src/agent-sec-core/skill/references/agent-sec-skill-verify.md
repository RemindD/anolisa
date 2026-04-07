---
name: agent-sec-skill-verify
description: 验证 Skill 完整性与签名，加载外部 Skill 前必须调用。
---

# Skill 完整性验证

## 用法

```bash
# 验证配置中所有 skills 目录
python3 scripts/agent-sec-cli.py verify

# 验证单个 skill
python3 scripts/agent-sec-cli.py verify --skill /path/to/skill_name
```

## 配置文件

`scripts/asset-verify/config.conf`:

```ini
skills_dir = [
    /opt/agent/skills
    /path/to/other/skills
]
```

## 输出

```
[OK] skill_a
[OK] skill_b
[ERROR] skill_c
  ERR_HASH_MISMATCH: ...

==================================================
PASSED: 2
FAILED: 1
==================================================
VERIFICATION FAILED
```

## 错误码

| 码 | 含义 |
|----|------|
| 0 | 通过 |
| 10 | 缺失 .skill.sig |
| 11 | 缺失 Manifest.json |
| 12 | 签名无效 |
| 13 | 哈希不匹配 |

