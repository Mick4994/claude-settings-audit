# claude-settings-audit

Claude Code 插件——审计 `~/.claude/` 下 5 个配置文件（`settings.json`、`settings.local.json`、`hooks/hooks.json`、`plugin.json`、`marketplace.json`）的**每一次改动**。

每次改动记录三要素：
- **何时** — UTC ISO8601 时间戳
- **改了啥** — 文件路径 + 内容差异
- **谁改的** — 三种归因：
  - Claude Code 自己改的 → 工具名 + 会话上下文（PostToolUse hook 捕获）
  - 外部进程改的 → SID + 进程名 + PID（Windows 4663 安全审计事件捕获）
  - 兜底 → `unknown` + 运行中进程快照（watchdog 捕获）

## 快速开始

详见 [INSTALL.md](INSTALL.md)

```bash
# 1. 虚拟环境 + 依赖
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r scripts\requirements.txt

# 2. 安装插件（junction + Task Scheduler 开机自启）
powershell -ExecutionPolicy Bypass -File scripts\audit_install.ps1

# 3. 启用 4663 审计（管理员，一次性）
#    在管理员 PowerShell 中运行：
& ".\scripts\audit_setup.ps1"

# 4. 启动 daemon（或重启电脑）
schtasks /Run /TN ClaudeSettingsAuditDaemon
```

## 验证

在 Claude Code 中：
```
/plugins              → 看到 claude-settings-audit ✔ enabled
/settings-audit status → daemon 运行、审计策略启用
/settings-audit recent → 最近改动事件清单
```

## Slash 命令

| 命令 | 作用 |
|------|------|
| `/settings-audit log` | 查看 change.log 末尾 |
| `/settings-audit recent [N]` | 表格化查看最近 N 条事件（默认 10） |
| `/settings-audit status` | daemon 状态 + 审计策略 + 事件计数 |
| `/settings-audit show <id>` | 按 ID 查完整事件 JSON |
| `/settings-audit setup` | 检查/重新启用 4663 审计 |
| `/settings-audit uninstall` | 卸载插件 |

## 日志位置

- `本篇 > change.log` — 人类可读
- `本篇 > change.log.jsonl` — 机器可读（JSON Lines）

## 卸载

管理员 PowerShell：
```powershell
& ".\scripts\audit_uninstall.ps1"
```

## 架构

Python 后台 daemon（常驻，Task Scheduler 开机自启），三路归因合并写入日志：

```
Claude Code Edit/Write/Bash
   ↓ PostToolUse hook (Node.js)
   ↓ TCP 127.0.0.1:17321
   ↓
外部进程写 settings
   ↓ Windows 4663 安全审计
   ↓ Get-WinEvent 轮询
   ↓                      → 归一化 → 去重 → change.log
watchdog mtime 兜底 ──────┘                      change.log.jsonl
```

## 测试

```bash
.venv\Scripts\python.exe -m pytest -v
# 期望：10 passed
```

## 系统要求

- Windows 10/11
- Python 3.10+
- Node.js 18+
- 管理员权限（仅 4663 审计配置一步，一次性）
