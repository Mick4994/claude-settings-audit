# 安装 claude-settings-audit

**前提**：Windows 10/11，Python 3.10+，Node.js 18+，git。

---

## 1. 克隆项目

```cmd
git clone https://github.com/<你的账号>/claude-settings-audit.git
cd claude-settings-audit
```

或直接复制整个 `D:/Codes/claude-settings-audit/` 文件夹到目标电脑。

---

## 2. 创建 Python 虚拟环境 + 装依赖

```cmd
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r scripts\requirements.txt
.venv\Scripts\python.exe -m pytest -v
```

期望：10/10 通过。

---

## 3. 安装插件到 Claude Code

```powershell
powershell -ExecutionPolicy Bypass -File scripts\audit_install.ps1
```

做了 3 件事：
1. 把项目 junction 到 `~/.claude/plugins/claude-settings-audit/`
2. 注册 Windows Task Scheduler `ClaudeSettingsAuditDaemon`（开机自启）
3. 提示下一步

---

## 4. 启用 4663 文件审计（**管理员，一次性**）

以**管理员身份**打开 PowerShell，跑：

```powershell
& "路径\audit_setup.ps1"
```

自动做 3 步：全局审计策略 → 每文件 SACL → 触发测试验证。输出最后一行看到 `OK: 4663 events are firing` 即成功。

---

## 5. 启动 daemon

```cmd
schtasks /Run /TN ClaudeSettingsAuditDaemon
```

或重启电脑（Task Scheduler `At Startup` 自动起）。

---

## 6. 验证

在 Claude Code 里：

```
/plugins              → 看到 claude-settings-audit ✔ enabled
/settings-audit status → daemon 运行、4663 审计启用
/settings-audit recent → 看到最近的 settings 改动事件
```

3 条通道：
- **Hook**：用 Edit 工具改 settings → `source=hook`
- **Watchdog**：外部进程改 settings → `source=watchdog` 
- **4663 Audit**：外部进程改 settings → `source=audit`（带进程名）

---

## 目录结构

```
claude-settings-audit/
├── .claude-plugin/plugin.json    ← 插件清单
├── hooks/hooks.json              ← PostToolUse hook 注册
├── hooks/postsettingschange.js   ← hook 脚本（Node.js）
├── commands/                     ← 4 个 slash 命令
├── scripts/                      ← Python daemon + 安装/卸载/设置脚本
├── tests/                        ← pytest 单测 + 集成测试
└── docs/plans/                   ← 设计 + 实施文档
```

## 卸载

管理员 PowerShell：

```powershell
& "路径\scripts\audit_uninstall.ps1"
```

或 Claude Code 里 `/settings-audit uninstall`。
