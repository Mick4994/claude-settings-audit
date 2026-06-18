---
description: Uninstall claude-settings-audit (daemon, junction, Task Scheduler, registry)
allowed-tools: Bash
---

This removes the plugin from the Claude Code install. The source repo at `D:\Codes\claude-settings-audit` is NOT deleted (you can re-install any time with `audit_install.ps1`).

To uninstall, open an admin PowerShell and run:

```powershell
& "D:\Codes\claude-settings-audit\scripts\audit_uninstall.ps1"
```

Then verify with `claude plugin list` — `claude-settings-audit` should be gone.
