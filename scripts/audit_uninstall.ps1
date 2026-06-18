<#
.SYNOPSIS
Uninstall claude-settings-audit: stop daemon, remove junction, unregister Task Scheduler.
.DESCRIPTION
Idempotent. Run as admin if you want Task Scheduler removal to succeed.
#>
$ErrorActionPreference = "Stop"

$pluginRoot = Join-Path (Join-Path (Join-Path $HOME ".claude") "plugins") "claude-settings-audit"
$taskName = "ClaudeSettingsAuditDaemon"

# 1. Stop the daemon (user-level pythonw from this project)
Get-Process pythonw -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*claude-settings-audit*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "Stopped daemon processes"

# 2. Unregister Task Scheduler (admin required for this step)
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Unregistered scheduled task '$taskName'"
    } catch {
        Write-Warning "Could not unregister task '$taskName' (need admin?): $_"
    }
} else {
    Write-Host "No scheduled task to remove"
}

# 3. Remove the junction (do NOT recurse — we only own this link, not the source)
if (Test-Path $pluginRoot) {
    cmd /c rmdir "$pluginRoot"
    Write-Host "Removed junction $pluginRoot"
} else {
    Write-Host "No junction at $pluginRoot"
}

# 4. Remove the plugin entry from settings.local.json enabledPlugins
$localPath = Join-Path (Join-Path $HOME ".claude") "settings.local.json"
if (Test-Path $localPath) {
    python -c "
import json, sys
from pathlib import Path
p = Path(r'$localPath')
data = json.loads(p.read_text(encoding='utf-8'))
if 'enabledPlugins' in data:
    data['enabledPlugins'].pop('claude-settings-audit@claude-settings-audit', None)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + chr(10), encoding='utf-8')
    print('Removed plugin from settings.local.json')
else:
    print('No enabledPlugins in settings.local.json')
"
}

# 5. Remove the plugin entry from installed_plugins.json
$registry = Join-Path (Join-Path (Join-Path $HOME ".claude") "plugins") "installed_plugins.json"
if (Test-Path $registry) {
    python -c "
import json, sys
from pathlib import Path
p = Path(r'$registry')
data = json.loads(p.read_text(encoding='utf-8'))
data.get('plugins', {}).pop('claude-settings-audit@claude-settings-audit', None)
p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + chr(10), encoding='utf-8')
print('Removed plugin from installed_plugins.json')
"
}

# 6. Remove the marketplace registration
$marketDir = Join-Path (Join-Path (Join-Path $HOME ".claude") "plugins") "marketplaces\claude-settings-audit"
if (Test-Path $marketDir) {
    Remove-Item -Path $marketDir -Recurse -Force
    Write-Host "Removed marketplace dir"
}
$knownMarkets = Join-Path (Join-Path (Join-Path $HOME ".claude") "plugins") "known_marketplaces.json"
if (Test-Path $knownMarkets) {
    python -c "
import json
from pathlib import Path
p = Path(r'$knownMarkets')
data = json.loads(p.read_text(encoding='utf-8'))
data.pop('claude-settings-audit', None)
p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + chr(10), encoding='utf-8')
print('Removed marketplace from known_marketplaces.json')
"
}

Write-Host ""
Write-Host "Uninstall complete. Source at D:\Codes\claude-settings-audit remains intact."
Write-Host "To fully remove: also delete the source directory and any local change.log files."
