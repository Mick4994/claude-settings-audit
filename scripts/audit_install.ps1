<#
.SYNOPSIS
Install claude-settings-audit: junction, marketplace registration, Task Scheduler.
#>
$ErrorActionPreference = "Stop"

$source = Split-Path $PSScriptRoot -Parent
$claudeHome = Join-Path $HOME ".claude"
$pluginsDir = Join-Path $claudeHome "plugins"
$pluginLink = Join-Path $pluginsDir "claude-settings-audit"
$taskName = "ClaudeSettingsAuditDaemon"
$pluginId = "claude-settings-audit@claude-settings-audit"
$version = "0.1.0"

# 1. Junction (idempotent)
if (-not (Test-Path $pluginLink)) {
    New-Item -ItemType Junction -Path $pluginLink -Target $source | Out-Null
    Write-Host "Linked $pluginLink -> $source"
} else {
    Write-Host "Already linked: $pluginLink"
}

# 2. Python venv check
$venvPy = Join-Path (Join-Path $source ".venv") "Scripts\pythonw.exe"
if (-not (Test-Path $venvPy)) {
    Write-Error "Virtualenv not found at $venvPy"
    Write-Error "Run: python -m venv .venv && .venv\Scripts\pip install -r scripts\requirements.txt"
    exit 1
}

# 3. Register in installed_plugins.json (idempotent)
$installedPluginsPath = Join-Path $pluginsDir "installed_plugins.json"
$installed = @{ version = 2; plugins = @{} }
if (Test-Path $installedPluginsPath) {
    $installed = Get-Content $installedPluginsPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
}
if (-not $installed.plugins[$pluginId]) {
    $cachePluginPath = Join-Path $pluginsDir "cache\claude-settings-audit\claude-settings-audit\$version"
    $installed.plugins[$pluginId] = @(
        @{
            scope = "user"
            installPath = "$cachePluginPath"
            version = $version
            installedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
            lastUpdated = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
            gitCommitSha = "local-install"
        }
    )
    $installed | ConvertTo-Json -Depth 4 | Set-Content $installedPluginsPath -Encoding UTF8
    Write-Host "Registered in installed_plugins.json"
} else {
    Write-Host "Already in installed_plugins.json"
}

# 4. Register marketplace in known_marketplaces.json
$knownMarketplacesPath = Join-Path $pluginsDir "known_marketplaces.json"
$known = @{}
if (Test-Path $knownMarketplacesPath) {
    $known = Get-Content $knownMarketplacesPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
}
if (-not $known["claude-settings-audit"]) {
    $known["claude-settings-audit"] = @{
        source = @{
            source = "github"
            repo = "Mick4994/claude-settings-audit"
        }
        installLocation = "$claudeHome\plugins\marketplaces\claude-settings-audit"
        lastUpdated = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
    }
    $known | ConvertTo-Json -Depth 4 | Set-Content $knownMarketplacesPath -Encoding UTF8
    Write-Host "Registered marketplace: claude-settings-audit"
} else {
    Write-Host "Marketplace already registered"
}

# 5. Ensure marketplace directory
$marketplaceDir = Join-Path $pluginsDir "marketplaces\claude-settings-audit\.claude-plugin"
if (-not (Test-Path $marketplaceDir)) {
    New-Item -ItemType Directory -Path $marketplaceDir -Force | Out-Null
}
$marketplaceJson = Join-Path $marketplaceDir "marketplace.json"
if (-not (Test-Path $marketplaceJson)) {
    @{
        name = "claude-settings-audit"
        owner = @{ name = "Mick4994" }
        metadata = @{
            description = "Audit every change to Claude Code's user-level settings files with attribution"
            version = $version
        }
        plugins = @(
            @{
                name = "claude-settings-audit"
                source = "./"
                description = "Audit every change to Claude Code's user-level settings files with attribution"
                version = $version
                category = "monitoring"
                tags = @("audit", "settings", "change-log", "attribution", "security")
            }
        )
    } | ConvertTo-Json -Depth 5 | Set-Content $marketplaceJson -Encoding UTF8
    Write-Host "Created marketplace manifest"
}

# 6. Ensure plugin cache directory (junction target already handled, but cache entry needed)
$cacheDir = Join-Path $pluginsDir "cache\claude-settings-audit\claude-settings-audit\$version"
if (-not (Test-Path $cacheDir)) {
    New-Item -ItemType Junction -Path $cacheDir -Target $source -Force | Out-Null
    Write-Host "Linked plugin cache: $cacheDir -> $source"
}

# 7. Task Scheduler
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Task '$taskName' already registered"
} else {
    $action = New-ScheduledTaskAction -Execute $venvPy -Argument "$source\scripts\audit_daemon.py"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName `
        -Action $action -Trigger $trigger -Settings $settings `
        -Description "Claude Code settings-file audit daemon" `
        -RunLevel Highest | Out-Null
    Write-Host "Registered scheduled task '$taskName'"
}

Write-Host ""
Write-Host "Install complete."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. (admin PowerShell, one time)  & `"$source\scripts\audit_setup.ps1`""
Write-Host "  2. (start daemon)                schtasks /Run /TN $taskName"
Write-Host "  3. (verify)                      /plugins in Claude Code"
