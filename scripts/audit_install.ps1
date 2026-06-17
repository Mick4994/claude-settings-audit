<#
.SYNOPSIS
Install claude-settings-audit: link to ~/.claude/plugins/, register Task Scheduler.
#>
$ErrorActionPreference = "Stop"

$source = Split-Path $PSScriptRoot -Parent
$pluginRoot = "$HOME\.claude\plugins\claude-settings-audit"
$taskName = "ClaudeSettingsAuditDaemon"

# 1. Junction (idempotent)
if (-not (Test-Path $pluginRoot)) {
    New-Item -ItemType Junction -Path $pluginRoot -Target $source | Out-Null
    Write-Host "Linked $pluginRoot -> $source"
} else {
    Write-Host "Already linked: $pluginRoot"
}

# 2. Python path
$venvPy = Join-Path (Join-Path $source ".venv") "Scripts\pythonw.exe"
if (-not (Test-Path $venvPy)) {
    Write-Error "Virtualenv not found at $venvPy"
    Write-Error "Run: python -m venv .venv && .venv\Scripts\pip install -r scripts\requirements.txt"
    exit 1
}

# 3. Task Scheduler
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
Write-Host "Next step (admin, one time):"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$pluginRoot\scripts\audit_setup.ps1`""
Write-Host "Then start the daemon now (optional):"
Write-Host "  Start-ScheduledTask -TaskName $taskName"
