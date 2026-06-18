<#
.SYNOPSIS
Enable Windows File System audit (policy + SACL) for claude-settings-audit.
Each run is idempotent and self-verifying.
#>
$ErrorActionPreference = "Stop"
$catGuid = "{6997984A-797A-11D9-BED3-505054503030}"
$subGuid  = "{0CCE921E-69AE-11D9-BED3-505054503030}"

# === Step 1: global policy (idempotent) ===
Write-Host "[1/3] auditpol /set (GUIDs, locale-independent)"
$ok = & auditpol.exe /set /category:$catGuid /subcategory:$subGuid /success:enable 2>&1
if ($LASTEXITCODE -ne 0) { Write-Error "auditpol failed: $ok"; exit 1 }
# Verify
$state = & auditpol.exe /get /category:$catGuid /subcategory:$subGuid 2>&1
Write-Host "  Policy state: $($state -join ' ')"

# === Step 2: SACL on watched files via icacls (more reliable than Set-Acl) ===
Write-Host "[2/3] SACL on watched files (icacls)"
$homeClaude = Join-Path $HOME ".claude"
$watched = @(
    (Join-Path $homeClaude "settings.json"),
    (Join-Path $homeClaude "settings.local.json"),
    (Join-Path $homeClaude "hooks\hooks.json"),
    (Join-Path $homeClaude "plugin.json"),
    (Join-Path $homeClaude "marketplace.json")
)
# WD=WriteData, AD=AppendData, WP=WriteProperties, WA=WriteAttributes, DC=DeleteChild
# S=Success audit, F=Failure audit — we only want Success for writes
$icaclsSacl = "Everyone:(WD,AD,WP,WA,DC)S"
foreach ($f in $watched) {
    if (-not (Test-Path $f)) { Write-Host "  - $f (missing)"; continue }
    $out = icacls $f /setaudit $icaclsSacl 2>&1 | Select-Object -Last 1
    Write-Host "  + $f  ($out)"
}

# === Step 3: quick self-verification ===
Write-Host "[3/3] Trigger test write + wait 3s..."
Add-Content -Path $watched[0] -Value "" -NoNewline -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
$recent = Get-WinEvent -LogName Security -MaxEvents 10 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4663 } | Select-Object -First 3
if ($recent) {
    Write-Host "  OK: 4663 events are firing (~$($recent.Count) in recent 10)"
    $recent | ForEach-Object {
        $props = $_.Properties
        $file = if ($props.Count -gt 5) { $props[5].Value } else { "?" }
        Write-Host "    file=$file"
    }
} else {
    Write-Warning "  No 4663 events in recent Security log — policy may need a reboot or group policy refresh"
    Write-Warning "  Run: gpupdate /force"
}

$doneDir = Join-Path (Join-Path $PSScriptRoot "..") "install"
$doneFile = Join-Path $doneDir "setup.done"
New-Item -ItemType Directory -Path $doneDir -Force | Out-Null
Set-Content -Path $doneFile -Value ("setup completed at " + (Get-Date -Format "o"))
Write-Host "Wrote $doneFile"
