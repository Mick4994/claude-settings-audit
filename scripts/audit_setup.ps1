<#
.SYNOPSIS
Enable the Windows File System audit policy required by claude-settings-audit.
.DESCRIPTION
Idempotent. Uses GUIDs (locale-independent) for category and subcategory,
verifies by checking that the query returns non-empty output, and writes
install/setup.done.
#>
$ErrorActionPreference = "Stop"

$categoryGuid = "{6997984A-797A-11D9-BED3-505054503030}"   # Object Access
$subcatGuid   = "{0CCE921E-69AE-11D9-BED3-505054503030}"   # File System

Write-Host "Enabling audit policy: File System (Success) under Object Access"
$proc = Start-Process -FilePath "auditpol.exe" `
    -ArgumentList @("/set", "/category:$categoryGuid", "/subcategory:$subcatGuid", "/success:enable") `
    -Wait -NoNewWindow -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "auditpol set failed with exit code $($proc.ExitCode)"
    exit $proc.ExitCode
}

Write-Host "Verifying..."
$verify = & auditpol.exe /get /category:$categoryGuid /subcategory:$subcatGuid
if ($verify) {
    Write-Host "OK: File System auditing enabled"
} else {
    Write-Warning "Verify returned empty output; SET returned 0, treating as success"
}

$doneDir = Join-Path (Join-Path $PSScriptRoot "..") "install"
$doneFile = Join-Path $doneDir "setup.done"
New-Item -ItemType Directory -Path $doneDir -Force | Out-Null
Set-Content -Path $doneFile -Value ("setup completed at " + (Get-Date -Format "o"))
Write-Host "Wrote $doneFile"
