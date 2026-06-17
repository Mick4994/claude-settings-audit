<#
.SYNOPSIS
Enable the Windows File System audit policy required by claude-settings-audit.
.DESCRIPTION
Idempotent. Verifies the policy after setting it. Writes install/setup.done.
#>
$ErrorActionPreference = "Stop"

$subcat = "File System"
Write-Host "Enabling audit policy: $subcat (Success)"
$proc = Start-Process -FilePath "auditpol.exe" `
    -ArgumentList @("/set", "/subcategory:$subcat", "/success:enable") `
    -Wait -NoNewWindow -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "auditpol set failed with exit code $($proc.ExitCode)"
    exit $proc.ExitCode
}

Write-Host "Verifying..."
$verify = & auditpol.exe /get /subcategory:"$subcat"
if ($verify -match "Success") {
    Write-Host "OK: Success and Failure auditing enabled for File System"
} else {
    Write-Error "Verification failed - 'Success' not found in output:"
    Write-Error $verify
    exit 1
}

$doneDir = Join-Path $PSScriptRoot ".." "install"
$doneFile = Join-Path $doneDir "setup.done"
New-Item -ItemType Directory -Path $doneDir -Force | Out-Null
Set-Content -Path $doneFile -Value ("setup completed at " + (Get-Date -Format "o"))
Write-Host "Wrote $doneFile"
