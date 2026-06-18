<#
.SYNOPSIS
Enable the Windows File System audit policy AND set SACLs on the watched files
required by claude-settings-audit.
.DESCRIPTION
Idempotent. Both steps are needed for 4663 events to fire:
  1. Global File System audit policy (auditpol /set)
  2. Per-file SACL so Windows knows which writes to log (Set-Acl)
Uses GUIDs (locale-independent) for category and subcategory.
#>
$ErrorActionPreference = "Stop"

$categoryGuid = "{6997984A-797A-11D9-BED3-505054503030}"   # Object Access
$subcatGuid   = "{0CCE921E-69AE-11D9-BED3-505054503030}"   # File System

# --- Step 1: global policy ---
Write-Host "[1/2] Enabling audit policy: File System (Success) under Object Access"
$proc = Start-Process -FilePath "auditpol.exe" `
    -ArgumentList @("/set", "/category:$categoryGuid", "/subcategory:$subcatGuid", "/success:enable") `
    -Wait -NoNewWindow -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "auditpol set failed with exit code $($proc.ExitCode)"
    exit $proc.ExitCode
}
$verify = & auditpol.exe /get /category:$categoryGuid /subcategory:$subcatGuid
if ($verify) {
    Write-Host "  OK"
} else {
    Write-Warning "  verify returned empty; SET exit 0, treating as success"
}

# --- Step 2: SACL on the 5 watched files ---
Write-Host "[2/2] Setting SACL on the 5 watched files"
$watched = @(
    (Join-Path $HOME ".claude\settings.json"),
    (Join-Path $HOME ".claude\settings.local.json"),
    (Join-Path $HOME ".claude\hooks\hooks.json"),
    (Join-Path $HOME ".claude\plugin.json"),
    (Join-Path $HOME ".claude\marketplace.json")
)

# Audit rule: "Everyone" Success on Write/Append/Delete/ChangePermissions/SetValue
# This matches what 4663 events log for.
$rights = [System.Security.AccessControl.FileSystemRights]::Write `
       -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
       -bor [System.Security.AccessControl.FileSystemRights]::Delete `
       -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions `
       -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes `
       -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
       -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
$propagation = [System.Security.AccessControl.PropagationFlags]::None

foreach ($f in $watched) {
    if (-not (Test-Path $f)) {
        Write-Host "  - $f (missing, skipping)"
        continue
    }
    $acl = Get-Acl $f
    # Build the audit ACE
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        [System.Security.Principal.NTAccount]::new("Everyone"),
        $rights,
        $inheritance,
        $propagation,
        [System.Security.AccessControl.AuditFlags]::Success
    )
    # Remove any existing audit rules for Everyone first (idempotent)
    $acl.RemoveAuditRuleSpecific($rule) | Out-Null
    $acl.AddAuditRule($rule)
    try {
        Set-Acl -Path $f -AclObject $acl -ErrorAction Stop
        Write-Host "  + $f"
    } catch {
        Write-Warning "  ! $f - $($_.Exception.Message)"
    }
}

$doneDir = Join-Path (Join-Path $PSScriptRoot "..") "install"
$doneFile = Join-Path $doneDir "setup.done"
New-Item -ItemType Directory -Path $doneDir -Force | Out-Null
Set-Content -Path $doneFile -Value ("setup completed at " + (Get-Date -Format "o"))
Write-Host ""
Write-Host "Setup complete. Wrote $doneFile"
