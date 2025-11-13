<#
.SYNOPSIS
  Toggle the built-in Guest account’s membership in the local Administrators group and its enabled state.
  - Secure mode ($false): removes Guest from Administrators and DISABLES the account.
  - Insecure mode ($true): adds Guest to Administrators and ENABLES the account.

.NOTES
  Author        : Danny Cologero
  Date Created  : 2025-11-11
  Last Modified : 2025-11-12
  Version       : 1.5 (adds ProgramData logging; mirrors summary lines)

.USAGE
  Requirements:
    - Run in PowerShell 5.1.17763.7919+ as Administrator.
    - Script writes a timestamped log to C:\ProgramData\Guest_Admin_Toggle_Logs\

  Steps:
    1) Open PowerShell as Administrator.
    2) Edit the toggle near the top of the script to choose behavior:
         $AddGuestToAdminGroup = $false   # SECURE (remove from Admins + disable Guest)  [RECOMMENDED]
         $AddGuestToAdminGroup = $true    # INSECURE (add to Admins + enable Guest)
    3) Execute the script from its folder:
         .\toggle-guest-local-administrators.ps1
    4) Read the on-screen PASS/FAIL summary and review the saved log path printed at the end.

  Notes:
    - This script is SID/locale robust (resolves Administrators via S-1-5-32-544 and Guest via RID 501).
    - It does not rename accounts; it only manages membership + enabled state as described.

.LOGS
  Logs are written to:
    C:\ProgramData\Guest_Admin_Toggle_Logs\Guest_Admin_Toggle_YYYYMMDD_HHMMSS.log
#>

# --------------------------
# Toggle (default: secure)
# --------------------------
$AddGuestToAdminGroup = $false

# --------------------------
# Logging setup
# --------------------------
$logFolder = "C:\ProgramData\Guest_Admin_Toggle_Logs"
if (-not (Test-Path -Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
}
$logFile = Join-Path $logFolder ("Guest_Admin_Toggle_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Log ($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$timestamp] $msg"
}
function Info ($msg)  { Write-Host "[INFO]  $msg" -ForegroundColor Cyan;   Log $msg }
function Warn ($msg)  { Write-Host "[WARN]  $msg" -ForegroundColor Yellow; Log $msg }
function ErrorExit ($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red; Log "ERROR: $msg"; exit 1 }

Info "----- Script start -----"
Info "Mode: " + ($(if ($AddGuestToAdminGroup) { "INSECURE (add + enable Guest)" } else { "SECURE (remove + disable Guest)" }))

# --------------------------
# Safety: require admin
# --------------------------
$principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    ErrorExit "Please run this script as Administrator."
}

# --------------------------
# Resolve Administrators (localized) via SID S-1-5-32-544
# --------------------------
try {
    $adminSid = New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $adminNt  = $adminSid.Translate([Security.Principal.NTAccount]).Value
    $adminGroupName = $adminNt.Split('\')[-1]
    Info "Resolved Administrators group as '$adminGroupName' ($($adminSid.Value))"
} catch {
    ErrorExit "Failed to resolve local Administrators group: $($_.Exception.Message)"
}

# --------------------------
# Resolve local built-in Guest account (RID 501 -> ...-501)
# Works even if the Guest account was renamed.
# --------------------------
try {
    $guestAcct = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'"
    if (-not $guestAcct) { ErrorExit "Could not find the built-in Guest account (RID 501)." }
    $guestSID  = $guestAcct.SID
    $guestName = $guestAcct.Name   # May be renamed; display only
    Info "Resolved Guest account: Name='$guestName' SID='$guestSID'"
} catch {
    ErrorExit "Failed to resolve Guest account: $($_.Exception.Message)"
}

# --------------------------
# Helper: is Guest currently a member?
# Compare by SID to avoid localization/rename issues.
# --------------------------
function Test-GuestInAdmins {
    try {
        $members = Get-LocalGroupMember -Group $adminGroupName -ErrorAction Stop
        return $members.Where({ $_.SID -eq $guestSID }).Count -gt 0
    } catch {
        Warn "Failed to query group membership: $($_.Exception.Message)"
        return $false
    }
}

# --------------------------
# Add Guest to Administrators
# --------------------------
function Add-GuestToAdmins {
    if (Test-GuestInAdmins) {
        Info "Guest ($guestName / $guestSID) is already a member of '$adminGroupName'."
        return
    }
    try {
        Add-LocalGroupMember -Group $adminGroupName -Member $guestSID -ErrorAction Stop
        Info "Guest ($guestName / $guestSID) has been ADDED to '$adminGroupName'."
    } catch {
        ErrorExit "Failed to add Guest to '$adminGroupName': $($_.Exception.Message)"
    }
}

# --------------------------
# Remove Guest from Administrators
# --------------------------
function Remove-GuestFromAdmins {
    if (-not (Test-GuestInAdmins)) {
        Info "Guest ($guestName / $guestSID) is NOT a member of '$adminGroupName'."
        return
    }
    try {
        Remove-LocalGroupMember -Group $adminGroupName -Member $guestSID -ErrorAction Stop
        Info "Guest ($guestName / $guestSID) has been REMOVED from '$adminGroupName'."
    } catch {
        ErrorExit "Failed to remove Guest from '$adminGroupName': $($_.Exception.Message)"
    }
}

# --------------------------
# Execute
# --------------------------
if ($AddGuestToAdminGroup) {
    # Insecure path: add to Admins, then ENABLE Guest account if disabled
    Add-GuestToAdmins

    try {
        $guestLocal = Get-LocalUser | Where-Object { $_.SID -eq $guestSID }
        if (-not $guestLocal) {
            try {
                $guestLocal = Get-LocalUser -Name $guestName -ErrorAction Stop
            } catch {
                ErrorExit "Could not locate the Guest LocalUser object to enable (SID $guestSID, Name '$guestName')."
            }
        }

        if (-not $guestLocal.Enabled) {
            Enable-LocalUser -Name $guestLocal.Name -ErrorAction Stop
            Info "Guest account '$($guestLocal.Name)' has been ENABLED."
        } else {
            Info "Guest account '$($guestLocal.Name)' is already enabled."
        }
    } catch {
        ErrorExit "Failed to enable the Guest account: $($_.Exception.Message)"
    }
} else {
    # Secure path: remove from Admins, then DISABLE Guest account if enabled
    Remove-GuestFromAdmins

    try {
        $guestLocal = Get-LocalUser | Where-Object { $_.SID -eq $guestSID }
        if ($guestLocal) {
            if ($guestLocal.Enabled) {
                Disable-LocalUser -Name $guestLocal.Name -ErrorAction Stop
                Info "Guest account '$($guestLocal.Name)' has been DISABLED."
            } else {
                Info "Guest account '$($guestLocal.Name)' is already disabled."
            }
        } else {
            Info "Guest account (SID: $guestSID) not found via Get-LocalUser. It may already be disabled or hidden."
        }
    } catch {
        ErrorExit "Failed to disable the Guest account: $($_.Exception.Message)"
    }
}

# --------------------------
# Verification Summary (PASS/FAIL)
# --------------------------
Write-Host ""
Write-Host "==== Verification Summary ====" -ForegroundColor Cyan
Log "==== Verification Summary ===="

# Re-evaluate current state
$membershipNow = $false
try { $membershipNow = Test-GuestInAdmins } catch { $membershipNow = $false }

$guestLocalNow = Get-LocalUser | Where-Object { $_.SID -eq $guestSID }
$guestEnabled  = $null
if ($guestLocalNow) { $guestEnabled = [bool]$guestLocalNow.Enabled }

$overallPass = $false

if ($AddGuestToAdminGroup) {
    # In insecure mode, require membership present AND Guest enabled
    $membershipPass = $membershipNow
    $enabledPass    = ($null -ne $guestEnabled) -and $guestEnabled

    if ($membershipPass) {
        Write-Host "[PASS] Guest is a member of '$adminGroupName'." -ForegroundColor Green
        Log       "PASS: Guest is a member of '$adminGroupName'."
    } else {
        Write-Host "[FAIL] Guest is NOT a member of '$adminGroupName'." -ForegroundColor Red
        Log       "FAIL: Guest is NOT a member of '$adminGroupName'."
    }

    if ($enabledPass) {
        Write-Host "[PASS] Guest account is ENABLED." -ForegroundColor Green
        Log       "PASS: Guest account is ENABLED."
    } else {
        if ($null -eq $guestEnabled) {
            Write-Host "[FAIL] Could not determine Guest enabled state (LocalUser not found)." -ForegroundColor Red
            Log       "FAIL: Could not determine Guest enabled state (LocalUser not found)."
        } else {
            Write-Host "[FAIL] Guest account is DISABLED." -ForegroundColor Red
            Log       "FAIL: Guest account is DISABLED."
        }
    }

    $overallPass = $membershipPass -and $enabledPass
} else {
    # In secure mode, require NOT a member AND Guest disabled
    $membershipPass = -not $membershipNow
    $disabledPass   = ($null -ne $guestEnabled) -and (-not $guestEnabled)

    if ($membershipPass) {
        Write-Host "[PASS] Guest is NOT a member of '$adminGroupName'." -ForegroundColor Green
        Log       "PASS: Guest is NOT a member of '$adminGroupName'."
    } else {
        Write-Host "[FAIL] Guest is still a member of '$adminGroupName'." -ForegroundColor Red
        Log       "FAIL: Guest is still a member of '$adminGroupName'."
    }

    if ($disabledPass) {
        Write-Host "[PASS] Guest account is DISABLED." -ForegroundColor Green
        Log       "PASS: Guest account is DISABLED."
    } else {
        if ($null -eq $guestEnabled) {
            Write-Host "[FAIL] Could not determine Guest enabled state (LocalUser not found)." -ForegroundColor Red
            Log       "FAIL: Could not determine Guest enabled state (LocalUser not found)."
        } else {
            Write-Host "[FAIL] Guest account is still ENABLED." -ForegroundColor Red
            Log       "FAIL: Guest account is still ENABLED."
        }
    }

    $overallPass = $membershipPass -and $disabledPass
}

if ($overallPass) {
    Write-Host "`nOverall: PASS" -ForegroundColor Green
    Log       "Overall: PASS"
    Info "Log saved: $logFile"
    exit 0
} else {
    Write-Host "`nOverall: FAIL" -ForegroundColor Red
    Log       "Overall: FAIL"
    Info "Log saved: $logFile"
    exit 1
}
