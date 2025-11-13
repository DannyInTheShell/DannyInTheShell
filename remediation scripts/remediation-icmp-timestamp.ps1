<#
.SYNOPSIS
  Blocks (secure) or removes (insecure) ICMP Timestamp Request (Type 13) and Timestamp Reply (Type 14)
  on Windows Server 2019 or Windows 11 using Windows Advanced Firewall.

.DESCRIPTION
  Remediates the “ICMP Timestamp Request Remote Date Disclosure” vulnerability (Plugin ID 10114)
  by blocking inbound ICMP type 13 and outbound ICMP type 14. Toggle behavior with $secureEnvironment.

.TOGGLE
  $secureEnvironment = $true   # SECURE: create rules (block 13 inbound, 14 outbound)
  $secureEnvironment = $false  # INSECURE: remove those rules

.AUTHOR
  Danny Cologero

.DATE CREATED
  10-15-2025

.VERSION
  1.6

.HOW TO USE
1) Open PowerShell as Administrator.
2) Set the toggle at the top of this script:
     $secureEnvironment = $true   # secure (apply)
     $secureEnvironment = $false  # insecure (remove)
3) Run:
     .\remediation-icmp-timestamp.ps1

.VERIFICATION
  On the target (PowerShell):
    Get-NetFirewallRule -DisplayName "*Timestamp*" | ft DisplayName,Direction,Action,Enabled

  From another Windows host (PowerShell):
    & "C:\Program Files (x86)\Nmap\nping.exe" --icmp --icmp-type 13 -c 3 <server-ip>
    # Expected when blocked: SENT 3, RCVD 0

  Notes:
    - Rules persist across reboots. Re-check after restarting the target.
    - If nping is in PATH you can run:
        nping --icmp --icmp-type 13 -c 3 <server-ip>
      In Command Prompt (cmd.exe) omit the leading &.

  Troubleshooting nping
    If you see "Cannot determine Next Hop MAC address":
      1) Run PowerShell as Administrator
      2) Ensure Npcap is running:
           Get-Service npcap
      3) Send at IP layer:
           & "C:\Program Files (x86)\Nmap\nping.exe" --icmp --icmp-type 13 -c 3 --send-ip <server-ip>
      4) If multiple adapters, pick one:
           Get-NetAdapter | Where-Object Status -eq Up | Select Name, InterfaceDescription
           & "C:\Program Files (x86)\Nmap\nping.exe" -e "Ethernet" --icmp --icmp-type 13 -c 3 --send-ip <server-ip>
      5) Fallback check using Nmap NSE:
           & "C:\Program Files (x86)\Nmap\nmap.exe" -Pn -sn --script=icmp-timestamp <server-ip>

#>

# -------------------------------
# Toggle (secure vs insecure)
# -------------------------------
$secureEnvironment = $true

# ----------------------------------------
# Allow script in this session if restricted
# ----------------------------------------
if ($PSVersionTable.PSVersion.Major -ge 5) {
    if ((Get-ExecutionPolicy) -eq "Restricted") {
        Set-ExecutionPolicy RemoteSigned -Scope Process -Force
    }
}

# ----------------------------------------
# Logging Setup
# ----------------------------------------
$logFolder = "C:\ProgramData\ICMP_Remediation_Log"
if (-not (Test-Path -Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
}
$logFile = "$logFolder\ICMP_Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log ($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$timestamp] $msg"
}

# ----------------------------------------
# Console Helpers (mirror to log)
# ----------------------------------------
function Info ($msg)      { Write-Host "[INFO]  $msg" -ForegroundColor Cyan;   Log $msg }
function Warn ($msg)      { Write-Host "[WARN]  $msg" -ForegroundColor Yellow; Log $msg }
function PassMsg ($msg)   { Write-Host "[PASS]  $msg" -ForegroundColor Green;  Log "PASS: $msg" }
function FailMsg ($msg)   { Write-Host "[FAIL]  $msg" -ForegroundColor Red;    Log "FAIL: $msg" }
function ErrorExit ($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red;    Log "ERROR: $msg"; exit 1 }

# ----------------------------------------
# Admin check
# ----------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    ErrorExit "Please run this script as Administrator."
}

# Rule names
$ruleInName  = "Block ICMP Timestamp Request (Type 13) - Inbound"
$ruleOutName = "Block ICMP Timestamp Reply (Type 14) - Outbound"

# ----------------------------------------
# Helper: read ICMP types via COM (INetFwPolicy2 / INetFwRule3)
# Returns $true if the rule’s IcmpTypesAndCodes string includes "<Type>:"
# ----------------------------------------
function Test-RuleIcmpType {
    param(
        [Parameter(Mandatory=$true)][string]$DisplayName,
        [Parameter(Mandatory=$true)][int]$Type
    )
    try {
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        foreach ($rule in $fw.Rules) {
            if ($rule.Name -eq $DisplayName) {
                $s = [string]$rule.IcmpTypesAndCodes
                if ([string]::IsNullOrWhiteSpace($s)) { return $false }
                # Typical format: "13:*,8:*" etc
                if ($s -match "(^|,)\s*$Type\s*:") { return $true }
                return $false
            }
        }
        return $false
    } catch {
        return $false
    }
}

# ----------------------------------------
# Idempotently remove existing rules (both paths do this first)
# ----------------------------------------
if (Get-NetFirewallRule -DisplayName $ruleInName -ErrorAction SilentlyContinue) {
    Info "Existing inbound rule found; removing old rule."
    Remove-NetFirewallRule -DisplayName $ruleInName
}
if (Get-NetFirewallRule -DisplayName $ruleOutName -ErrorAction SilentlyContinue) {
    Info "Existing outbound rule found; removing old rule."
    Remove-NetFirewallRule -DisplayName $ruleOutName
}

if ($secureEnvironment) {
    # --------------------------
    # SECURE: Create rules
    # --------------------------
    Info "Starting ICMP Timestamp remediation (SECURE mode)..."

    # Inbound ICMP type 13
    Info "Creating inbound rule to block ICMP type 13 (Timestamp Request)..."
    New-NetFirewallRule -DisplayName $ruleInName `
        -Direction Inbound `
        -Protocol ICMPv4 `
        -IcmpType 13 `
        -Action Block `
        -Profile Any `
        -Description "Blocks ICMP Timestamp Request (type 13) to prevent remote system clock disclosure." `
        | Out-Null

    # Outbound ICMP type 14
    Info "Creating outbound rule to block ICMP type 14 (Timestamp Reply)..."
    New-NetFirewallRule -DisplayName $ruleOutName `
        -Direction Outbound `
        -Protocol ICMPv4 `
        -IcmpType 14 `
        -Action Block `
        -Profile Any `
        -Description "Blocks ICMP Timestamp Reply (type 14) to prevent remote system clock disclosure." `
        | Out-Null

    # Snapshot to log
    $confirm = Get-NetFirewallRule -DisplayName "*Timestamp*" |
               Select-Object DisplayName, Direction, Action, Enabled |
               Out-String
    Log "Rule snapshot:`n$confirm"

    # Verify (without Get-NetFirewallICMPSetting)
    $rIn  = Get-NetFirewallRule -DisplayName $ruleInName  -ErrorAction SilentlyContinue
    $rOut = Get-NetFirewallRule -DisplayName $ruleOutName -ErrorAction SilentlyContinue

    $passIn  = $false
    $passOut = $false

    if ($rIn -and $rIn.Enabled -eq "True" -and $rIn.Action -eq "Block" -and $rIn.Direction -eq "Inbound" `
        -and (Test-RuleIcmpType -DisplayName $ruleInName -Type 13)) {
        $passIn = $true
    }
    if ($rOut -and $rOut.Enabled -eq "True" -and $rOut.Action -eq "Block" -and $rOut.Direction -eq "Outbound" `
        -and (Test-RuleIcmpType -DisplayName $ruleOutName -Type 14)) {
        $passOut = $true
    }

    Write-Host ""
    Write-Host "==== Verification Summary (Apply) ====" -ForegroundColor Cyan
    if ($passIn)  { PassMsg "Inbound rule present, enabled, Block, Direction=Inbound, IcmpType=13." } else { FailMsg "Inbound rule verification failed." }
    if ($passOut) { PassMsg "Outbound rule present, enabled, Block, Direction=Outbound, IcmpType=14." } else { FailMsg "Outbound rule verification failed." }

    $overall = $passIn -and $passOut
    if ($overall) {
        PassMsg "Overall: APPLY PASS"
        Info "Remediation complete. ICMP Timestamp Requests/Replies are now blocked."
        Info "Log saved: $logFile"
        exit 0
    } else {
        FailMsg "Overall: APPLY FAIL"
        Warn "Remediation attempted but verification failed. Review the log."
        Info "Log saved: $logFile"
        exit 1
    }
}
else {
    # --------------------------
    # INSECURE: Remove rules
    # --------------------------
    Info "Removing ICMP Timestamp firewall rules (INSECURE mode)..."

    $rIn  = Get-NetFirewallRule -DisplayName $ruleInName  -ErrorAction SilentlyContinue
    $rOut = Get-NetFirewallRule -DisplayName $ruleOutName -ErrorAction SilentlyContinue
    if ($rIn)  { Remove-NetFirewallRule -DisplayName $ruleInName }
    if ($rOut) { Remove-NetFirewallRule -DisplayName $ruleOutName }

    # Verify removed
    $rIn2  = Get-NetFirewallRule -DisplayName $ruleInName  -ErrorAction SilentlyContinue
    $rOut2 = Get-NetFirewallRule -DisplayName $ruleOutName -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "==== Verification Summary (Revert) ====" -ForegroundColor Cyan
    if (-not $rIn2)  { PassMsg "Inbound rule removed." }  else { FailMsg "Inbound rule still present." }
    if (-not $rOut2) { PassMsg "Outbound rule removed." } else { FailMsg "Outbound rule still present." }

    $overall = (-not $rIn2) -and (-not $rOut2)
    if ($overall) {
        PassMsg "Overall: REVERT PASS"
        Info "Rules removed. Log saved: $logFile"
        exit 0
    } else {
        FailMsg "Overall: REVERT FAIL"
        Warn "Revert attempted but verification failed. Review the log."
        Info "Log saved: $logFile"
        exit 1
    }
}

# End of script
