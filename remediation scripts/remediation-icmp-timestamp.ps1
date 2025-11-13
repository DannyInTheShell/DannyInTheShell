<#
.SYNOPSIS
  Blocks (secure) or removes (insecure) ICMP Timestamp Request (Type 13) and Timestamp Reply (Type 14)
  on Windows Server 2019 or Windows 11 using Windows Advanced Firewall.

.DESCRIPTION
  Remediates the “ICMP Timestamp Request Remote Date Disclosure” vulnerability (Plugin ID 10114)
  by blocking inbound ICMP type 13 and outbound ICMP type 14 using Windows Advanced Firewall. Toggle behavior with $secureEnvironment.

.TOGGLE
  $secureEnvironment = $true   # SECURE: create rules (block 13 inbound, 14 outbound)
  $secureEnvironment = $false  # INSECURE: remove those rules

.AUTHOR
  Danny Cologero

.DATE CREATED
  10-15-2025

.VERSION
  1.5 

.HOW TO USE
1) Open PowerShell as Administrator.
2) Set the toggle at the top of this script:
     $secureEnvironment = $true   # secure (apply)
     $secureEnvironment = $false  # insecure (remove)
3) Run:
     .\remediation-icmp-timestamp.ps1

.VERIFICATION
  PowerShell:
   1. Check applied rules in PowerShell:
     	Get-NetFirewallRule | findstr Timestamp
   2. Confirm the rules block traffic from another host:
      	nmap -sO -p 13,14 <server-ip>
     	 Note: You may get error if FW or NSG is blocking Ping: "Host seems down. If it is really up, but blocking our ping probes, try -Pn"
      	  nmap -sO -Pn -p 13,14 <host-ip>
   3. Rules persist across reboots; check again after restart.

.NOTES
  Requires: Windows Server 2019 Datacenter (Build 1809) or Windows 11, PowerShell 5.1+
  Administrative privileges required.
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
    Log "Apply operation started."

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

    # Verify
    $rIn  = Get-NetFirewallRule -DisplayName $ruleInName  -ErrorAction SilentlyContinue
    $rOut = Get-NetFirewallRule -DisplayName $ruleOutName -ErrorAction SilentlyContinue

    $passIn  = $false
    $passOut = $false

    if ($rIn -and $rIn.Enabled -eq "True" -and $rIn.Action -eq "Block" -and $rIn.Direction -eq "Inbound") {
        $icmpIn = Get-NetFirewallRule -DisplayName $ruleInName | Get-NetFirewallICMPSetting -ErrorAction SilentlyContinue
        if ($icmpIn -and ($icmpIn.IcmpType -contains 13)) { $passIn = $true }
    }
    if ($rOut -and $rOut.Enabled -eq "True" -and $rOut.Action -eq "Block" -and $rOut.Direction -eq "Outbound") {
        $icmpOut = Get-NetFirewallRule -DisplayName $ruleOutName | Get-NetFirewallICMPSetting -ErrorAction SilentlyContinue
        if ($icmpOut -and ($icmpOut.IcmpType -contains 14)) { $passOut = $true }
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
    Log "Revert operation started."

    # After pre-removal above, ensure none remain (idempotent)
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
