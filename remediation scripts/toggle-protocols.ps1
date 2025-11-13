<#
.SYNOPSIS
    Toggles cryptographic protocols (secure vs insecure) on the system.
    Please test thoroughly in a non-production environment before deploying widely.
    Make sure to run as Administrator or with appropriate privileges.

.NOTES
    Author        : Danny Cologero
    Date Created  : 2025-11-09
    Last Modified : 2025-11-12
    Version       : 1.1 (adds logging, verification, PASS/FAIL exit)

.TESTED ON
    Date(s) Tested  : 2025-11-09
    Tested By       : Danny Cologero
    Systems Tested  : Windows Server 2019 Datacenter, Build 1809
    PowerShell Ver. : 5.1.17763.7919

.USAGE
    Set [$makeSecure = $true] to secure the system
    Example syntax:
    PS C:\> .\toggle-protocols.ps1 

.LOGS
    C:\ProgramData\Protocol_Toggle_Logs\Protocol_Toggle_YYYYMMDD_HHMMSS.log
#>

# Variable to determine if we want to make the computer secure or insecure
$makeSecure = $true

# --- Logging setup ---
$logFolder = "C:\ProgramData\Protocol_Toggle_Logs"
if (-not (Test-Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
}
$logFile = Join-Path $logFolder ("Protocol_Toggle_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$ts] $msg"
}
function Info($msg)  { Write-Host "[INFO]  $msg"  -ForegroundColor Cyan;   Log $msg }
function Warn($msg)  { Write-Host "[WARN]  $msg"  -ForegroundColor Yellow; Log $msg }
function Fail($msg)  { Write-Host "[FAIL]  $msg"  -ForegroundColor Red;    Log "FAIL: $msg" }
function Pass($msg)  { Write-Host "[PASS]  $msg"  -ForegroundColor Green;  Log "PASS: $msg" }
function ErrorExit($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red; Log "ERROR: $msg"; exit 1 }

Info "----- Script start -----"
Info ("Mode: " + ($(if ($makeSecure) { "SECURE (disable legacy; enable TLS 1.2)" } else { "INSECURE (enable legacy; disable TLS 1.2)" })))

# Check if the script is run as Administrator
function Check-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Check-Admin)) {
    ErrorExit "Access Denied. Please run with Administrator privileges."
}

# --- Verification helper (reads back registry and validates expected values) ---
function Verify-Protocol {
    param(
        [string]$ProtocolName,
        [string]$ServerPath,
        [string]$ClientPath,
        [int]$ExpServerEnabled,
        [int]$ExpServerDisabledByDefault,
        [int]$ExpClientEnabled,
        [int]$ExpClientDisabledByDefault
    )

    $ok = $true

    $sv = Get-ItemProperty -Path $ServerPath -ErrorAction SilentlyContinue
    $cv = Get-ItemProperty -Path $ClientPath -ErrorAction SilentlyContinue

    if ($null -eq $sv) {
        Fail "$ProtocolName Server key missing: $ServerPath"
        $ok = $false
    } else {
        if ($sv.Enabled -ne $ExpServerEnabled) {
            Fail "$ProtocolName Server Enabled expected $ExpServerEnabled, found $($sv.Enabled)"
            $ok = $false
        } else { Pass "$ProtocolName Server Enabled = $ExpServerEnabled" }

        if ($sv.DisabledByDefault -ne $ExpServerDisabledByDefault) {
            Fail "$ProtocolName Server DisabledByDefault expected $ExpServerDisabledByDefault, found $($sv.DisabledByDefault)"
            $ok = $false
        } else { Pass "$ProtocolName Server DisabledByDefault = $ExpServerDisabledByDefault" }
    }

    if ($null -eq $cv) {
        Fail "$ProtocolName Client key missing: $ClientPath"
        $ok = $false
    } else {
        if ($cv.Enabled -ne $ExpClientEnabled) {
            Fail "$ProtocolName Client Enabled expected $ExpClientEnabled, found $($cv.Enabled)"
            $ok = $false
        } else { Pass "$ProtocolName Client Enabled = $ExpClientEnabled" }

        if ($cv.DisabledByDefault -ne $ExpClientDisabledByDefault) {
            Fail "$ProtocolName Client DisabledByDefault expected $ExpClientDisabledByDefault, found $($cv.DisabledByDefault)"
            $ok = $false
        } else { Pass "$ProtocolName Client DisabledByDefault = $ExpClientDisabledByDefault" }
    }

    if ($ok) { Pass "$ProtocolName verification PASSED" } else { Fail "$ProtocolName verification FAILED" }
    return $ok
}

# =========================
# SSL 2.0 settings
# =========================
$serverPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
$clientPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"

if ($makeSecure) {
    New-Item -Path $serverPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 2.0 has been disabled."
    Log        "SSL 2.0 has been disabled."
} else {
    New-Item -Path $serverPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 2.0 has been enabled."
    Log        "SSL 2.0 has been enabled."
}
$passSSL2 = Verify-Protocol -ProtocolName "SSL 2.0" -ServerPath $serverPathSSL2 -ClientPath $clientPathSSL2 `
    -ExpServerEnabled ($(if ($makeSecure) {0} else {1})) `
    -ExpServerDisabledByDefault ($(if ($makeSecure) {1} else {0})) `
    -ExpClientEnabled ($(if ($makeSecure) {0} else {1})) `
    -ExpClientDisabledByDefault ($(if ($makeSecure) {1} else {0}))

# =========================
# SSL 3.0 settings
# =========================
$serverPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
$clientPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"

if ($makeSecure) {
    New-Item -Path $serverPathSSL3 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL3 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL3 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL3 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL3 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL3 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 3.0 has been disabled."
    Log        "SSL 3.0 has been disabled."
} else {
    New-Item -Path $serverPathSSL3 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL3 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL3 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL3 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL3 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL3 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 3.0 has been enabled."
    Log        "SSL 3.0 has been enabled."
}
$passSSL3 = Verify-Protocol -ProtocolName "SSL 3.0" -ServerPath $serverPathSSL3 -ClientPath $clientPathSSL3 `
    -ExpServerEnabled ($(if ($makeSecure) {0} else {1})) `
    -ExpServerDisabledByDefault ($(if ($makeSecure) {1} else {0})) `
    -ExpClientEnabled ($(if ($makeSecure) {0} else {1})) `
    -ExpClientDisabledByDefault ($(if ($makeSecure) {1} else {0}))

# =========================
# TLS 1.0 settings
# =========================
$serverPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
$clientPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"

if ($makeSecure) {
    New-Item -Path $serverPathTLS10 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS10 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS10 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS10 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS10 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS10 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.0 has been disabled."
    Log        "TLS 1.0 has been disabled."
} else {
    New-Item -Path $serverPathTLS10 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS10 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS10 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS10 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS10 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS10 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.0 has been enabled."
    Log        "TLS 1.0 has been enabled."
}
$passTLS10 = Verify-Protocol -ProtocolName "TLS 1.0" -ServerPath $serverPathTLS10 -ClientPath $clientPathTLS10 `
    -ExpServerEnabled ($(if ($makeSecure) {0} else {1})) `
    -ExpServerDisabledByDefault ($(if ($makeSecure) {1} else {0})) `
    -ExpClientEnabled ($(if ($makeSecure) {0} else {1})) `
    -ExpClientDisabledByDefault ($(if ($makeSecure) {1} else {0}))

# =========================
# TLS 1.1 settings
# =========================
$serverPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
$clientPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"

if ($makeSecure) {
    New-Item -Path $serverPathTLS11 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS11 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS11 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS11 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS11 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS11 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.1 has been disabled."
    Log        "TLS 1.1 has been disabled."
} else {
    New-Item -Path $serverPathTLS11 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS11 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS11 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS11 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS11 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS11 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.1 has been enabled."
    Log        "TLS 1.1 has been enabled."
}
$passTLS11 = Verify-Protocol -ProtocolName "TLS 1.1" -ServerPath $serverPathTLS11 -ClientPath $clientPathTLS11 `
    -ExpServerEnabled ($(if ($makeSecure) {0} else {1})) `
    -ExpServerDisabledByDefault ($(if ($makeSecure) {1} else {0})) `
    -ExpClientEnabled ($(if ($makeSecure) {0} else {1})) `
    -ExpClientDisabledByDefault ($(if ($makeSecure) {1} else {0}))

# =========================
# TLS 1.2 settings
# =========================
$serverPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
$clientPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

if ($makeSecure) {
    New-Item -Path $serverPathTLS12 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS12 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS12 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS12 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS12 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS12 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.2 has been enabled."
    Log        "TLS 1.2 has been enabled."
} else {
    New-Item -Path $serverPathTLS12 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS12 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS12 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS12 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS12 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS12 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.2 has been disabled."
    Log        "TLS 1.2 has been disabled."
}
$passTLS12 = Verify-Protocol -ProtocolName "TLS 1.2" -ServerPath $serverPathTLS12 -ClientPath $clientPathTLS12 `
    -ExpServerEnabled ($(if ($makeSecure) {1} else {0})) `
    -ExpServerDisabledByDefault ($(if ($makeSecure) {0} else {1})) `
    -ExpClientEnabled ($(if ($makeSecure) {1} else {0})) `
    -ExpClientDisabledByDefault ($(if ($makeSecure) {0} else {1}))

# --- Overall summary & exit code ---
$overall = $passSSL2 -and $passSSL3 -and $passTLS10 -and $passTLS11 -and $passTLS12
if ($overall) {
    Pass  "Overall: Protocol posture verified."
    Info  "Log saved: $logFile"
    Write-Host "Please reboot for settings to take effect."
    exit 0
} else {
    Fail  "Overall: One or more protocol verifications FAILED."
    Info  "Log saved: $logFile"
    Write-Host "Please reboot for settings to take effect."
    exit 1
}
