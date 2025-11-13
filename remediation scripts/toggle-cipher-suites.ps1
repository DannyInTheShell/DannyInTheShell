<#
.SYNOPSIS
  Toggle the Schannel SSL Cipher Suite Order for both Windows Server 2019 and Windows 11.

.DESCRIPTION
  - $secureEnvironment = $true  -> writes a modern “secure” suite order
  - $secureEnvironment = $false -> writes a broader, intentionally “insecure” order for testing
  Notes:
    * TLS 1.3 suites (TLS_AES_*) are excluded from the policy value on all OSes because
      their ordering isn’t controlled by this policy. WS2019 doesn’t use TLS 1.3 anyway.

.NOTES
  Author        : Danny Cologero
  Date Created  : 2025-11-11
  Last Modified : 2025-11-12
  Version       : 1.1 (cross-OS handling + logging & verification)

.TESTED ON
  Windows Server 2019 Datacenter (Build 1809)
  Windows 11

.USAGE
  Set [$secureEnvironment = $true] to secure the system, $false to make it intentionally weak for testing.
  Then run:
    PS C:\> .\toggle-cipher-suites.ps1

.LOGS
  C:\ProgramData\Cipher_Suite_Toggle_Logs\Cipher_Suite_Toggle_YYYYMMDD_HHMMSS.log
#>

# --------------------------
# Toggle (secure vs insecure)
# --------------------------
$secureEnvironment = $true

# --------------------------
# Logging
# --------------------------
$logDir  = "C:\ProgramData\Cipher_Suite_Toggle_Logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$logFile = Join-Path $logDir ("Cipher_Suite_Toggle_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
function Log($m){ $ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; Add-Content -Path $logFile -Value "[$ts] $m" }
function Info($m){ Write-Host "[INFO]  $m" -ForegroundColor Cyan;   Log $m }
function Pass($m){ Write-Host "[PASS]  $m" -ForegroundColor Green;  Log "PASS: $m" }
function Fail($m){ Write-Host "[FAIL]  $m" -ForegroundColor Red;    Log "FAIL: $m" }
function ErrorExit($m){ Write-Host "[ERROR] $m" -ForegroundColor Red; Log "ERROR: $m"; exit 1 }

Info "----- Script start -----"
$mode = if ($secureEnvironment) { "SECURE" } else { "INSECURE" }
Info "Mode: $mode"

# --------------------------
# Admin check
# --------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  ErrorExit "Please run this script as Administrator."
}

# --------------------------
# Cipher suite lists (your originals)
# --------------------------
$secureCipherSuites = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256"

$insecureCipherSuites = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256,TLS_RSA_WITH_DES_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_RC4_128_MD5,TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,TLS_RSA_EXPORT_WITH_RC4_40_MD5,SSL_RSA_WITH_DES_CBC_SHA,SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_RSA_WITH_RC4_128_SHA,SSL_RSA_WITH_RC4_128_MD5,SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA,SSL_RSA_EXPORT1024_WITH_RC4_56_SHA,SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,SSL_RSA_EXPORT_WITH_RC4_40_MD5"

# --------------------------
# Build the list to write (exclude TLS 1.3 names from Functions value)
# --------------------------
$selected = if ($secureEnvironment) { $secureCipherSuites } else { $insecureCipherSuites }
$names = $selected -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

# TLS 1.3 suite names start with TLS_AES_* and are not controlled by this policy
$namesForPolicy = $names | Where-Object { $_ -notmatch '^TLS_AES_' }

# Optional: de-duplicate while keeping order
$seen = @{}
$orderedUnique = foreach ($n in $namesForPolicy) { if (-not $seen.ContainsKey($n)) { $seen[$n]=$true; $n } }
$policyValue = ($orderedUnique -join ',')

# --------------------------
# Write policy
# --------------------------
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
if (-not (Test-Path $regPath)) {
  New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "Functions" -Value $policyValue
Info  "Cipher Suite Order policy written."
Write-Host "`nEffective policy string written to registry:"
Write-Host $policyValue

# --------------------------
# Verify (read-back compare)
# --------------------------
$readBack = (Get-ItemProperty -Path $regPath -Name "Functions" -ErrorAction Stop).Functions
if (($readBack -replace '\s','') -ieq ($policyValue -replace '\s','')) {
  Pass "Registry verification: Functions matches intended value."
} else {
  Fail "Registry verification: Functions does NOT match intended value."
  ErrorExit "Aborting due to verification failure."
}

Info "NOTE: TLS 1.3 suites (TLS_AES_*) are not controlled by this policy and were excluded from the string."
Info "Reboot is required for Schannel to apply the new cipher suite order."
Write-Host "`nPlease restart the server to apply the changes. Log saved at: $logFile"
