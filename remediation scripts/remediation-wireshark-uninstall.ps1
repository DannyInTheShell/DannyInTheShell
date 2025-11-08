# Dot-source the script to load it and its comment-based help into your current PowerShell session. 
# Navigate to the directory where the script is stored.
# Type and run exactly this (with the space between the two dots): . .\remediation-wireshark-uninstall.ps1"

<#
.SYNOPSIS
Uninstalls any installed version of Wireshark from the system executing the script.

.DESCRIPTION
This script detects and uninstalls any installed version of Wireshark silently.
It checks both 64-bit and 32-bit installation paths, logs results, and requires
Administrator privileges to run. Tested on multiple Wireshark versions.
Please test thoroughly in a non-production environment before deploying widely.

.NOTES
Author        : Danny Cologero
Date Created  : 10-15-2025
Last Modified : 10-15-2025
Version       : 1.2
Tested On     : Windows Server 2019 Datacenter (Build 1809)
PowerShell Ver: 5.1.17763.7786

.EXAMPLE
PS C:\> .\remediation-wireshark-uninstall.ps1
Runs the script to automatically uninstall all installed Wireshark versions.

#>

# ----------------------------------------
# Ensure script is running as Administrator
# ----------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator."
    exit
}

# ----------------------------------------
# Define Variables
# ----------------------------------------
$silentUninstallSwitch = "/S"
$logFolder = "$env:ProgramData\Wireshark_Uninstall_Logs"
$logFile = "$logFolder\Wireshark_Uninstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Ensure log folder exists
if (-not (Test-Path -Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
}

Start-Transcript -Path $logFile

# ----------------------------------------
# Function: Detect Installed Wireshark Versions
# ----------------------------------------
function Get-WiresharkInstallPaths {
    $possiblePaths = @(
        "$env:ProgramFiles\Wireshark",
        "$env:ProgramFiles(x86)\Wireshark"
    )

    $installedPaths = @()

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            # Look for uninstall.exe in the folder
            $uninstaller = Join-Path $path "uninstall.exe"
            if (Test-Path $uninstaller) {
                # Use Get-Item for reliable version detection
                $version = (Get-Item $uninstaller).VersionInfo.ProductVersion
                $installedPaths += [PSCustomObject]@{
                    Path    = $uninstaller
                    Version = $version
                }
            }
        }
    }

    return $installedPaths
}

# ----------------------------------------
# Function: Uninstall Wireshark
# ----------------------------------------
function Uninstall-Wireshark {
    $installedWireshark = Get-WiresharkInstallPaths

    if ($installedWireshark.Count -eq 0) {
        Write-Output "No Wireshark installation found on this system."
        return
    }

    foreach ($install in $installedWireshark) {
        $displayName = "Wireshark $($install.Version)"
        Write-Output "Uninstalling $displayName..."

        try {
            # Attempt to uninstall application
            $uninstallCmd = "`"$($install.Path)`" $silentUninstallSwitch"
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstallCmd" -Wait -ErrorAction Stop
            Write-Host "Successfully uninstalled $displayName"
        }
        catch {
            Write-Error "Failed to uninstall ${displayName}: $($_)"
        }

    }
}

# ----------------------------------------
# Execute the Uninstall
# ----------------------------------------
Uninstall-Wireshark

Stop-Transcript
