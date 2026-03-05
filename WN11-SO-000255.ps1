<#
.SYNOPSIS
Configures User Account Control (UAC) setting for standard users in compliance with STIG WN11-SO-000255.

.DESCRIPTION
This script sets the policy for User Account Control prompt behavior for standard users
to "Automatically deny elevation requests" via registry modification. This enforces the 
Group Policy setting: "User Account Control: Behavior of the elevation prompt for standard users".

.STIG REFERENCE
STIG-ID: WN11-SO-000255
Setting: ConsentPromptBehaviorUser = 0
Policy Location: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options

.NOTES
Author          : Alexander Morrison
LinkedIn        : https://linkedin.com/in/cyber-alexander
GitHub          : https://github.com/alexander-morrison
Date Created    : 2026-03-04
Last Modified   : 2026-03-04
Version         : 1.0
PowerShell Ver. : 5.1+
Systems Tested  : Windows 11

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-ID-WN11-SO-000255.ps1
#>

# Ensure Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Define constants
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName    = "ConsentPromptBehaviorUser"
$CompliantValue = 0

try {
    Write-Host "Checking UAC configuration..." -ForegroundColor Yellow

    # Retrieve the current registry value
    $CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

    if ($CurrentValue -ne $CompliantValue) {
        Write-Host "Non-compliant value detected: $CurrentValue. Applying remediation..." -ForegroundColor Yellow
        Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $CompliantValue -Type DWord
        Write-Host "Successfully set '$ValueName' to $CompliantValue (Automatic Deny Elevation Requests)." -ForegroundColor Green
        
        # Apply updated policy immediately
        gpupdate /force | Out-Null
        Write-Host "Group policy updated successfully." -ForegroundColor Cyan
    }
    else {
        Write-Host "Registry setting already compliant. No action required." -ForegroundColor Cyan
    }
}
catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "WN11-SO-000255 remediation complete — COMPLIANT." -ForegroundColor Green
