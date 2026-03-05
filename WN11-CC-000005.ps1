<#
.SYNOPSIS
Disables camera access from the Windows 11 lock screen per STIG WN11-CC-000005.

.DESCRIPTION
This script enforces the Group Policy setting "Prevent enabling lock screen camera" 
via registry modification in accordance with STIG-ID WN11-CC-000005.

.NOTES
Author          : Alexander Morrison
LinkedIn        : [https://linkedin.com/in/cyber-alexander](https://linkedin.com/in/cyber-alexander)
GitHub          : [https://github.com/alexander-morrison](https://github.com/alexander-morrison)
Date Created    : 2026-03-04
Last Modified   : 2026-03-04
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-CC-000005

.TESTED ON
Date(s) Tested  : 2026-03-04
Tested By       : [Your Name or Team]
Systems Tested  : Windows 11
PowerShell Ver. : 5.1+

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-ID-WN11-CC-000005.ps1
#>

# Define constants
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$ValueName    = "NoLockScreenCamera"
$ValueData    = 1  # 1 = Disabled (compliant)

try {
    # Check if the registry path exists; if not, create it
    if (-not (Test-Path $RegistryPath)) {
        Write-Host "Registry path not found. Creating path..." -ForegroundColor Yellow
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    # Get current value if it exists
    $CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

    # Set or update the value if necessary (must be exactly 1 for compliance)
    if ($null -eq $CurrentValue -or $CurrentValue -ne $ValueData) {
        Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type DWord
        Write-Host "Successfully set '$ValueName' to $ValueData at '$RegistryPath'." -ForegroundColor Green
        Write-Host "Run 'gpupdate /force' to apply policy immediately." -ForegroundColor Cyan
    } else {
        Write-Host "Registry value '$ValueName' = $CurrentValue (already compliant)." -ForegroundColor Cyan
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "WN11-CC-000005 remediation complete." -ForegroundColor Green
