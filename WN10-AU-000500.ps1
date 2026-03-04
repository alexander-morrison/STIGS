<#
.SYNOPSIS
Ensures that the maximum size of the Windows Application Event Log is at least 32 MB (32768 KB).

.DESCRIPTION
This script verifies and enforces the Windows Event Log size policy for the Application log 
in accordance with STIG-ID WN10-AU-000500.

.NOTES
Author          : Alexander Morrison
LinkedIn        : https://linkedin.com/in/cyber-alexander
GitHub          : https://github.com/alexander-morrison
Date Created    : 2026-03-04
Last Modified   : 2026-03-04
Version         : 1.1
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-AU-000500

.TESTED ON
Date(s) Tested  : 2026-03-04
Tested By       : [Your Name or Team]
Systems Tested  : Windows 10 / Windows 11
PowerShell Ver. : 5.1+

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-ID-WN10-AU-000500.ps1
#>

# Define constants
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName    = "MaxSize"
$ValueData    = 32768  # Equivalent to 32 MB (0x00008000 in hex)

try {
    # Check if the registry path exists; if not, create it
    if (-not (Test-Path $RegistryPath)) {
        Write-Host "Registry path not found. Creating path..." -ForegroundColor Yellow
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    # Get current value if it exists
    $CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

    # Set or update the value if necessary
    if ($null -eq $CurrentValue -or $CurrentValue -lt $ValueData) {
        Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type DWord
        Write-Host "Successfully set '$ValueName' to $ValueData KB at '$RegistryPath'." -ForegroundColor Green
    } else {
        Write-Host "Current value ($CurrentValue KB) already meets or exceeds $ValueData KB. No changes made." -ForegroundColor Cyan
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
