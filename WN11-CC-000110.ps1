<#
.SYNOPSIS
Ensures printing over HTTP is prevented in accordance with STIG-ID WN11-CC-000110.

.DESCRIPTION
This script verifies and enforces the registry policy to disable HTTP printing 
for the Windows Print Spooler service per STIG-ID WN11-CC-000110.

.NOTES
Author          : Alexander Morrison
LinkedIn        : [https://linkedin.com/in/cyber-alexander](https://linkedin.com/in/cyber-alexander)
GitHub          : [https://github.com/alexander-morrison](https://github.com/alexander-morrison)
Date Created    : 2026-03-04
Last Modified   : 2026-03-04
Version         : 1.1
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-CC-000110

.TESTED ON
Date(s) Tested  : 2026-03-04
Tested By       : Alexander Morrison
Systems Tested  : Windows 11
PowerShell Ver. : 5.1+

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-ID-WN11-CC-000110.ps1
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

#region Variables
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$RegName = "DisableHTTPPrinting"
$RequiredValue = 1  # DWORD 1 = Enabled (HTTP printing disabled)
#endregion

#region Functions
function Test-HTTPPrintingDisabled {
    if (!(Test-Path $RegPath)) { return $false }
    
    $currentValue = (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
    return $currentValue -eq $RequiredValue
}

function Set-HTTPPrintingDisabled {
    # Create registry path if it doesn't exist
    if (!(Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    
    # Set registry value
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RequiredValue -PropertyType DWORD -Force | Out-Null
    
    # Force policy refresh
    gpupdate /force | Out-Null
    Write-Verbose "Set DisableHTTPPrinting = $RequiredValue and applied policy"
}
#endregion

#region Main
try {
    Write-Host "=== STIG-ID WN11-CC-000110: Printing over HTTP Disabled ===" -ForegroundColor Cyan
    
    # Check current status
    if (Test-HTTPPrintingDisabled) {
        Write-Host "PASS: HTTP printing is disabled (DisableHTTPPrinting = $RequiredValue)" -ForegroundColor Green
        exit 0
    }
    
    # Remediation needed
    Write-Warning "HTTP printing is NOT disabled per STIG. Remediating..."
    
    Set-HTTPPrintingDisabled
    
    # Verify remediation
    Start-Sleep -Seconds 2
    if (Test-HTTPPrintingDisabled) {
        Write-Host "SUCCESS: Remediation applied. HTTP printing now disabled." -ForegroundColor Green
        exit 0
    } else {
        Write-Error "FAILED: Remediation did not apply correctly"
        exit 1
    }
}
catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    exit 1
}
#endregion
