<#
.SYNOPSIS
Ensures Windows Installer 'Always install with elevated privileges' is disabled per STIG-ID WN11-CC-000315.

.DESCRIPTION
This script configures both HKLM and HKCU registry policies to explicitly set AlwaysInstallElevated=0,
prevents privilege escalation via MSI packages, and restarts MSI service for Tenable compliance.

.NOTES
Author          : Alexander Morrison
LinkedIn        : [https://linkedin.com/in/cyber-alexander](https://linkedin.com/in/cyber-alexander)
GitHub          : [https://github.com/alexander-morrison](https://github.com/alexander-morrison)
Date Created    : 2026-03-04
Last Modified   : 2026-03-04
Version         : 1.1
CVEs            : N/A
Plugin IDs      : 162174
STIG-ID         : WN11-CC-000315

.TESTED ON
Date(s) Tested  : 2026-03-04
Tested By       : Alexander Morrison
Systems Tested  : Windows 11
PowerShell Ver. : 5.1+

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-ID-WN11-CC-000315.ps1
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

#region Variables
$LMPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$CUPath = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
$RegName = "AlwaysInstallElevated"
$RequiredValue = 0
#endregion

#region Functions
function Test-AlwaysInstallElevatedDisabled {
    $lmCompliant = $true
    $cuCompliant = $true
    
    # Check HKLM
    if (Test-Path $LMPath) {
        $lmValue = (Get-ItemProperty -Path $LMPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
        $lmCompliant = ($null -eq $lmValue) -or ($lmValue -eq $RequiredValue)
    }
    
    # Check HKCU
    if (Test-Path $CUPath) {
        $cuValue = (Get-ItemProperty -Path $CUPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
        $cuCompliant = ($null -eq $cuValue) -or ($cuValue -eq $RequiredValue)
    }
    
    return $lmCompliant -and $cuCompliant
}

function Set-AlwaysInstallElevatedDisabled {
    # Configure HKLM
    if (!(Test-Path $LMPath)) { New-Item -Path $LMPath -Force | Out-Null }
    New-ItemProperty -Path $LMPath -Name $RegName -Value $RequiredValue -PropertyType DWORD -Force | Out-Null
    
    # Configure HKCU
    if (!(Test-Path $CUPath)) { New-Item -Path $CUPath -Force | Out-Null }
    New-ItemProperty -Path $CUPath -Name $RegName -Value $RequiredValue -PropertyType DWORD -Force | Out-Null
    
    # Apply policy and restart MSI service
    gpupdate /force | Out-Null
    Restart-Service -Name msiserver -Force
    Write-Verbose "Set AlwaysInstallElevated=0 in both HKLM/HKCU and restarted MSI service"
}
#endregion

#region Main
try {
    Write-Host "=== STIG-ID WN11-CC-000315: AlwaysInstallElevated Disabled ===" -ForegroundColor Cyan
    
    # Check current status
    if (Test-AlwaysInstallElevatedDisabled) {
        $lmCheck = Get-ItemProperty -Path $LMPath -Name $RegName -ErrorAction SilentlyContinue
        $cuCheck = Get-ItemProperty -Path $CUPath -Name $RegName -ErrorAction SilentlyContinue
        Write-Host "PASS: AlwaysInstallElevated disabled in both locations" -ForegroundColor Green
        Write-Host "HKLM: $($lmCheck.$RegName)  HKCU: $($cuCheck.$RegName)" -ForegroundColor Green
        exit 0
    }
    
    # Remediation needed
    Write-Warning "AlwaysInstallElevated NOT disabled per STIG. Remediating..."
    
    Set-AlwaysInstallElevatedDisabled
    
    # Verify remediation
    Start-Sleep -Seconds 3
    if (Test-AlwaysInstallElevatedDisabled) {
        $lmCheck = Get-ItemProperty -Path $LMPath -Name $RegName -ErrorAction SilentlyContinue
        $cuCheck = Get-ItemProperty -Path $CUPath -Name $RegName -ErrorAction SilentlyContinue
        Write-Host "SUCCESS: Remediation applied. Both registries show $RequiredValue" -ForegroundColor Green
        Write-Host "HKLM: $($lmCheck.$RegName)  HKCU: $($cuCheck.$RegName)" -ForegroundColor Green
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
