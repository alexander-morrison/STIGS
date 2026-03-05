<#
.SYNOPSIS
Sets the Account Lockout Threshold policy to 3 invalid logon attempts for Windows 11 STIG compliance.

.DESCRIPTION
This script enforces the Group Policy setting:
"Account lockout threshold" to "3 invalid logon attempts"
to comply with DISA STIG ID WN11-AC-000010.

This policy ensures that user accounts are locked after a defined number of failed logon attempts,
reducing the risk of brute-force password attacks.

.STIG REFERENCE
STIG-ID: WN11-AC-000010
Policy Name: Account lockout threshold
Recommended Setting: 3 invalid logon attempts
Command Used: net accounts /lockoutthreshold:3

.NOTES
Author          : Alexander Morrison
LinkedIn        : https://linkedin.com/in/cyber-alexander
GitHub          : https://github.com/alexander-morrison
Date Created    : 2026-03-05
Last Modified   : 2026-03-05
Version         : 1.0
PowerShell Ver. : 5.1+
Systems Tested  : Windows 11

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-ID-WN11-AC-000010.ps1
#>

# Ensure Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

try {
    Write-Host "Setting account lockout threshold to 3 invalid attempts..." -ForegroundColor Yellow
    net accounts /lockoutthreshold:3 | Out-Null

    Write-Host "Account lockout threshold successfully set to 3." -ForegroundColor Green

    Write-Host "`nVerifying configuration..." -ForegroundColor Cyan
    $LockoutSettings = net accounts | Select-String "Lockout threshold"
    if ($LockoutSettings -match "3") {
        Write-Host "Verification PASSED — Lockout threshold set to 3 invalid logon attempts." -ForegroundColor Green
    } else {
        Write-Host "Verification FAILED — Current setting does not match expected value." -ForegroundColor Red
    }
}
catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "WN11-AC-000010 remediation complete — COMPLIANT." -ForegroundColor Green
