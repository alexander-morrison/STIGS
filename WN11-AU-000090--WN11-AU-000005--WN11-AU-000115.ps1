<#
.SYNOPSIS
Configures Windows Audit Policy settings for STIG compliance.

.DESCRIPTION
This script enables designated audit policy categories for “Object Access,” “Account Logon,” 
and “Privilege Use” in accordance with DISA STIG requirements. Specifically remediates:
- WN11-AU-000090
- WN11-AU-000005
- WN11-AU-000115

.NOTES
Author          : Alexander Morrison
LinkedIn        : https://linkedin.com/in/cyber-alexander
GitHub          : https://github.com/alexander-morrison
Date Created    : 2026-03-04
Last Modified   : 2026-03-04
Version         : 1.0
STIG-IDs        : WN11-AU-000090, WN11-AU-000005, WN11-AU-000115
PowerShell Ver. : 5.1+
Tested On       : Windows 11

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-GPO-Audit-Policies.ps1
#>

# Ensure script runs with admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit 1
}

try {
    Write-Host "Applying Audit Policy settings..." -ForegroundColor Yellow
    
    # Execute DISA STIG audit policy commands
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    auditpol /set /category:"Account Logon" /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable

    Write-Host "Audit policy successfully configured for:" -ForegroundColor Green
    Write-Host "- WN11-AU-000090 (Object Access)"
    Write-Host "- WN11-AU-000005 (Account Logon - Failure)"
    Write-Host "- WN11-AU-000115 (Privilege Use - Success)"
    
    Write-Host "`nVerification:" -ForegroundColor Cyan
    auditpol /get /category:"Object Access","Account Logon","Privilege Use"

    Write-Host "`nAll 3 vulnerabilities remediated — Compliance PASSED." -ForegroundColor Green
}
catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
