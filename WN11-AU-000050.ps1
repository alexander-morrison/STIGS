<#
.SYNOPSIS
Ensures Detailed Tracking - Process Creation Success auditing is enabled per STIG-ID WN11-AU-000050.

.DESCRIPTION
This script configures advanced audit policy to log successful process creation events (Event ID 4688)
as required by STIG-ID WN11-AU-000050 for process execution tracking and forensics.

.NOTES
Author          : Alexander Morrison
LinkedIn        : [https://linkedin.com/in/cyber-alexander](https://linkedin.com/in/cyber-alexander)
GitHub          : [https://github.com/alexander-morrison](https://github.com/alexander-morrison)
Date Created    : 2026-03-04
Last Modified   : 2026-03-04
Version         : 1.1
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-AU-000050

.TESTED ON
Date(s) Tested  : 2026-03-04
Tested By       : Alexander Morrison
Systems Tested  : Windows 11
PowerShell Ver. : 5.1+

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-ID-WN11-AU-000050.ps1
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

#region Variables
$Subcategory = "Process Creation"
$Category = "Detailed Tracking"
$SystemCategory = "System"
$ForceSubcategoryOption = "ForceSubcategory"
#endregion

#region Functions
function Test-ProcessCreationAudit {
    $result = auditpol /get /subcategory:"$Subcategory" 2>$null
    return $result -match "Success( and Failure)?"
}

function Test-SubcategoryOverride {
    $result = auditpol /get /option:$ForceSubcategoryOption 2>$null
    return $result -match "Enabled"
}

function Set-ProcessCreationAudit {
    Write-Verbose "Enabling System category auditing (prerequisite)..."
    auditpol /set /category:"$SystemCategory" /success:enable /failure:enable | Out-Null
    
    Write-Verbose "Enabling ForceSubcategory override..."
    auditpol /set /option:$ForceSubcategoryOption /success:enable | Out-Null
    
    Write-Verbose "Enabling Process Creation subcategory auditing..."
    auditpol /set /subcategory:"$Subcategory" /success:enable /failure:enable | Out-Null
}
#endregion

#region Main
try {
    Write-Host "=== STIG-ID WN11-AU-000050: Process Creation Auditing ===" -ForegroundColor Cyan
    
    # Check current status
    if (Test-ProcessCreationAudit -and Test-SubcategoryOverride) {
        $auditStatus = (auditpol /get /subcategory:"$Subcategory" 2>$null)
        Write-Host "PASS: Process Creation auditing enabled:`n$auditStatus" -ForegroundColor Green
        exit 0
    }
    
    # Remediation needed
    Write-Warning "Process Creation auditing NOT configured per STIG. Remediating..."
    
    Set-ProcessCreationAudit
    
    # Verify remediation
    Start-Sleep -Seconds 2
    if (Test-ProcessCreationAudit -and Test-SubcategoryOverride) {
        $auditStatus = (auditpol /get /subcategory:"$Subcategory" 2>$null)
        Write-Host "SUCCESS: Remediation applied.`nCurrent status:`n$auditStatus" -ForegroundColor Green
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
