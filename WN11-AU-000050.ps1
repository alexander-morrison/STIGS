<#
.SYNOPSIS
WN11-AU-000050 - The system must be configured to audit Detailed Tracking - Process Creation successes.

.DESCRIPTION
WN11-AU-000050 means the system must be set up to log (audit) every successful creation of a process so that new program executions can be tracked and reviewed.

.NOTES
Author          : Alexander Morrison
LinkedIn        : https://linkedin.com/in/cyber-alexander
GitHub          : https://github.com/alexander-morrison
Date Created    : 2026-03-04
Last Modified   : 2026-03-04
Version         : 1.1
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-AU-000050

.TESTED ON
Date(s) Tested  : 2026-03-04
Tested By       : [Your Name or Team]
Systems Tested  : Windows 11
PowerShell Ver. : 5.1+

.USAGE
Run in an elevated PowerShell session.

Example:
PS C:\> .\STIG-ID-WN11-AU-000050.ps1
#>

# PowerShell Remediation Command
# Run elevated PowerShell (Admin):

# Enable Process Creation Success auditing (STIG requirement)
auditpol /set /subcategory:"Process Creation" /success:enable

# Force subcategory override (required per STIG WN11-SO-000030)
auditpol /set /category:"Detailed Tracking" /success:enable

auditpol /get /subcategory:"Process Creation"

# System audit policy
    # Category/Subcategory      Setting
    # Detailed Tracking
        # Process Creation      Success
