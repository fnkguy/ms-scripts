# ch to run cmdleeck required permissionst
$Cmdlet = Read-Host "what is the command you are testing?"
$Perms = Get-ManagenentRoIe -Cmdlet $Cmdlet 
$Perms | ForEach-Object { 
	Get-ManagementRoIeAssignment -Role $_.Name -Delegating $false | Format-table -Auto Role, RoleAssigneeType, RoleAssigneeName
}

# Check what cmdlets are available for a role - "<Role Name>\"
Get-ManagementRoleEntry "Security Reader\*"

# 
Get-RoleGroup security*

#
Get-RoleGroup *

#
Get-ManagementRoleAssignment "Security Reader*"

# Add or remove roles to a custome role - only cmdlets from parent role are acceptable - "<Custom Role Name>\<command to add>"
Add-ManagementRoleEntry "<Custom Quarantine Role\Set-AntiPhishingPolicy"