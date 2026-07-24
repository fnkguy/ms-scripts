$Rolegroups = Get-RoleGroup
# Display details of each policy
foreach ($rolegroup in $rolegroups) {
Write-Output "----------ROLE GROUP $($rolegroup.Name)-------------------"
}
<#
Write-Output "UserIDs              : $($rolegroup.Guid)"
Write-Output "Enabled              : $($rolegroup.Enabled)"
Write-Output "Default              : $($rolegroup.Default)"
Write-Output "External Limit - Hour: $($rolegroup.RecipientLimitExternalPerHour)"
Write-Output "Internal Limit - Hour: $($rolegroup.RecipientLimitInternalPerHour)"
Write-Output "Total Limit - Day    : $($rolegroup.RecipientLimitPerDay)"
Write-Output "Action               : $($rolegroup.ActionWhenThresholdReached)"
Write-Output "AutoForwarding       : $($rolegroup.AutoForwarding)"
Write-Output "Notify Outbound Spam : $($rolegroup.NotifyOutboundSpamRecipients)"
Write-Output "Notify               : $($rolegroup.Notify)"
Write-Output "Creation             : $($rolegroup.Creation)"
Write-Output "Change               : $($rolegroup.Change)"
Write-Output "-------------------------------------"
}
#>