#OUTBOUND POLICIES & RULES
# select account
$AdminAccount = Read-Host "Admin account"
# Connect to Exchange Online PowerShell
Connect-ExchangeOnline -UserPrincipalName $AdminAccount
# Start transcript to log the output
Start-Transcript -Path "C:\temp\OutboundPolicies.txt"
# Get all outbound spam filter policies
$outboundSpamPolicies = Get-HostedOutboundSpamFilterPolicy
# Get all outbound spam filter rules
$outboundSpamRules = Get-HostedOutboundSpamFilterRule
# Display details of each policy
foreach ($policy in $outboundSpamPolicies) {
Write-Output "----------POLICIES-------------------"
Write-Output "Policy Name          : $($policy.Name)"
Write-Output "PolicyGuid           : $($policy.Guid)"
Write-Output "Enabled              : $($policy.Enabled)"
Write-Output "Default              : $($policy.Default)"
Write-Output "External Limit - Hour: $($policy.RecipientLimitExternalPerHour)"
Write-Output "Internal Limit - Hour: $($policy.RecipientLimitInternalPerHour)"
Write-Output "Total Limit - Day    : $($policy.RecipientLimitPerDay)"
Write-Output "Action               : $($policy.ActionWhenThresholdReached)"
Write-Output "AutoForwarding       : $($policy.AutoForwarding)"
Write-Output "Notify Outbound Spam : $($policy.NotifyOutboundSpamRecipients)"
Write-Output "Notify               : $($policy.Notify)"
Write-Output "Creation             : $($policy.Creation)"
Write-Output "Change               : $($policy.Change)"
Write-Output "-------------------------------------"
}
# Loop through each rule to get detailed information
foreach ($rule in $outboundSpamRules) {
Write-Output "--------RULES------------------------"
Write-Output "Name             : $($filter.Name)"
Write-Output "FilterGuid       : $($filter.Guid)"
Write-Output "Priority         : $($filter.Priority)"
Write-Output "Status           : $($filter.State)"
Write-Output "Users            : $($filter.From)"
Write-Output "Users Exception  : $($filter.ExceptIfFrom)"
Write-Output "Groups           : $($filter.FromMemberOf)"
Write-Output "Groups Exception : $($filter.ExceptIfFromMemberOf)"
Write-Output "Domains          : $($filter.SenderDomainIs)"
Write-Output "Domains Exception: $($filter.ExceptIfSenderDomainIs)"
Write-Output "Description      : $($filter.Description)"
Write-Output "Change           : $($filter.WhenChanged)"
Write-Host "-----------------------------"
}
# Stop transcript
Stop-Transcript
