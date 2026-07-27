#OUTBOUND POLICIES & RULES
# select account
$AdminAccount = Read-Host "Admin account"
# Connect to Exchange Online PowerShell
Connect-ExchangeOnline -UserPrincipalName $AdminAccount
# Start transcript to log the output
Start-Transcript -Path "C:\temp\AntiPhishPolicies.txt"
# Get all outbound spam filter policies
$antiPhishPolicies = Get-AntiPhishPolicy
# Get all outbound spam filter rules
$antiPhishRules = Get-AntiPhishRule
# Display details of each policy
foreach ($policy in $antiPhishPolicies) {
Write-Output "----------POLICIY $($policy.Name)-------------------"
Write-Output "PolicyGuid           : $($policy.Guid)"
Write-Output "Enabled              : $($policy.Enabled)"
Write-Output "Default              : $($policy.IsDefault)"
Write-Output "Users To Protect     : $($policy.TargetedUsersToProtect)"
Write-Output "Targeted Users Action: $($policy.TargetedUserActionRecipients)"
Write-Output "MB Intel Action Recipients: $($policy.MailboxIntelligenceProtectionActionRecipients)"
Write-Output "Domains to Protect   : $($policy.TargetedDomainsToProtect)"
Write-Output "Targeted Domain Action: $($policy.TargetedDomainActionRecipients)"
Write-Output "Excluded Domains     : $($policy.ExcludedDomains)"
Write-Output "Excluded Senders     : $($policy.ExcludedSenders)"
Write-Output "Excluded Sub Domains: $($policy.ExcludedSubDomains)"
Write-Output "Creation             : $($policy.WhenCreatedUTC)"
Write-Output "Change               : $($policy.WhenChangedUTC)"
Write-Output "----------------------------------------------------"
}
# Loop through each rule to get detailed information
foreach ($rule in $antiPhishRules) {
Write-Output "--------RULES $($filter.Name)-----------------------"
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
Write-Host "------------------------------------------------------"
}
# Stop transcript
Stop-Transcript
