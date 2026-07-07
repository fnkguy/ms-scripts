#ANTI MALWARE POLICIES & RULES
# select account
$AdminAccount = Read-Host "Admin account"
# Connect to Exchange Online PowerShell
Connect-ExchangeOnline -UserPrincipalName $AdminAccount
# Start transcript to log the output
Start-Transcript -Path "C:\temp\SafeAttachmentsPolicies.txt"
# Get all outbound spam filter policies
$SafeAttachmentsPolicies = Get-SafeAttachmentsPolicy
# Get all outbound spam filter rules
$SafeAttachmentsRules = Get-SafeAttachmentsRule
# Display details of each policy
foreach ($policy in $SafeAttachmentsPolicies) {
Write-Output "----------POLICIY $($policy.Name)-------------------"
Write-Output "PolicyGuid           : $($policy.Guid)"
Write-Output "Enabled              : $($policy.Enable)"
Write-Output "Default              : $($policy.IsDefault)"
Write-Output "Action               : $($policy.Action)"
Write-Output "Blocking Encrypted   : $($policy.EnableBlockingEncryptedAttachments)"
Write-Output "Organization Branding: $($policy.EnableOrganizationBranding)"
Write-Output "Redirect             : $($policy.Redirect)"
Write-Output "Redirect Address     : $($policy.RedirectAddress)"
Write-Output "Creation UTC         : $($policy.WhenCreatedUTC)"
Write-Output "Change UTC           : $($policy.WhenChangedUTC)"
Write-Output "-------------------------------------"
}
# Loop through each rule to get detailed information
foreach ($rule in $SafeAttachmentsRules) {
Write-Output "--------RULES $($filter.Name)------------------------"
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
Write-Output "Change           : $($filter.WhenChangedUTC)"
Write-Host "-----------------------------"
}
# Stop transcript
Stop-Transcript
