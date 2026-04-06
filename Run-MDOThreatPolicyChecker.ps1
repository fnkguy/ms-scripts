<## Customer will need the PowerShell modules:
- ExchangeOnlineManagement
    o	Install-Module -Name ExchangeOnlineManagement -Force
    o	Import-Module ExchangeOnlineManagement -Force
- Microsoft.Graph
    o	Install-Module Microsoft.Graph -Repository PSGallery -Force
    o	Import-Module Microsoft.Graph -Force
#>

# Connect PowerShell session to Microsoft tenant
Connect-MgGraph -Scopes 'Group.Read.All','User.Read.All'
Connect-ExchangeOnline

# Change PowerShell location to the folder where the MDOThreatPolicyChecker is located
cd ~\downloads

# Start transcript to log the output
Start-Transcript -Path "C:\temp\SafeAttachments.txt"
 	
	# Run the MDOThreatPolicyChecker script to get the Safe Attachments information
.\MDOThreatPolicyChecker.ps1 -EmailAddress [user01@consoso.com],[user02@contoso.com] -OnlyMDOPolicies -ShowDetailedPolicies

# Stop transcript
Stop-Transcript