# List of paths with customer data
$paths = (
    "$ENV:USERPROFILE\OneDrive - Microsoft\Documents\ShareX\Logs",`
    "$ENV:USERPROFILE\OneDrive - Microsoft\Documents\ShareX\Screenshots",`
    "$ENV:USERPROFILE\CaseBuddy.CaseData\Archived",`
    "$ENV:USERPROFILE\OneDrive - Microsoft\Pictures\Screenshots",`
    "$ENV:ProgramData\Microsoft\Event Viewer\ExternalLogs")

# Store items older then 30 days from all $paths 
$items = Get-ChildItem $paths -Recurse | Where-Object {($_.lastwritetime -lt (Get-Date).AddDays(-30))}

# Delete all items in $items
foreach ($item in $items) {
    Remove-Item $item -Recurse -Verbose -Force
}