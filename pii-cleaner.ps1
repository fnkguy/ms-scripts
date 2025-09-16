# List of paths with customer data
$paths = (
    'C:\Users\fnepomuceno\OneDrive - Microsoft\Documents\ShareX\Logs', `
    'C:\Users\fnepomuceno\OneDrive - Microsoft\Documents\ShareX\Screenshots', `
    'C:\Users\fnepomuceno\CaseBuddy.CaseData\Archived', `
    'C:\Users\fnepomuceno\OneDrive - Microsoft\Pictures\Screenshots', `
    'C:\ProgramData\Microsoft\Event Viewer\ExternalLogs')

# Store items older then 30 days from all $paths 
$items = Get-ChildItem $paths -Recurse | Where-Object {($_.lastwritetime -lt (Get-Date).AddDays(-30))}

# Delete all items in $items
foreach ($item in $items) {
    Remove-Item $item -Recurse -Verbose -Force
}