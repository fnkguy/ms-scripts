# Retention period
$cutoff = (Get-Date).AddDays(-30)

# Paths containing customer data
$paths = @(
    "$ENV:USERPROFILE\Downloads\Customer Data",
    "$ENV:USERPROFILE\Documents\Customer Data",
    "$ENV:USERPROFILE\CaseBuddy.CaseData\Archived",
    "$ENV:USERPROFILE\Pictures\Screenshots",
    "$ENV:ProgramData\Microsoft\Event Viewer\ExternalLogs"
)

foreach ($path in $paths) {
    if (-not (Test-Path $path)) { continue }

    Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# Remove empty directories afterwards
foreach ($path in $paths) {
    if (-not (Test-Path $path)) { continue }

    Get-ChildItem -Path $path -Directory -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue).Count -eq 0
        } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
