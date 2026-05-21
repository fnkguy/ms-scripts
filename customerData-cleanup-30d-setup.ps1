#Requires -Version 5.1

# ── Configuration ──────────────────────────────────────────────
$taskName    = "customerData-cleanup-30d"
$scriptName  = "$taskName.ps1"
$defaultPath = Join-Path $ENV:USERPROFILE "Scripts"

# ── Step 1: Script save location (default with optional override) ──
Write-Host "`nThis installer creates a cleanup script and a monthly scheduled task." -ForegroundColor Cyan
Write-Host "Default script location: $defaultPath"

$ps1_dir = Read-Host "Press Enter to accept, or type a custom path"
if ([string]::IsNullOrWhiteSpace($ps1_dir)) { $ps1_dir = $defaultPath }

# Create directory if needed
if (-not (Test-Path $ps1_dir)) {
    New-Item -Path $ps1_dir -ItemType Directory -Force | Out-Null
}

$ps1_fullpath = Join-Path $ps1_dir $scriptName

# ── Step 2: Write the cleanup script ──────────────────────────
# IMPORTANT: Single-quoted here-string prevents variable expansion
$ps1_content = @'
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
'@

Set-Content -Path $ps1_fullpath -Value $ps1_content -Encoding UTF8
Write-Host "  Script created: $ps1_fullpath" -ForegroundColor Green

# ── Step 3: Detect PowerShell engine ──────────────────────────
$pwshPath = if (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe") {
    "C:\Program Files\PowerShell\7\pwsh.exe"
} elseif (Get-Command pwsh -ErrorAction SilentlyContinue) {
    (Get-Command pwsh).Source
} else {
    "powershell.exe"
}

# ── Step 4: Register Scheduled Task (monthly, 1st of each month) ──
# Using schtasks.exe for native monthly trigger support
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ps1_fullpath`""

schtasks.exe /Create `
    /TN "$taskName" `
    /TR "`"$pwshPath`" $arguments" `
    /SC MONTHLY /D 1 /ST 09:00 `
    /RL LIMITED `
    /F

# ── Done ──────────────────────────────────────────────────────
Write-Host "`n Setup complete!" -ForegroundColor Green
Write-Host "  Script Location:  $ps1_fullpath"
Write-Host "  Scheduled Task:   taskName (1st of every month at 09:00)"
Write-Host "  Engine:           $pwshPath" 
Write-Host "  Want to run now?: schtasks.exe /Run /TN `"$taskName`"" -ForegroundColor DarkGray