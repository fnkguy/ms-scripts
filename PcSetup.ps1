<# --- WINDOWS PERSONALIZATION --- #>
# Uninstall Taskbar Widgets
Winget uninstall `
    "windows web experience pack"

# Taskbar - align left
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0

# Taskbar - remove search icon
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -value 0

# Taskbar - remove task view
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -value 0

# Keyboard - Set Default to PT
Set-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "1" -value 00000816

# Keyboard - Set Default to PT
#Set-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "Default" -value 00000816


<# --- GIT --- removed since this needs to be created in order to get this script
# Create git.repo folder in C:/
New-Item -Path C:\git.repo
# Change directory to C:\git.repo
Set-Location C:\git.repo
# Clone ms-sripts to git.repo folder
git clone https://github.com/fnkguy/ms-scripts.git
#>


<# --- SOFTWARE --- #>
# Package IDs to be installed
$Packages = (
    'google.googledrive',` <#Google Drive#> 
    'KeePassXCTeam.KeePassXC',` <#KeePass XC#> 
    '9NZVDKPMR9RD',` <#FireFox#>
    '9NBLGGH4Z1SP',` <#ShareX#> 
    'Microsoft.WindowsApp',` <#Windows App#>
    'Microsoft.VisualStudioCode',` <#Visual Studio Code#>
    'Microsoft.PowerShell',` <#PowerShell 7#>
    'Microsoft.WSL',` <#WSL#>
    'google.chrome',` <#Google Chrome#>
    '9PDXGNCFSCZV' <#Ubuntu#>)
    #'git.git'` #Git - removed since it needs to be installed in order to get this script
    #'Notepad++.Notepad++',` <#NotePad++#> - removed as not allowed by MS


# Install software
foreach ($Package in $Packages){
    Winget install --id $Package --silent --accept-package-agreements
}


<# --- POWERSHELL --- #>
# Set PowerShell location to Git Repo
New-Item -Path $ENV:USERPROFILE\"OneDrive - Microsoft"\Documents\PowerShell -Name profile.ps1
Add-Content -Path $ENV:USERPROFILE\"OneDrive - Microsoft"\Documents\PowerShell\profile.ps1 -Value "Set-Location 'C:\git.repo\ms-scripts'"

# PowerShell modules to be installed
$modules = (
    'Microsoft.Graph -repository PSGallery',`
    #'Microsoft.Graph.Authentication',`
    #'Microsoft.Graph.Security',`
    #'Microsoft.Graph.Beta.Security',`
    #'Microsoft.Graph.Groups',`
    #'Microsoft.Graph.Users',`
    'ExchangeOnlineManagement',`
    'PSWindowsUpdate',`
    'ORCA',`
    'SecurityPermissionsChecker')

# Install each PowerShell module 
foreach ($module in $modules){
    Install-Module -Name $module -Force -Scope CurrentUser
    Import-Module -Name $module
}


<# TASK SCHEDULER #>
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

# Windows Update

# Winget Update