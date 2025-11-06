<# --- WINDOWS PERSONALIZATION --- #>
# Uninstall Taskbar Widgets
Winget unistall `
    "windows web experience pack"

# Taskbar - align left
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0

# Taskbar - remove search icon
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -value 0


<# --- SOFTWARE --- #>
# Package IDs to be installed
$Packages = (
    'google.googledrive'` #Google Drive
    'KeePassXCTeam.KeePassXC'` #KeePass XC
    '9NZVDKPMR9RD'` #FireFox
    'Notepad++.Notepad++'` # NotePad++
    'git.git'` #Git
    '9NBLGGH4Z1SP'` #ShareX
    'Microsoft.WindowsApp'` #Windows App
    'Microsoft.VisualStudioCode'` #Visual Studio Code
    'Microsoft.PowerShell'` #PowerShell 7
    'Microsoft.WSL'` #WSL
    'google.chrome'` #Google Chrome
    '9PDXGNCFSCZV' ) #Ubunto


# Install software
foreach ($Package in $Packages){
    Winget install --id $Package --silent --accept-package-agreements
}


<# --- GIT --- #>
# Create git.repo folder in C:/
New-Item -Path C:\git.repo
# Change directory to C:\git.repo
Set-Location C:\git.repo
# Clone ms-sripts to git.repo folder
git clone https://github.com/fnkguy/ms-scripts.git


<# --- POWERSHELL --- #>
# Set PowerShell location to Git Repo
New-Item -Path $ENV:USERPROFILE\Documents\PowerShell -Name profile.ps1
Add-Content -Path $ENV:USERPROFILE\Documents\PowerShell\profile.ps1 -Value "Set-Location 'C:\git.repo\ms-scripts"

# PowerShell modules to be installed
$modules = (
    'Microsoft.Graph',`
    'Microsoft.Graph.Authentication',`
    'Microsoft.Graph.Security',`
    'Microsoft.Graph.Beta.Security',`
    'Microsoft.Graph.Groups',`
    'Microsoft.Graph.Users',`
    'ExchangeOnlineManagement',`
    'PSWindowsUpdate',`
    'ORCA')

# Install each PowerShell module 
foreach ($module in $modules){
    Install-Module -Name $module -Force -Scope CurrentUser
    Import-Module -Name $module
}


<# TASK SCHEDULER #>
# pii-cleaner

# Windows Update

# Winget Update