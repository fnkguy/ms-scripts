# Install software
Winget install `
    google.googledrive ` #Google Drive
    KeePassXCTeam.KeePassXC ` #KeePass XC
    9NZVDKPMR9RD ` #FireFox
    Notepad++.Notepad++ ` # NotePad++
    git.git ` #Git
    9NBLGGH4Z1SP ` #ShareX
    Microsoft.WindowsApp ` #Windows App
    Microsoft.VisualStudioCode ` #Visual Studio Code
    Microsoft.PowerShell ` #PowerShell 7
    Microsoft.WSL ` #WSL
    google.chrome ` #Google Chrome
    9PDXGNCFSCZV ` #Ubunto
    --silent --accept-package-agreements #run silent & accept all

# Uninstall Taskbar Widgets
Winget unistall `
    "windows web experience pack"

# Taskbar - align left
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0

# Taskbar - remove search icon
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -value 0

# Create git.repo folder in C:/
New-Item -Path C:\git.repo
# Change directory to C:\git.repo
cd C:\git.repo
# Clone ms-sripts to git.repo folder
git clone https://github.com/fnkguy/ms-scripts.git

# Task Scheduler - pii-cleaner