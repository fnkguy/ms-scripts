# update winget repository
winget update

# update all updatable software
winget upgrade --all --accept-package-agreements

# update all poweshell modules if available
Get-InstalledModule | foreach {update-module -name $_.name -force}