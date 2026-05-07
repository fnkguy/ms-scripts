<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 26.04.29.1054

#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Users
#Requires -Modules Microsoft.Graph.Groups
#Requires -Modules ExchangeOnlineManagement -Version 3.0.0

<#
.SYNOPSIS
Evaluates user coverage and potential redundancies in Microsoft Defender for Office 365 and Exchange Online Protection threat policies, including anti-malware, anti-phishing, and anti-spam policies, as well as Safe Attachments and Safe Links policies if licensed.

.DESCRIPTION
This script checks which Microsoft Defender for Office 365 and Exchange Online Protection threat policies cover a particular user, including anti-malware, anti-phishing, inbound and outbound anti-spam, as well as Safe Attachments and Safe Links policies in case these are licensed for your tenant. In addition, the script can check for threat policies that have inclusion and/or exclusion settings that may be redundant or confusing and lead to missed coverage of users or coverage by an unexpected threat policy. It also includes an option to show all the actions and settings of the policies that apply to a user.

.PARAMETER CsvFilePath
    Allows you to specify a CSV file with a list of email addresses to check.
.PARAMETER EmailAddress
    Allows you to specify email address or multiple addresses separated by commas.
.PARAMETER IncludeMDOPolicies
    Checks both EOP and MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddress parameter.
.PARAMETER OnlyMDOPolicies
    Checks only MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddress parameter.
.PARAMETER ShowDetailedPolicies
    In addition to the policy applied, show any policy details that are set to True, On, or not blank.
.PARAMETER ShowDetailedExplanation
    Show specific explanation about why a policy is matched or not.
.PARAMETER SkipConnectionCheck
    Skips connection check for Graph and Exchange Online.
.PARAMETER SkipVersionCheck
    Skips the version check of the script.
.PARAMETER ScriptUpdateOnly
    Just updates script version to latest one.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1
	To check all threat policies for potentially confusing user inclusion and/or exclusion conditions and print them out for review.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv]
	To provide a CSV input file with email addresses and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddress user1@contoso.com,user2@fabrikam.com
	To provide multiple email addresses by command line and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv] -IncludeMDOPolicies
	To provide a CSV input file with email addresses and see both EOP and MDO policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddress user1@contoso.com -OnlyMDOPolicies
	To provide an email address and see only MDO (Safe Attachment and Safe Links) policies.
#>

[CmdletBinding(DefaultParameterSetName = 'AppliedTenant')]
param(
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOCsv')]
    [string]$CsvFilePath,

    [Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = 'AppliedEmail')]
    [Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = 'AppliedMDOEmail')]
    [string[]]$EmailAddress,

    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedEmail')]
    [switch]$IncludeMDOPolicies,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$OnlyMDOPolicies,

    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedEmail')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$ShowDetailedPolicies,

    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedEmail')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$ShowDetailedExplanation,

    [Parameter(Mandatory = $false)]
    [switch]$SkipConnectionCheck,

    [Parameter(Mandatory = $false)]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

begin {





function Confirm-ProxyServer {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TargetUri
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    try {
        $proxyObject = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($TargetUri)
        if ($TargetUri -ne $proxyObject.OriginalString) {
            Write-Verbose "Proxy server configuration detected"
            Write-Verbose $proxyObject.OriginalString
            return $true
        } else {
            Write-Verbose "No proxy server configuration detected"
            return $false
        }
    } catch {
        Write-Verbose "Unable to check for proxy server configuration"
        return $false
    }
}

function WriteErrorInformationBase {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0],
        [ValidateSet("Write-Host", "Write-Verbose")]
        [string]$Cmdlet
    )

    [string]$errorInformation = [System.Environment]::NewLine + [System.Environment]::NewLine +
    "----------------Error Information----------------" + [System.Environment]::NewLine

    if ($null -ne $CurrentError.OriginInfo) {
        $errorInformation += "Error Origin Info: $($CurrentError.OriginInfo.ToString())$([System.Environment]::NewLine)"
    }

    $errorInformation += "$($CurrentError.CategoryInfo.Activity) : $($CurrentError.ToString())$([System.Environment]::NewLine)"

    if ($null -ne $CurrentError.Exception -and
        $null -ne $CurrentError.Exception.StackTrace) {
        $errorInformation += "Inner Exception: $($CurrentError.Exception.StackTrace)$([System.Environment]::NewLine)"
    } elseif ($null -ne $CurrentError.Exception) {
        $errorInformation += "Inner Exception: $($CurrentError.Exception)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.InvocationInfo.PositionMessage) {
        $errorInformation += "Position Message: $($CurrentError.InvocationInfo.PositionMessage)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage) {
        $errorInformation += "Remote Position Message: $($CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.ScriptStackTrace) {
        $errorInformation += "Script Stack: $($CurrentError.ScriptStackTrace)$([System.Environment]::NewLine)"
    }

    $errorInformation += "-------------------------------------------------$([System.Environment]::NewLine)$([System.Environment]::NewLine)"

    & $Cmdlet $errorInformation
}

function Write-VerboseErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Verbose"
}

function Write-HostErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Host"
}

function Invoke-WebRequestWithProxyDetection {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [string]
        $Uri,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [switch]
        $UseBasicParsing,

        [Parameter(Mandatory = $true, ParameterSetName = "ParametersObject")]
        [hashtable]
        $ParametersObject,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [string]
        $OutFile
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    if ([System.String]::IsNullOrEmpty($Uri)) {
        $Uri = $ParametersObject.Uri
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Confirm-ProxyServer -TargetUri $Uri) {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }

    if ($null -eq $ParametersObject) {
        $params = @{
            Uri     = $Uri
            OutFile = $OutFile
        }

        if ($UseBasicParsing) {
            $params.UseBasicParsing = $true
        }
    } else {
        $params = $ParametersObject
    }

    try {
        Invoke-WebRequest @params
    } catch {
        Write-VerboseErrorInformation
    }
}

<#
    Determines if the script has an update available.
#>
function Get-ScriptUpdateAvailable {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
    )

    $BuildVersion = "26.04.29.1054"

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $result = [PSCustomObject]@{
        ScriptName     = $scriptName
        CurrentVersion = $BuildVersion
        LatestVersion  = ""
        UpdateFound    = $false
        Error          = $null
    }

    if ((Get-AuthenticodeSignature -FilePath $scriptFullName).Status -eq "NotSigned") {
        Write-Warning "This script appears to be an unsigned test build. Skipping version check."
    } else {
        try {
            $versionData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequestWithProxyDetection -Uri $VersionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
            $latestVersion = ($versionData | Where-Object { $_.File -eq $scriptName }).Version
            $result.LatestVersion = $latestVersion
            if ($null -ne $latestVersion) {
                $result.UpdateFound = ($latestVersion -ne $BuildVersion)
            } else {
                Write-Warning ("Unable to check for a script update as no script with the same name was found." +
                    "`r`nThis can happen if the script has been renamed. Please check manually if there is a newer version of the script.")
            }

            Write-Verbose "Current version: $($result.CurrentVersion) Latest version: $($result.LatestVersion) Update found: $($result.UpdateFound)"
        } catch {
            Write-Verbose "Unable to check for updates: $($_.Exception)"
            $result.Error = $_
        }
    }

    return $result
}


function Confirm-Signature {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $File
    )

    $IsValid = $false
    $MicrosoftSigningRoot2010 = 'CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    $MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    try {
        $sig = Get-AuthenticodeSignature -FilePath $File

        if ($sig.Status -ne 'Valid') {
            Write-Warning "Signature is not trusted by machine as Valid, status: $($sig.Status)."
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        if (-not $chain.Build($sig.SignerCertificate)) {
            Write-Warning "Signer certificate doesn't chain correctly."
            throw
        }

        if ($chain.ChainElements.Count -le 1) {
            Write-Warning "Certificate Chain shorter than expected."
            throw
        }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            Write-Warning "Top-level certificate in chain is not a root certificate."
            throw
        }

        if ($rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2010 -and $rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2011) {
            Write-Warning "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)."
            throw
        }

        Write-Host "File signed by $($sig.SignerCertificate.Subject)"

        $IsValid = $true
    } catch {
        $IsValid = $false
    }

    $IsValid
}

<#
.SYNOPSIS
    Overwrites the current running script file with the latest version from the repository.
.NOTES
    This function always overwrites the current file with the latest file, which might be
    the same. Get-ScriptUpdateAvailable should be called first to determine if an update is
    needed.

    In many situations, updates are expected to fail, because the server running the script
    does not have internet access. This function writes out failures as warnings, because we
    expect that Get-ScriptUpdateAvailable was already called and it successfully reached out
    to the internet.
#>
function Invoke-ScriptUpdate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([boolean])]
    param ()

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)
    $tempFullName = (Join-Path ((Get-Item $env:TEMP).FullName) $scriptName)

    if ($PSCmdlet.ShouldProcess("$scriptName", "Update script to latest version")) {
        try {
            Invoke-WebRequestWithProxyDetection -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName" -OutFile $tempFullName
        } catch {
            Write-Warning "AutoUpdate: Failed to download update: $($_.Exception.Message)"
            return $false
        }

        try {
            if (Confirm-Signature -File $tempFullName) {
                Write-Host "AutoUpdate: Signature validated."
                if (Test-Path $oldFullName) {
                    Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                }
                Move-Item $scriptFullName $oldFullName
                Move-Item $tempFullName $scriptFullName
                Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                Write-Host "AutoUpdate: Succeeded."
                return $true
            } else {
                Write-Warning "AutoUpdate: Signature could not be verified: $tempFullName."
                Write-Warning "AutoUpdate: Update was not applied."
            }
        } catch {
            Write-Warning "AutoUpdate: Failed to apply update: $($_.Exception.Message)"
        }
    }

    return $false
}

<#
    Determines if the script has an update available. Use the optional
    -AutoUpdate switch to make it update itself. Pass -Confirm:$false
    to update without prompting the user. Pass -Verbose for additional
    diagnostic output.

    Returns $true if an update was downloaded, $false otherwise. The
    result will always be $false if the -AutoUpdate switch is not used.
#>
function Test-ScriptVersion {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Need to pass through ShouldProcess settings to Invoke-ScriptUpdate')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [switch]
        $AutoUpdate,
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
    )

    $updateInfo = Get-ScriptUpdateAvailable $VersionsUrl
    if ($updateInfo.UpdateFound) {
        if ($AutoUpdate) {
            return Invoke-ScriptUpdate
        } else {
            Write-Warning "$($updateInfo.ScriptName) $BuildVersion is outdated. Please download the latest, version $($updateInfo.LatestVersion)."
        }
    }

    return $false
}

function Get-NewLoggerInstance {
    [CmdletBinding()]
    param(
        [string]$LogDirectory = (Get-Location).Path,

        [ValidateNotNullOrEmpty()]
        [string]$LogName = "Script_Logging",

        [bool]$AppendDateTime = $true,

        [bool]$AppendDateTimeToFileName = $true,

        [int]$MaxFileSizeMB = 10,

        [int]$CheckSizeIntervalMinutes = 10,

        [int]$NumberOfLogsToKeep = 10
    )

    $fileName = if ($AppendDateTimeToFileName) { "{0}_{1}.txt" -f $LogName, ((Get-Date).ToString('yyyyMMddHHmmss')) } else { "$LogName.txt" }
    $fullFilePath = [System.IO.Path]::Combine($LogDirectory, $fileName)

    if (-not (Test-Path $LogDirectory)) {
        try {
            New-Item -ItemType Directory -Path $LogDirectory -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to create Log Directory: $LogDirectory. Inner Exception: $_"
        }
    }

    return [PSCustomObject]@{
        FullPath                 = $fullFilePath
        AppendDateTime           = $AppendDateTime
        MaxFileSizeMB            = $MaxFileSizeMB
        CheckSizeIntervalMinutes = $CheckSizeIntervalMinutes
        NumberOfLogsToKeep       = $NumberOfLogsToKeep
        BaseInstanceFileName     = $fileName.Replace(".txt", "")
        Instance                 = 1
        NextFileCheckTime        = ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
        PreventLogCleanup        = $false
        LoggerDisabled           = $false
    } | Write-LoggerInstance -Object "Starting Logger Instance $(Get-Date)"
}

function Write-LoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance,

        [Parameter(Mandatory = $true, Position = 1)]
        [object]$Object
    )
    process {
        if ($LoggerInstance.LoggerDisabled) { return }

        if ($LoggerInstance.AppendDateTime -and
            $Object.GetType().Name -eq "string") {
            $Object = "[$([System.DateTime]::Now)] : $Object"
        }

        # Doing WhatIf:$false to support -WhatIf in main scripts but still log the information
        $Object | Out-File $LoggerInstance.FullPath -Append -WhatIf:$false

        #Upkeep of the logger information
        if ($LoggerInstance.NextFileCheckTime -gt [System.DateTime]::Now) {
            return
        }

        #Set next update time to avoid issues so we can log things
        $LoggerInstance.NextFileCheckTime = ([System.DateTime]::Now).AddMinutes($LoggerInstance.CheckSizeIntervalMinutes)
        $item = Get-ChildItem $LoggerInstance.FullPath

        if (($item.Length / 1MB) -gt $LoggerInstance.MaxFileSizeMB) {
            $LoggerInstance | Write-LoggerInstance -Object "Max file size reached rolling over" | Out-Null
            $directory = [System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)
            $fileName = "$($LoggerInstance.BaseInstanceFileName)-$($LoggerInstance.Instance).txt"
            $LoggerInstance.Instance++
            $LoggerInstance.FullPath = [System.IO.Path]::Combine($directory, $fileName)

            $items = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*"

            if ($items.Count -gt $LoggerInstance.NumberOfLogsToKeep) {
                $item = $items | Sort-Object LastWriteTime | Select-Object -First 1
                $LoggerInstance | Write-LoggerInstance "Removing Log File $($item.FullName)" | Out-Null
                $item | Remove-Item -Force
            }
        }
    }
    end {
        return $LoggerInstance
    }
}

function Invoke-LoggerInstanceCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance
    )
    process {
        if ($LoggerInstance.LoggerDisabled -or
            $LoggerInstance.PreventLogCleanup) {
            return
        }

        Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*" |
            Remove-Item -Force
    }
}

function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {

        if ($null -ne $Script:WriteVerboseManipulateMessageAction) {
            $Message = & $Script:WriteVerboseManipulateMessageAction $Message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteVerboseRemoteManipulateMessageAction) {
            $Message = & $Script:WriteVerboseRemoteManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Verbose $Message

        if ($null -ne $Script:WriteVerboseDebugAction) {
            & $Script:WriteVerboseDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteVerboseDebugAction) {
            & $Script:WriteRemoteVerboseDebugAction $Message
        }
    }
}

function SetWriteVerboseAction ($DebugAction) {
    $Script:WriteVerboseDebugAction = $DebugAction
}

function SetWriteRemoteVerboseAction ($DebugAction) {
    $Script:WriteRemoteVerboseDebugAction = $DebugAction
}

function SetWriteVerboseManipulateMessageAction ($DebugAction) {
    $Script:WriteVerboseManipulateMessageAction = $DebugAction
}

function SetWriteVerboseRemoteManipulateMessageAction ($DebugAction) {
    $Script:WriteVerboseRemoteManipulateMessageAction = $DebugAction
}

function Write-Warning {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Warning from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )
    process {

        if ($null -ne $Script:WriteWarningManipulateMessageAction) {
            $Message = & $Script:WriteWarningManipulateMessageAction $Message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteWarningRemoteManipulateMessageAction) {
            $Message = & $Script:WriteWarningRemoteManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Warning $Message

        # Add WARNING to beginning of the message by default.
        $Message = "WARNING: $Message"

        if ($null -ne $Script:WriteWarningDebugAction) {
            & $Script:WriteWarningDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteWarningDebugAction) {
            & $Script:WriteRemoteWarningDebugAction $Message
        }
    }
}

function SetWriteWarningAction ($DebugAction) {
    $Script:WriteWarningDebugAction = $DebugAction
}

function SetWriteRemoteWarningAction ($DebugAction) {
    $Script:WriteRemoteWarningDebugAction = $DebugAction
}

function SetWriteWarningManipulateMessageAction ($DebugAction) {
    $Script:WriteWarningManipulateMessageAction = $DebugAction
}

function SetWriteWarningRemoteManipulateMessageAction ($DebugAction) {
    $Script:WriteWarningRemoteManipulateMessageAction = $DebugAction
}

<#
.DESCRIPTION
    An override for Write-Host to allow logging to occur and color format changes to match with what the user as default set for Warning and Error.
#>
function Write-Host {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Proper handling of write host with colors')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [object]$Object,
        [switch]$NoNewLine,
        [string]$ForegroundColor
    )
    process {
        $consoleHost = $host.Name -eq "ConsoleHost"

        if ($null -ne $Script:WriteHostManipulateObjectAction) {
            $Object = & $Script:WriteHostManipulateObjectAction $Object
        }

        $params = @{
            Object    = $Object
            NoNewLine = $NoNewLine
        }

        if ([string]::IsNullOrEmpty($ForegroundColor)) {
            if ($null -ne $host.UI.RawUI.ForegroundColor -and
                $consoleHost) {
                $params.Add("ForegroundColor", $host.UI.RawUI.ForegroundColor)
            }
        } elseif ($ForegroundColor -eq "Yellow" -and
            $consoleHost -and
            $null -ne $host.PrivateData.WarningForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.WarningForegroundColor)
        } elseif ($ForegroundColor -eq "Red" -and
            $consoleHost -and
            $null -ne $host.PrivateData.ErrorForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.ErrorForegroundColor)
        } else {
            $params.Add("ForegroundColor", $ForegroundColor)
        }

        Microsoft.PowerShell.Utility\Write-Host @params

        if ($null -ne $Script:WriteHostDebugAction -and
            $null -ne $Object) {
            &$Script:WriteHostDebugAction $Object
        }
    }
}

function SetProperForegroundColor {
    $Script:OriginalConsoleForegroundColor = $host.UI.RawUI.ForegroundColor

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.WarningForegroundColor) {
        Write-Verbose "Foreground Color matches warning's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.ErrorForegroundColor) {
        Write-Verbose "Foreground Color matches error's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }
}

function RevertProperForegroundColor {
    $Host.UI.RawUI.ForegroundColor = $Script:OriginalConsoleForegroundColor
}

function SetWriteHostAction ($DebugAction) {
    $Script:WriteHostDebugAction = $DebugAction
}

function SetWriteHostManipulateObjectAction ($ManipulateObject) {
    $Script:WriteHostManipulateObjectAction = $ManipulateObject
}

    # Cache to reduce calls to Get-MgGroup
    $groupCache = @{}
    # Cache of members to reduce number of calls to Get-MgGroupMember
    $memberCache = @{}

    function Write-DetailedExplanationOption {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Message,
            [Parameter(Mandatory = $true)]
            [switch]$ShowDetailedExplanation
        )
        if ($ShowDetailedExplanation) {
            Write-Host "`t`t$message"
        } else {
            Write-Verbose $message
        }
    }

    function Get-GroupObjectId {
        [OutputType([string])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [MailAddress]$GroupEmail
        )

        $stGroupEmail = $GroupEmail.ToString()
        # Check the cache first
        Write-Verbose "Searching cache for Group $stGroupEmail"
        if ($groupCache.ContainsKey($stGroupEmail)) {
            Write-Verbose "Group $stGroupEmail found in cache"
            return $groupCache[$stGroupEmail]
        }

        # Get the group
        $group = $null
        Write-Verbose "Getting Group $stGroupEmail"
        try {
            $group = Get-MgGroup -Filter "mail eq '$stGroupEmail'" -ErrorAction Stop
        } catch {
            Write-Host "Error getting group $stGroupEmail`:`n$_" -ForegroundColor Red
            return $null
        }

        if ($group -and $group.id) {
            if ($group.Id.GetType() -eq [string]) {
                # Cache the result
                Write-Verbose "Added to cache Group $stGroupEmail with Id $($group.Id)"
                $groupCache[$stGroupEmail] = $group.Id

                # Return the Object ID of the group
                return $group.Id
            } else {
                Write-Host "Wrong type for $($group.ToString()): $($group.Id.GetType().Name)" -ForegroundColor Red
                return $null
            }
        } else {
            Write-Host "The EmailAddress of group $stGroupEmail was not found." -ForegroundColor Red
            return $null
        }
    }

    # Function to check if an email is in a group
    function Test-IsInGroup {
        [OutputType([bool])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [MailAddress]$Email,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$GroupObjectId
        )

        # Check the cache first
        $stEmail = $Email.ToString()
        $cacheKey = "$stEmail|$GroupObjectId"
        Write-Verbose "Searching cache for value of User in Group: $stEmail | $GroupObjectId"
        if ($memberCache.ContainsKey($cacheKey)) {
            Write-Verbose "Found $stEmail|$GroupObjectId in cache"
            return $memberCache[$cacheKey]
        }

        # Get the group members
        $groupMembers = $null
        Write-Verbose "Getting $GroupObjectId"
        try {
            $groupMembers = Get-MgGroupMember -GroupId $GroupObjectId -All -ErrorAction Stop
        } catch {
            Write-Host "Error getting group members for $GroupObjectId`:`n$_" -ForegroundColor Red
            $memberCache[$cacheKey] = $false
            return $false
        }

        # Check if the email address is in the group
        if ($null -ne $groupMembers) {
            foreach ($member in $groupMembers) {
                # Check if the member is a user
                if ($member['@odata.type'] -eq '#microsoft.graph.user') {
                    if ($member.Id) {
                        # Get the user object by Id
                        Write-Verbose "Getting user with Id $($member.Id)"
                        try {
                            $user = Get-MgUser -UserId $member.Id -ErrorAction Stop
                        } catch {
                            Write-Host "Error getting user with Id $($member.Id):`n$_" -ForegroundColor Red
                            $memberCache[$cacheKey] = $false
                            return $false
                        }
                        # Compare the user's email address with the $email parameter
                        if ($user.Mail -eq $Email.ToString()) {
                            # Cache the result
                            $memberCache[$cacheKey] = $true
                            return $true
                        }
                    } else {
                        Write-Host "The user with Id $($member.Id) does not have an email address." -ForegroundColor Red
                    }
                }
                # Check if the member is a group
                elseif ($member['@odata.type'] -eq '#microsoft.graph.group') {
                    Write-Verbose "Nested group $($member.Id)"
                    # Recursive call to check nested groups
                    $isInNestedGroup = Test-IsInGroup -Email $Email -GroupObjectId $member.Id
                    if ($isInNestedGroup) {
                        # Cache the result
                        Write-Verbose "Cache group $cacheKey"
                        $memberCache[$cacheKey] = $true
                        return $true
                    }
                }
            }
        } else {
            Write-Verbose "The group with Object ID $GroupObjectId does not have any members."
        }

        # Cache the result
        $memberCache[$cacheKey] = $false
        return $false
    }

    function Test-EmailAddress {
        [OutputType([MailAddress])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$EmailAddress,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string[]]$AcceptedDomains
        )

        try {
            $tempAddress = $null
            Write-Verbose "Casting $EmailAddress"
            $tempAddress = [MailAddress]$EmailAddress
        } catch {
            Write-Host "The EmailAddress $EmailAddress cannot be validated. Please provide a valid email address." -ForegroundColor Red
            Write-Host "Error details:`n$_" -ForegroundColor Red
            return $null
        }

        $domain = $tempAddress.Host
        Write-Verbose "Checking domain $domain"
        if ($AcceptedDomains -contains $domain) {
            Write-Verbose "Verified domain $domain for $tempAddress"
            $recipient = $null
            Write-Verbose "Getting $EmailAddress"
            try {
                $recipient = Get-EXORecipient $EmailAddress -ErrorAction Stop
                if ($null -eq $recipient) {
                    Write-Host "$EmailAddress is not a recipient in this tenant." -ForegroundColor Red
                } else {
                    return $tempAddress
                }
            } catch {
                Write-Host "Error getting recipient $EmailAddress $tempAddress" -ForegroundColor Red
                Write-Verbose "$_"
            }
        } else {
            Write-Host "The domain $domain is not an accepted domain in your organization. Please provide a valid email address: $tempAddress " -ForegroundColor Red
        }
        return $null
    }

    # Function to check rules
    function Test-Rules {
        param(
            [Parameter(Mandatory = $true)]
            $Rules,
            [Parameter(Mandatory = $true)]
            [MailAddress]$Email,
            [Parameter(Mandatory = $false)]
            [switch]$Outbound
        )

        foreach ($rule in $Rules) {
            $senderOrReceiver = $exceptSenderOrReceiver = $memberOf = $exceptMemberOf = $domainsIs = $exceptIfDomainsIs = $null
            $emailInRule = $emailExceptionInRule = $groupInRule = $groupExceptionInRule = $domainInRule = $domainExceptionInRule = $false
            Write-Host " "
            if ($Outbound) {
                Write-DetailedExplanationOption -Message "Checking outbound spam rule: `"$($rule.Name)`"" -ShowDetailedExplanation:$ShowDetailedExplanation
                $requestedProperties = 'From', 'ExceptIfFrom', 'FromMemberOf', 'ExceptIfFromMemberOf', 'SenderDomainIs', 'ExceptIfSenderDomainIs'
                $senderOrReceiver = $rule.From
                $exceptSenderOrReceiver = $rule.ExceptIfFrom
                $memberOf = $rule.FromMemberOf
                $exceptMemberOf = $rule.ExceptIfFromMemberOf
                $domainsIs = $rule.SenderDomainIs
                $exceptIfDomainsIs = $rule.ExceptIfSenderDomainIs
            } else {
                Write-DetailedExplanationOption -Message "Checking rule: `"$($rule.Name)`"" -ShowDetailedExplanation:$ShowDetailedExplanation
                $requestedProperties = 'SentTo', 'ExceptIfSentTo', 'SentToMemberOf', 'ExceptIfSentToMemberOf', 'RecipientDomainIs', 'ExceptIfRecipientDomainIs'
                $senderOrReceiver = $rule.SentTo
                $exceptSenderOrReceiver = $rule.ExceptIfSentTo
                $memberOf = $rule.SentToMemberOf
                $exceptMemberOf = $rule.ExceptIfSentToMemberOf
                $domainsIs = $rule.RecipientDomainIs
                $exceptIfDomainsIs = $rule.ExceptIfRecipientDomainIs
            }

            $Policy.PSObject.Properties | ForEach-Object {
                if ($requestedProperties -contains $_.Name) {
                    Write-Host "`t`t$($_.Name): $($_.Value)"
                }
            }
            Write-Verbose " "

            if ($senderOrReceiver -and $Email -in $senderOrReceiver) {
                Write-DetailedExplanationOption -Message "Included in rule as User. Other conditions must match also." -ShowDetailedExplanation:$ShowDetailedExplanation
                $emailInRule = $true
            }
            if ($exceptSenderOrReceiver -and $Email -in $exceptSenderOrReceiver) {
                Write-DetailedExplanationOption -Message "Excluded from rule as User." -ShowDetailedExplanation:$ShowDetailedExplanation
                $emailExceptionInRule = $true
            }

            if ($memberOf) {
                foreach ($groupEmail in $memberOf) {
                    Write-DetailedExplanationOption -Message "Checking if recipient is in Group $groupEmail" -ShowDetailedExplanation:$ShowDetailedExplanation
                    $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $groupInRule = Test-IsInGroup -Email $Email -GroupObjectId $groupObjectId
                        if ($groupInRule) {
                            Write-DetailedExplanationOption -Message "Group membership match: $($Email.ToString()) is a member of Group $($groupObjectId)" -ShowDetailedExplanation:$ShowDetailedExplanation
                            break
                        } else {
                            Write-DetailedExplanationOption -Message "No Group match because $($Email.ToString()) is not a member of Group $($groupObjectId)" -ShowDetailedExplanation:$ShowDetailedExplanation
                        }
                    }
                }
            }

            if ($exceptMemberOf) {
                foreach ($groupEmail in $exceptMemberOf) {
                    Write-DetailedExplanationOption -Message "Checking if recipient is in excluded Group $groupEmail" -ShowDetailedExplanation:$ShowDetailedExplanation
                    $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $groupExceptionInRule = Test-IsInGroup -Email $Email -GroupObjectId $groupObjectId
                        if ($groupExceptionInRule) {
                            Write-DetailedExplanationOption -Message "Excluded from rule by group membership. $($Email.ToString()) is in excluded Group $($groupObjectId)" -ShowDetailedExplanation:$ShowDetailedExplanation
                            break
                        } else {
                            Write-DetailedExplanationOption -Message "$($Email.ToString()) is not excluded from rule by membership in Group $($groupObjectId)" -ShowDetailedExplanation:$ShowDetailedExplanation
                        }
                    }
                }
            }

            $temp = $Email.Host
            while ($temp.IndexOf(".") -gt 0) {
                if ($temp -in $domainsIs) {
                    Write-DetailedExplanationOption -Message "Domain is in rule: $temp. Other conditions must match also." -ShowDetailedExplanation:$ShowDetailedExplanation
                    $domainInRule = $true
                }
                if ($temp -in $exceptIfDomainsIs) {
                    Write-DetailedExplanationOption -Message "Excluded from rule by domain: $temp" -ShowDetailedExplanation:$ShowDetailedExplanation
                    $domainExceptionInRule = $true
                }
                $temp = $temp.Substring($temp.IndexOf(".") + 1)
            }

            # Check for explicit inclusion in any user, group, or domain that are not empty, and account for 3 empty inclusions
            # Also check for any exclusions as user, group, or domain. Nulls don't need to be accounted for and this is an OR condition for exclusions
            if (((($emailInRule -or (-not $senderOrReceiver)) -and ($domainInRule -or (-not $domainsIs)) -and ($groupInRule -or (-not $memberOf))) -and
                    ($emailInRule -or $domainInRule -or $groupInRule)) -and
                ((-not $emailExceptionInRule) -and (-not $groupExceptionInRule) -and (-not $domainExceptionInRule))) {
                Write-DetailedExplanationOption -Message "Policy match found: `"$($rule.Name)`"" -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Included in rule as User: $emailInRule. Included in rule by Group membership: $groupInRule. Included in rule by Domain: $domainInRule." -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Excluded from rule as User: $emailExceptionInRule. Excluded from rule by group membership: $groupExceptionInRule. Excluded from rule by domain: $domainExceptionInRule." -ShowDetailedExplanation:$ShowDetailedExplanation
                return $rule
            } else {
                Write-DetailedExplanationOption -Message "The rule/policy does not explicitly include the recipient because not all User, Group, and Domain properties which have values include the recipient. `n`t`tDue to the AND operator between the User, Group, and Domain inclusion properties, if any of those properties have non-null values (they are not empty), the recipient must be included in that property." -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Included in rule as User: $emailInRule. Included in rule by Group membership: $groupInRule. Included in rule by Domain: $domainInRule." -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Excluded from rule as User: $emailExceptionInRule. Excluded from rule by group membership: $groupExceptionInRule. Excluded from rule by domain: $domainExceptionInRule." -ShowDetailedExplanation:$ShowDetailedExplanation
            }

            # Check for implicit inclusion (no mailboxes included at all), which is possible for Presets and SA/SL. They are included if not explicitly excluded. Only inbound
            if ((-not $Outbound) -and
                (((-not $senderOrReceiver) -and (-not $domainsIs) -and (-not $memberOf)) -and
                ((-not $emailExceptionInRule) -and (-not $groupExceptionInRule) -and (-not $domainExceptionInRule)))) {
                Write-DetailedExplanationOption -Message "The recipient is IMPLICITLY included. There are no recipients explicitly included in the policy, and the user is not explicitly excluded either in the User, Group, or Domain exclusion properties. `n`t`tImplicit inclusion is possible for Preset policies and Safe Attachments and Safe Links in which no explicit inclusions have been made." -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Rule of matching policy: `"$($rule.Name)`"" -ShowDetailedExplanation:$ShowDetailedExplanation
                return $rule
            }
        }
        return $null
    }

    function Show-DetailedPolicy {
        param (
            [Parameter(Mandatory = $true)]
            $Policy
        )
        Write-Host "`n`tProperties of the policy that are True, On, or not blank:"
        $excludedProperties = 'Identity', 'Id', 'Name', 'ExchangeVersion', 'DistinguishedName', 'ObjectCategory', 'ObjectClass', 'WhenChanged', 'WhenCreated',
        'WhenChangedUTC', 'WhenCreatedUTC', 'ExchangeObjectId', 'OrganizationalUnitRoot', 'OrganizationId', 'OriginatingServer', 'ObjectState', 'Priority', 'ImmutableId',
        'Description', 'HostedContentFilterPolicy', 'AntiPhishPolicy', 'MalwareFilterPolicy', 'SafeAttachmentPolicy', 'SafeLinksPolicy', 'HostedOutboundSpamFilterPolicy'

        $Policy.PSObject.Properties | ForEach-Object {
            if ($null -ne $_.Value -and
                (($_.Value.GetType() -eq [Boolean] -and $_.Value -eq $true) -or
                ($_.Value -ne '{}' -and $_.Value -ne 'Off' -and $_.Value -ne $true -and $_.Value -ne '' -and $excludedProperties -notcontains $_.Name))) {
                Write-Host "`t`t$($_.Name): $($_.Value)"
            } else {
                Write-Verbose "`t`tExcluded property:$($_.Name): $($_.Value)"
            }
        }
        Write-Host " "
    }

    function Test-GraphContext {
        [OutputType([bool])]
        param (
            [Parameter(Mandatory = $true)]
            [string[]]$Scopes,
            [Parameter(Mandatory = $true)]
            [string[]]$ExpectedScopes
        )

        $validScope = $true
        foreach ($expectedScope in $ExpectedScopes) {
            if ($Scopes -contains $expectedScope) {
                Write-Verbose "Scopes $expectedScope is present."
            } else {
                Write-Host "The following scope is missing: $expectedScope" -ForegroundColor Red
                $validScope = $false
            }
        }
        return $validScope
    }

    function Write-DebugLog ($message) {
        if (![string]::IsNullOrEmpty($message)) {
            $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
        }
    }

    function Write-HostLog ($message) {
        if (![string]::IsNullOrEmpty($message)) {
            $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
        }
        # all write-host should be logged in the debug log as well.
        Write-DebugLog $message
    }

    $LogFileName = "MDOThreatPolicyChecker"
    $StartDate = Get-Date
    $StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
    $Script:DebugLogger = Get-NewLoggerInstance -LogName "$LogFileName-Debug-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
    $Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteVerboseAction ${Function:Write-DebugLog}
    SetWriteWarningAction ${Function:Write-HostLog}

    $BuildVersion = "26.04.29.1054"

    Write-Host ("MDOThreatPolicyChecker.ps1 script version $($BuildVersion)") -ForegroundColor Green

    if ($ScriptUpdateOnly) {
        switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false) {
            ($true) { Write-Host ("Script was successfully updated.") -ForegroundColor Green }
            ($false) { Write-Host ("No update of the script performed.") -ForegroundColor Yellow }
            default { Write-Host ("Unable to perform ScriptUpdateOnly operation.") -ForegroundColor Red }
        }
        return
    }

    if ((-not($SkipVersionCheck)) -and (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false)) {
        Write-Host ("Script was updated. Please re-run the command.") -ForegroundColor Yellow
        return
    }
}

process {
    if (-not $SkipConnectionCheck) {
        #Validate EXO PS Connection
        $exoConnection = $null
        try {
            $exoConnection = Get-ConnectionInformation -ErrorAction Stop
        } catch {
            Write-Host "Error checking EXO connection:`n$_" -ForegroundColor Red
            Write-Host "Verify that you have ExchangeOnlineManagement module installed." -ForegroundColor Yellow
            Write-Host "You need a connection to Exchange Online; you can use:" -ForegroundColor Yellow
            Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
            Write-Host "Exchange Online Powershell Module is required." -ForegroundColor Red
            exit
        }
        if ($null -eq $exoConnection) {
            Write-Host "Not connected to EXO" -ForegroundColor Red
            Write-Host "You need a connection to Exchange Online; you can use:" -ForegroundColor Yellow
            Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
            Write-Host "Exchange Online Powershell Module is required." -ForegroundColor Red
            exit
        } elseif ($exoConnection.count -eq 1) {
            Write-Host " "
            Write-Host "Connected to EXO"
            Write-Host "Session details"
            Write-Host "Tenant Id: $($exoConnection.TenantId)"
            Write-Host "User: $($exoConnection.UserPrincipalName)"
        } else {
            Write-Host "You have more than one EXO session. Please use just one session." -ForegroundColor Red
            exit
        }

        if ($PSCmdlet.ParameterSetName -ne "AppliedTenant") {
            #Validate Graph is connected
            $graphConnection = $null
            Write-Host " "
            try {
                $graphConnection = Get-MgContext -ErrorAction Stop
            } catch {
                Write-Host "Error checking Graph connection:`n$_" -ForegroundColor Red
                Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                Write-Host "You could use:" -ForegroundColor Yellow
                Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
                exit
            }
            if ($null -eq $graphConnection) {
                Write-Host "Not connected to Graph" -ForegroundColor Red
                Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                Write-Host "You could use:" -ForegroundColor Yellow
                Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
                exit
            } elseif ($graphConnection.count -eq 1) {
                $expectedScopes = "Group.Read.All", 'User.Read.All'
                if (Test-GraphContext -Scopes $graphConnection.Scopes -ExpectedScopes $expectedScopes) {
                    Write-Host "Connected to Graph"
                    Write-Host "Session details"
                    Write-Host "TenantID: $(($graphConnection).TenantId)"
                    Write-Host "Account: $(($graphConnection).Account)"
                } else {
                    Write-Host "We cannot continue without Graph Powershell session without Expected Scopes." -ForegroundColor Red
                    Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                    Write-Host "You could use:" -ForegroundColor Yellow
                    Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
                    exit
                }
            } else {
                Write-Host "You have more than one Graph sessions. Please use just one session." -ForegroundColor Red
                exit
            }
            if (($graphConnection.TenantId) -ne ($exoConnection.TenantId) ) {
                Write-Host "`nThe Tenant Id from Graph and EXO are different. Please use the same tenant." -ForegroundColor Red
                exit
            }
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "AppliedTenant") {
        # Define the cmdlets to retrieve policies from and their corresponding policy types
        $cmdlets = @{
            "Get-HostedContentFilterRule"                                                                        = "Anti-spam Policy"
            "Get-HostedOutboundSpamFilterRule"                                                                   = "Outbound Spam Policy"
            "Get-MalwareFilterRule"                                                                              = "Malware Policy"
            "Get-AntiPhishRule"                                                                                  = "Anti-phishing Policy"
            "Get-SafeLinksRule"                                                                                  = "Safe Links Policy"
            "Get-SafeAttachmentRule"                                                                             = "Safe Attachment Policy"
            "Get-ATPBuiltInProtectionRule"                                                                       = "Built-in protection preset security Policy"
            { Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } }   = "EOP"
            { Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } } = "EOP"
            { Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } }   = "MDO (Safe Links / Safe Attachments)"
            { Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } } = "MDO (Safe Links / Safe Attachments)"
        }

        $foundIssues = $false

        Write-Host " "
        # Loop through each cmdlet
        foreach ($cmdlet in $cmdlets.Keys) {
            # Retrieve the policies
            $policies = & $cmdlet

            # Loop through each policy
            foreach ($policy in $policies) {
                # Initialize an empty list to store issues
                $issues = New-Object System.Collections.Generic.List[string]

                # Check the logic of the policy and add issues to the list
                if ($policy.SentTo -and $policy.ExceptIfSentTo) {
                    $issues.Add("`t`t-> User inclusions and exclusions. `n`t`t`tExcluding and including Users individually is redundant and confusing as only the included Users could possibly be included.`n")
                }
                if ($policy.RecipientDomainIs -and $policy.ExceptIfRecipientDomainIs) {
                    $issues.Add("`t`t-> Domain inclusions and exclusions. `n`t`t`tExcluding and including Domains is redundant and confusing as only the included Domains could possibly be included.`n")
                }
                if ($policy.SentTo -and $policy.SentToMemberOf) {
                    $issues.Add("`t`t-> Illogical inclusions of Users and Groups. `n`t`t`tThe policy will only apply to Users who are also members of any Groups you have specified. `n`t`t`tThis makes the Group inclusion redundant and confusing.`n`t`t`tSuggestion: use one or the other type of inclusion.`n")
                }
                if ($policy.SentTo -and $policy.RecipientDomainIs) {
                    $issues.Add("`t`t-> Illogical inclusions of Users and Domains. `n`t`t`tThe policy will only apply to Users whose email domains also match any Domains you have specified. `n`t`t`tThis makes the Domain inclusion redundant and confusing.`n`t`t`tSuggestion: use one or the other type of inclusion.`n")
                }

                # Do the same checks for Outbound spam policies
                if ($policy.From -and $policy.ExceptIfFrom) {
                    $issues.Add("`t`t-> User inclusions and exclusions. `n`t`t`tExcluding and including Users individually is redundant and confusing as only the included Users could possibly be included.`n")
                }
                if ($policy.SenderDomainIs -and $policy.ExceptIfSenderDomainIs) {
                    $issues.Add("`t`t-> Domain inclusions and exclusions. `n`t`t`tExcluding and including Domains is redundant and confusing as only the included Domains could possibly be included.`n")
                }
                if ($policy.From -and $policy.FromMemberOf) {
                    $issues.Add("`t`t-> Illogical inclusions of Users and Groups. `n`t`t`tThe policy will only apply to Users who are also members of any Groups you have specified. `n`t`t`tThis makes the Group inclusion redundant and confusing.`n`t`t`tSuggestion: use one or the other type of inclusion.`n")
                }
                if ($policy.From -and $policy.SenderDomainIs) {
                    $issues.Add("`t`t-> Illogical inclusions of Users and Domains. `n`t`t`tThe policy will only apply to Users whose email domains also match any Domains you have specified. `n`t`t`tThis makes the Domain inclusion redundant and confusing.`n`t`t`tSuggestion: use one or the other type of inclusion.`n")
                }

                # If there are any issues, print the policy details once and then list all the issues
                if ($issues.Count -gt 0) {
                    if ($policy.State -eq "Enabled") {
                        $color = [console]::ForegroundColor
                    } else {
                        $color = "Yellow"
                    }
                    Write-Host ("Policy `"$($policy.Name)`":")
                    Write-Host ("`tType: $($cmdlets[$cmdlet]).")
                    Write-Host ("`tState: $($policy.State).") -ForegroundColor $color
                    Write-Host ("`tIssues: ") -ForegroundColor Red
                    foreach ($issue in $issues) {
                        Write-Host $issue
                    }
                    $foundIssues = $true
                }
            }
        }
        if (-not $foundIssues) {
            Write-Host ("No logical inconsistencies found!") -ForegroundColor DarkGreen
        }
    } else {
        if ($CsvFilePath) {
            try {
                # Import CSV file
                $csvFile = Import-Csv -Path $CsvFilePath
                # checking 'email' header
                if ($csvFile[0].PSObject.Properties.Name -contains 'Email') {
                    $EmailAddress = $csvFile | Select-Object -ExpandProperty Email
                } else {
                    Write-Host "CSV does not contain 'Email' header." -ForegroundColor Red
                    exit
                }
            } catch {
                Write-Host "Error importing CSV file:`n$_" -ForegroundColor Red
                exit
            }
        }

        $acceptedDomains = $null
        try {
            $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        } catch {
            Write-Host "Error getting Accepted Domains:`n$_" -ForegroundColor Red
            exit
        }

        if ($null -eq $acceptedDomains) {
            Write-Host "We do not get accepted domains." -ForegroundColor Red
            exit
        }

        if ($acceptedDomains.count -eq 0) {
            Write-Host "No accepted domains found." -ForegroundColor Red
            exit
        } else {
            $acceptedDomainList = New-Object System.Collections.Generic.List[string]
            $acceptedDomains | ForEach-Object { $acceptedDomainList.Add($_.DomainName.ToString()) }
        }

        $foundError = $false
        $validEmailAddress = New-Object System.Collections.Generic.List[MailAddress]
        foreach ($email in $EmailAddress) {
            $tempAddress = $null
            $tempAddress = Test-EmailAddress -EmailAddress $email -AcceptedDomains $acceptedDomainList
            if ($null -eq $tempAddress) {
                $foundError = $true
            } else {
                $validEmailAddress.Add($tempAddress)
            }
        }
        if ($foundError) {
            exit
        }

        $malwareFilterRules = $null
        $antiPhishRules = $null
        $hostedContentFilterRules = $null
        $hostedOutboundSpamFilterRules = $null
        $eopStrictPresetRules = $null
        $eopStandardPresetRules = $null

        if ( -not $OnlyMDOPolicies) {
            $malwareFilterRules = Get-MalwareFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $antiPhishRules = Get-AntiPhishRule | Where-Object { $_.State -ne 'Disabled' }
            $hostedContentFilterRules = Get-HostedContentFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $hostedOutboundSpamFilterRules = Get-HostedOutboundSpamFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $eopStrictPresetRules = Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
            $eopStandardPresetRules = Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
        }

        $safeAttachmentRules = $null
        $safeLinksRules = $null
        $mdoStrictPresetRules = $null
        $mdoStandardPresetRules = $null

        if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
            # Get the custom and preset rules for Safe Attachments/Links
            $safeAttachmentRules = Get-SafeAttachmentRule | Where-Object { $_.State -ne 'Disabled' }
            $safeLinksRules = Get-SafeLinksRule | Where-Object { $_.State -ne 'Disabled' }
            $mdoStrictPresetRules = Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
            $mdoStandardPresetRules = Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
        }

        foreach ($email in $validEmailAddress) {
            $stEmailAddress = $email.ToString()
            # Initialize a variable to capture all policy details
            $allPolicyDetails = ""
            Write-Host "`n`nPolicies applied to $stEmailAddress..." -ForegroundColor Yellow

            if ( -not $OnlyMDOPolicies) {
                # Check the Strict EOP rules first as they have higher precedence
                $matchedRule = $null
                if ($eopStrictPresetRules) {
                    $matchedRule = Test-Rules -Rules $eopStrictPresetRules -email $stEmailAddress
                }
                if ($eopStrictPresetRules -contains $matchedRule) {
                    $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority
                    if ($ShowDetailedPolicies) {
                        $allPolicyDetails += "`n`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
                    }
                    Write-Host $allPolicyDetails -ForegroundColor Green
                    $outboundSpamMatchedRule = $null
                    if ($hostedOutboundSpamFilterRules) {
                        $outboundSpamMatchedRule = Test-Rules -Rules $hostedOutboundSpamFilterRules -email $stEmailAddress -Outbound
                        if ($null -eq $outboundSpamMatchedRule) {
                            Write-Host "`nOutbound Spam policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                            $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy "Default"
                        } else {
                            $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.HostedOutboundSpamFilterPolicy
                            Write-Host "`nOutbound Spam policy applied:`n`tName: $($outboundSpamMatchedRule.HostedOutboundSpamFilterPolicy)`n`tPriority: $($outboundSpamMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($hostedOutboundSpamFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $hostedOutboundSpamFilterPolicy
                        }
                    }
                } else {
                    # Check the Standard EOP rules secondly
                    $matchedRule = $null
                    if ($eopStandardPresetRules) {
                        $matchedRule = Test-Rules -Rules $eopStandardPresetRules -email $stEmailAddress
                    }
                    if ($eopStandardPresetRules -contains $matchedRule) {
                        $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority
                        if ($ShowDetailedPolicies) {
                            $allPolicyDetails += "`n`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
                        }
                        Write-Host $allPolicyDetails -ForegroundColor Green
                        $outboundSpamMatchedRule = $allPolicyDetails = $null
                        if ($hostedOutboundSpamFilterRules) {
                            $outboundSpamMatchedRule = Test-Rules -Rules $hostedOutboundSpamFilterRules -Email $stEmailAddress -Outbound
                            if ($null -eq $outboundSpamMatchedRule) {
                                Write-Host "`nOutbound Spam policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                                $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy "Default"
                            } else {
                                $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.HostedOutboundSpamFilterPolicy
                                Write-Host "`nOutbound Spam policy applied:`n`tName: $($outboundSpamMatchedRule.HostedOutboundSpamFilterPolicy)`n`tPriority: $($outboundSpamMatchedRule.Priority)"  -ForegroundColor Yellow
                            }
                            if ($hostedOutboundSpamFilterPolicy -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy $hostedOutboundSpamFilterPolicy
                            }
                        }
                    } else {
                        # If no match in EOPProtectionPolicyRules, check MalwareFilterRules, AntiPhishRules, outboundSpam, and HostedContentFilterRules
                        $allPolicyDetails = " "
                        $malwareMatchedRule = $malwareFilterPolicy = $null
                        if ($malwareFilterRules) {
                            $malwareMatchedRule = Test-Rules -Rules $malwareFilterRules -Email $stEmailAddress
                        }
                        if ($null -eq $malwareMatchedRule) {
                            Write-Host "`nMalware policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                            $malwareFilterPolicy = Get-MalwareFilterPolicy "Default"
                        } else {
                            $malwareFilterPolicy = Get-MalwareFilterPolicy $malwareMatchedRule.MalwareFilterPolicy
                            Write-Host "`nMalware policy applied:`n`tName: $($malwareMatchedRule.MalwareFilterPolicy)`n`tPriority: $($malwareMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($malwareFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $malwareFilterPolicy
                        }

                        $antiPhishMatchedRule = $antiPhishPolicy = $null
                        if ($antiPhishRules) {
                            $antiPhishMatchedRule = Test-Rules -Rules $antiPhishRules -Email $stEmailAddress
                        }
                        if ($null -eq $antiPhishMatchedRule) {
                            Write-Host "`nAnti-phish policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                            $antiPhishPolicy = Get-AntiPhishPolicy "Office365 AntiPhish Default"
                        } else {
                            $antiPhishPolicy = Get-AntiPhishPolicy $antiPhishMatchedRule.AntiPhishPolicy
                            Write-Host "`nAnti-phish policy applied:`n`tName: $($antiPhishMatchedRule.AntiPhishPolicy)`n`tPriority: $($antiPhishMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($antiPhishPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $antiPhishPolicy
                        }

                        $spamMatchedRule = $hostedContentFilterPolicy = $null
                        if ($hostedContentFilterRules) {
                            $spamMatchedRule = Test-Rules -Rules $hostedContentFilterRules -Email $stEmailAddress
                        }
                        if ($null -eq $spamMatchedRule) {
                            Write-Host "`nAnti-spam policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                            $hostedContentFilterPolicy = Get-HostedContentFilterPolicy "Default"
                        } else {
                            $hostedContentFilterPolicy = Get-HostedContentFilterPolicy $spamMatchedRule.HostedContentFilterPolicy
                            Write-Host "`nAnti-spam policy applied:`n`tName: $($spamMatchedRule.HostedContentFilterPolicy)`n`tPriority: $($spamMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($hostedContentFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $hostedContentFilterPolicy
                        }

                        $outboundSpamMatchedRule = $hostedOutboundSpamFilterPolicy = $null
                        if ($hostedOutboundSpamFilterRules) {
                            $outboundSpamMatchedRule = Test-Rules -Rules $hostedOutboundSpamFilterRules -email $stEmailAddress -Outbound
                        }
                        if ($null -eq $outboundSpamMatchedRule) {
                            Write-Host "`nOutbound Spam policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                            $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy "Default"
                        } else {
                            $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.HostedOutboundSpamFilterPolicy
                            Write-Host "`nOutbound Spam policy applied:`n`tName: $($outboundSpamMatchedRule.HostedOutboundSpamFilterPolicy)`n`tPriority: $($outboundSpamMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($hostedOutboundSpamFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $hostedOutboundSpamFilterPolicy
                        }

                        $allPolicyDetails = $userDetails + "`n" + $allPolicyDetails
                        Write-Host $allPolicyDetails -ForegroundColor Yellow
                    }
                }
            }

            if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
                $domain = $email.Host
                $matchedRule = $null

                # Check the MDO Strict Preset rules first as they have higher precedence
                if ($mdoStrictPresetRules) {
                    $matchedRule = Test-Rules -Rules $mdoStrictPresetRules -Email $stEmailAddress
                }
                if ($mdoStrictPresetRules -contains $matchedRule) {
                    Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                    if ($ShowDetailedPolicies) {
                        Write-Host ("`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#microsoft-defender-for-office-365-security") -ForegroundColor Green
                    }
                } else {
                    # Check the Standard MDO rules secondly
                    $matchedRule = $null
                    if ($mdoStandardPresetRules) {
                        $matchedRule = Test-Rules -Rules $mdoStandardPresetRules -Email $stEmailAddress
                    }
                    if ($mdoStandardPresetRules -contains $matchedRule) {
                        Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                        if ($ShowDetailedPolicies) {
                            Write-Host ("`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#microsoft-defender-for-office-365-security") -ForegroundColor Green
                        }
                    } else {
                        # No match in preset ATPProtectionPolicyRules, check custom SA/SL rules
                        $SAmatchedRule = $null
                        if ($safeAttachmentRules) {
                            $SAmatchedRule = Test-Rules -Rules $safeAttachmentRules -Email $stEmailAddress
                        }
                        $SLmatchedRule = $null
                        if ($safeLinksRules) {
                            $SLmatchedRule = Test-Rules -Rules $safeLinksRules -Email $stEmailAddress
                        }
                        if ($null -eq $SAmatchedRule) {
                            # Get the Built-in Protection Rule
                            $builtInProtectionRule = Get-ATPBuiltInProtectionRule
                            # Initialize a variable to track if the user is a member of any excluded group
                            $isInExcludedGroup = $false
                            # Check if the user is a member of any group in ExceptIfSentToMemberOf
                            foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
                                $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                                if ((-not [string]::IsNullOrEmpty($groupObjectId)) -and (Test-IsInGroup -Email $stEmailAddress -GroupObjectId $groupObjectId)) {
                                    $isInExcludedGroup = $true
                                    break
                                }
                            }
                            # Check if the user is returned by ExceptIfSentTo, isInExcludedGroup, or ExceptIfRecipientDomainIs in the Built-in Protection Rule
                            if ($stEmailAddress -in $builtInProtectionRule.ExceptIfSentTo -or
                                $isInExcludedGroup -or
                                $domain -in $builtInProtectionRule.ExceptIfRecipientDomainIs) {
                                Write-Host "`nSafe Attachments:`n`tThe user is excluded from all Safe Attachment protection because they are excluded from Built-in Protection, and they are not explicitly included in any other policy." -ForegroundColor Red
                            } else {
                                Write-Host "`nSafe Attachments:`n`tIf your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy." -ForegroundColor Yellow
                            }
                            $policy = $null
                        } else {
                            $safeAttachmentPolicy = Get-SafeAttachmentPolicy -Identity $SAmatchedRule.Name
                            Write-Host "`nSafe Attachments:`n`tName: $($SAmatchedRule.Name)`n`tPriority: $($SAmatchedRule.Priority)"  -ForegroundColor Yellow
                            if ($SAmatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy $safeAttachmentPolicy
                            }
                        }

                        if ($null -eq $SLmatchedRule) {
                            # Get the Built-in Protection Rule
                            $builtInProtectionRule = Get-ATPBuiltInProtectionRule

                            # Initialize a variable to track if the user is a member of any excluded group
                            $isInExcludedGroup = $false

                            # Check if the user is a member of any group in ExceptIfSentToMemberOf
                            foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
                                $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                                if ((-not [string]::IsNullOrEmpty($groupObjectId)) -and (Test-IsInGroup -Email $stEmailAddress -GroupObjectId $groupObjectId)) {
                                    $isInExcludedGroup = $true
                                    break
                                }
                            }

                            # Check if the user is returned by ExceptIfSentTo, isInExcludedGroup, or ExceptIfRecipientDomainIs in the Built-in Protection Rule
                            if ($stEmailAddress -in $builtInProtectionRule.ExceptIfSentTo -or
                                $isInExcludedGroup -or
                                $domain -in $builtInProtectionRule.ExceptIfRecipientDomainIs) {
                                Write-Host "`nSafe Links:`n`tThe user is excluded from all Safe Links protection because they are excluded from Built-in Protection, and they are not explicitly included in any other policy." -ForegroundColor Red
                            } else {
                                Write-Host "`nSafe Links:`n`tIf your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy." -ForegroundColor Yellow
                            }
                            $policy = $null
                        } else {
                            $safeLinkPolicy = Get-SafeLinksPolicy -Identity $SLmatchedRule.Name
                            Write-Host "`nSafe Links:`n`tName: $($SLmatchedRule.Name)`n`tPriority: $($SLmatchedRule.Priority)" -ForegroundColor Yellow
                            if ($SLmatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy $safeLinkPolicy
                            }
                        }
                    }
                }
            }
        }
    }
    if (-not $ShowDetailedExplanation) {
        Write-Host ("`nFor details about why a policy applies to a recipient, use the -ShowDetailedExplanation parameter and run this script again.")
    }
    Write-Host " "
}

# SIG # Begin signature block
# MIInbgYJKoZIhvcNAQcCoIInXzCCJ1sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAE/yq2Y/yEpwHz
# uovRa/a4rhocej9mHpihyaJk8/P3OaCCDMkwggYEMIID7KADAgECAhMzAAACHPrN
# xZvoL37EAAAAAAIcMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBD
# b2RlIFNpZ25pbmcgUENBIDIwMjQwHhcNMjYwNDE2MTg1OTQxWhcNMjcwNDE1MTg1
# OTQxWjB0MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYD
# VQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQDVsZfgOKmM31HPfoWOoNEiw0SlCiIxUMC0I9NMWbucKOw/e9lP
# oAoehQVu6SG65V4EPzrYsnBnFPNoi4/HoOdjhz1qkrEt4I6tEcxXU6oOeY9zGveC
# /3iBeuhLYxM3M/PkcUoebF+Nednm8OkdSPoDu8imViHPQq/8CQUu0WRR4rE+dMRf
# rpVqfmNi2qWCX94T4MsepijGVkwE//tJg0ryAiYdHT34LSnlG/RSBZmQRGWZ5g8j
# qnKjRParSqMft1gvjuUTVgtWNZfgcLFSK5Wa0myrq8OPcgTGGsRgun+tnSS+IxDT
# xVsAPH1OzvPjwomguByhUe/OcvUN0D5Wmp7xAgMBAAGjggGqMIIBpjAOBgNVHQ8B
# Af8EBAMCB4AwHwYDVR0lBBgwFgYKKwYBBAGCN0wIAQYIKwYBBQUHAwMwHQYDVR0O
# BBYEFNoH7a2YDjOSwpkp6DHcmUS7J+0yMFQGA1UdEQRNMEukSTBHMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxFjAUBgNVBAUT
# DTIzMDAxMis1MDc1NjkwHwYDVR0jBBgwFoAUf1k/VCHarU/vBeXmo9ctBpQSCDEw
# YAYDVR0fBFkwVzBVoFOgUYZPaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwQ29kZSUyMFNpZ25pbmclMjBQQ0ElMjAyMDI0LmNy
# bDBtBggrBgEFBQcBAQRhMF8wXQYIKwYBBQUHMAKGUWh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwQ29kZSUyMFNpZ25pbmcl
# MjBQQ0ElMjAyMDI0LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IC
# AQAUnEqhaRXe0T3hIJjvdQErEkrA/7bByjn6t5IArODkkRjzkYwtKMc2yYj2quaN
# rLutWw2YZcngKPy1b71YyDJQTy4NDRwaSh9Tw5thrk3NmcPrAHia5vtcBJ1CgtKK
# 7mQbIcQ22d/N3813ayCDDFewu1+jsZmX+r/aTEqaOM4TVxVtRSkuCy8nAXKuChOK
# Li/zA4XuH8iEYqIsj2YoNaeSxVmeGiERXpKdo3dDmYi0kO5w2D8VS4c3+9h6gElY
# BaAAg/dYErBg27qT3vv0zRDJhJufvCNylA8S7/+8H5E/PV5cng6na9VV/w9OV3qu
# uND6zdGa2EX38Glp50F9AIQk3p2xXmcvorDeM4XJ7UlWYBi6g80J1SSOQnInCYFE
# msfUNn3+1AaTJKSJL83quKArTac2pKhu0Yzzzrzo6HrsRiQKzpnRBb1/dMa6P3hz
# 75XbMRBctNsFhZC07WCmjExdLg2eHW5uV0TY8D5+6wozJf7vF3+WHkYPO85Z+BC6
# U4FkNbYNycZ9cE4j1tXRdyDCfml6c0HWPHjNVDObrv9lKt3qUqFpX38VCqVCyNOO
# 1UcXfQiVjJw32U2WUKZjt/neJKHEBsm9kFsLuWzkQ53+qcaSaytmsCnk2gOglrlD
# 5d3kKyvvAw+rzm0lT8K38P6PLxfZQHhu4W8dV7Av8N2ZmDCCBr0wggSloAMCAQIC
# EzMAAAA5O7Y3Gb8GHWcAAAAAADkwDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTI0MDgwODIwNTQxOFoX
# DTM2MDMyMjIyMTMwNFowVzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQ
# Q0EgMjAyNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANgBnB7jOMeq
# lRYHNa265v4IY9fH8TKhemHfPINe1gpLaV3dhg324WwH06LcHbpnsBukCDNitryo
# 0dtS/EW6I/yEL/bLSY8hKpbfQuWusBPr9qazYcDxCW/qnjb5JsI1s8bNOg3bVATv
# QVL4tcf03aTycsz8QeCdM0l/yHRObJ9QqazM1r6VPEOJ7LL+uEEb73w6QCuhs89a
# 1uv1zerOYMnsneRRwCbpyW11IcggU0cRKDDq1pjVJzIbIF6+oiXXbReOsgeI8zu1
# FyQfK0fVkaya8SmVHQ/tOf23mZ4W9k0Ri22QW9p3UgSC5OUDktKxxcCmGL6tXLfO
# GSWHIIV4YrTJTT6PNty5REojHJuZHArkF9VnHTERWoTjAzfI3kP+5b4alUdhgAZ7
# ttOu1bVnXfHaqPYl2rPs20ji03LOVWsh/radgE17es5hL+t6lV0eVHrVhsssROWJ
# uz2MXMCt7iw7lFPG9LXKGjsmonn2gotGdHIuEg5JnJMJVmixd5LRlkmgYRZKzhxS
# CwyoGIq0PhaA7Y+VPct5pCHkijcIIDm0nlkK+0KyepolcqGm0T/GYQRMhHJlGOOm
# VQop36wUVUYklUy++vDWeEgEo4s7hxN6mIbf2MSIQ/iIfMZgJxC69oukMUXCrOC3
# SkE/xIkgpfl22MM1itkZ35nNXkMolU1lAgMBAAGjggFOMIIBSjAOBgNVHQ8BAf8E
# BAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFH9ZP1Qh2q1P7wXl5qPX
# LQaUEggxMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMA8GA1UdEwEB/wQFMAMB
# Af8wHwYDVR0jBBgwFoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBP
# oE2gS4ZJaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAw
# TgYIKwYBBQUHMAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMv
# TWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNydDANBgkqhkiG9w0BAQwFAAOC
# AgEAFJQfOChP7onn6fLIMKrSlN1WYKwDFgAddymOUO3FrM8d7B/W/iQ6DxXsDn7D
# 5W4wMwYeLystcEqfkjz4NURRgazyMu5yRzQh4LqjA4tStTcJh1opExo7nn5PuPBY
# nbu0+THSuVHTe0VTTPVhily/piFrDo3axQ9P4C+Ol5yet+2gTfekICS5xS+cYfSI
# vgn0JksVBVMYVI5QFu/qhnLhsEFEUzG8fvv0hjgkO+lkpV9ty6GkN4vdnd7ya6Q6
# aR9y34aiM1qmxaxBi6OUnyNl6fkuun/diTFnYDLTppOkr/mg5WSfCiDVMNCxtj4w
# PKC5OmHm1DQIt/MNokbbH3UGsFP1QbzsLocuSqLCvH09Io3fDPTmscR9Y75G4qX7
# RTX8AdBPo0I6OEojf39zuFZt0qOHm65YWQE69cZM2ueE1MB05dNNgHK9gTE7zKvK
# /fg8B2qjW88MT/WF5V5uvZGtqa9FSL2RazArA+rDPuf6JGYz4HpgMZHB4S6szWSK
# YBv0VisCzfxgeU+dquXW9bd0auYlOB58DPcOYKdc3Se94g+xL4pcEhbB54JOgAkw
# YTu/9dLeH2pDqeJZAABVDWRQCaXfO5LgyKwKCLYXpigrZYCjUSBcr+Ve8PFWMhVT
# Ql0v4q8J/AUmQN5W4n101cY2L4A7GTQG1h32HHAvfQESWP0xghn7MIIZ9wIBATBu
# MFcxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# KDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMjQCEzMAAAIc
# +s3Fm+gvfsQAAAAAAhwwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZI
# hvcNAQkEMSIEIB+bJ27r1O02bhnsmpyzOHo7sMMrIp9PlCQoqtiwi/tAMEIGCisG
# AQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAVVrqPI7XfUqzWgzQZucJ
# ORqStg5MaI5LIUXfI7aK62vMFfWSWzMtBHGjCEZ56IgM3+GiXxV+R9ARupM2oLEO
# RCutbuZ/gr53fbgWDT4aE6P0Xveu3FngcWO3fGpS8JoDbTIKCjzzg238SCg7vcjU
# 0Bx3u6euUMgL4efGaGkA+GoUqKZ2cxsLA1Pk83UkuIrSAzDdEZ5XFuP+DrH2OAT5
# qSH/z13uug2BjadtTUw67+LgNDjmC+pD5NZFNlzvtNi6kjGOTpP7AKFNRC/dIGJ8
# Eb01v4GWSqahAOGiOgcUTwwbZlVSnuwMC67wv9zwYPhL+6oFtIlehXj61yzMPmAJ
# N6GCF60wghepBgorBgEEAYI3AwMBMYIXmTCCF5UGCSqGSIb3DQEHAqCCF4YwgheC
# AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIB
# QQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCDn3CvQUdXLHkHGSR/8
# SkVknJffvwlgjdhrpk4XxhMnrgIGaetNQqX9GBMyMDI2MDQyOTE3MzM0NC45MDFa
# MASAAgH0oIHZpIHWMIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo2QjA1LTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEfswggcoMIIFEKAD
# AgECAhMzAAACEUUYOZtDz/xsAAEAAAIRMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDgxNDE4NDgxM1oXDTI2MTExMzE4
# NDgxM1owgdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTAr
# BgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUG
# A1UECxMeblNoaWVsZCBUU1MgRVNOOjZCMDUtMDVFMC1EOTQ3MSUwIwYDVQQDExxN
# aWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAz7m7MxAdL5Vayrk7jsMo3GnhN85ktHCZEvEcj4BIccHKd/NK
# C7uPvpX5dhO63W6VM5iCxklG8qQeVVrPaKvj8dYYJC7DNt4NN3XlVdC/voveJuPP
# hTJ/u7X+pYmV2qehTVPOOB1/hpmt51SzgxZczMdnFl+X2e1PgutSA5CAh9/Xz5NW
# 0CxnYVz8g0Vpxg+Bq32amktRXr8m3BSEgUs8jgWRPVzPHEczpbhloGGEfHaROmHh
# VKIqN+JhMweEjU2NXM2W6hm32j/QH/I/KWqNNfYchHaG0xJljVTYoUKPpcQDuhH9
# dQKEgvGxj2U5/3Fq1em4dO6Ih04m6R+ttxr6Y8oRJH9ZhZ3sciFBIvZh7E2YFXOj
# P4MGybSylQTPDEFAtHHgpkskeEUhsPDR9VvWWhekhQx3qXaAKh+AkLmz/hpE3e0y
# +RIKO2AREjULJAKgf+R9QnNvqMeMkz9PGrjsijqWGzB2k2JNyaUYKlbmQweOabsC
# ioiY2fJbimjVyFAGk5AeYddUFxvJGgRVCH7BeBPKAq7MMOmSCTOMZ0Sw6zyNx4Uh
# h5Y0uJ0ZOoTKnB3KfdN/ba/eKHFeEhi3WqAfzTxiy0rMvhsfsXZK7zoclqaRvVl8
# Q48J174+eyriypY9HhU+ohgiYi4uQGDDVdTDeKDtoC/hD2Cn+ARzwE1rFfECAwEA
# AaOCAUkwggFFMB0GA1UdDgQWBBRifUUDwOnqIcvfb53+yV0EZn7OcDAfBgNVHSME
# GDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsG
# AQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01p
# Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMB
# Af8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDAN
# BgkqhkiG9w0BAQsFAAOCAgEApEKdnMeIIUiU6PatZ/qbrwiDzYUMKRczC4Bp/XY1
# S9NmHI+2c3dcpwH2SOmDfdvIIqt7mRrgvBPYOvJ9CtZS5eeIrsObC0b0ggKTv2wr
# TgWG+qktqNFEhQeipdURNLN68uHAm5edwBytd1kwy5r6B93klxDsldOmVWtw/ngj
# 7knN09muCmwr17JnsMFcoIN/H59s+1RYN7Vid4+7nj8FcvYy9rbZOMndBzsTiosF
# 1M+aMIJX2k3EVFVsuDL7/R5ppI9Tg7eWQOWKMZHPdsA3ZqWzDuhJqTzoFSQShnZe
# nC+xq/z9BhHPFFbUtfjAoG6EDPjSQJYXmogja8OEa19xwnh3wVufeP+ck+/0gxNi
# 7g+kO6WaOm052F4siD8xi6Uv75L7798lHvPThcxHHsgXqMY592d1wUof3tL/eDaQ
# 0UhnYCU8yGkU2XJnctONnBKAvURAvf2qiIWDj4Lpcm0zA7VuofuJR1Tpuyc5p1ja
# 52bNZBBVqAOwyDhAmqWsJXAjYXnssC/fJkee314Fh+GIyMgvAPRScgqRZqV16dTB
# Yvoe+w1n/wWs/ySTUsxDw4T/AITcu5PAsLnCVpArDrFLRTFyut+eHUoG6UYZfj8/
# RsuQ42INse1pb/cPm7G2lcLJtkIKT80xvB1LiaNvPTBVEcmNSvFUM0xrXZXcYcxV
# XiYwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEB
# CwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAe
# Fw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGm
# TOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/H
# ZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDc
# wUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62A
# W36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1w
# jjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCG
# MFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ
# 1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP
# 8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFz
# ymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHz
# NgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3
# xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsG
# AQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/
# LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEG
# DCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8G
# A1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQw
# VgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9j
# cmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUF
# BwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfC
# cTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AF
# vonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l
# 9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn
# 8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5m
# O0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyx
# TkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4
# S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9
# y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM
# +Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhw
# RNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIDVjCCAj4C
# AQEwggEBoYHZpIHWMIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo2QjA1LTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIa
# AxUAKyp8q2VdgAq1VGkzd7PZwV6zNc2ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQsFAAIFAO2cYuowIhgPMjAyNjA0Mjkx
# MDU4NTBaGA8yMDI2MDQzMDEwNTg1MFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 7Zxi6gIBADAHAgEAAgIFrjAHAgEAAgISkTAKAgUA7Z20agIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBCwUAA4IBAQCbCfKgY1h5g0tJchkMAMR23sz3aefLHuMaHz2YkEEk
# qom4/41eYleJJGFO9g9pERjLyeQi3hOGDNRe9CEAXLko/8BpRJ4LXAGVNhFQQetx
# zW/RS5BM47U/0T6H2uYaTsUMGvRb3B+2NwueODpykgiD0ZgLHQ30EjPqrcrDinMm
# TxKf5l4ACHWv+aFDs74ouWGOCmOhS4uemQVmKhpjw7c9108PYELIYE2Lx9KkEhGU
# FJPsxhe0XeClc0k7JGOrwP6INTb20jvv7WsLPZXNZ5bPyVODB9tEptff5Hp9uwxV
# olPe/PR4uN3AAEbh3hl+j8Fao0SdxaSXXkwofBu2uDfpMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIRRRg5m0PP/GwAAQAA
# AhEwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgy4w6UX7S625XD3EnyBRge+KJpm8uVJM93zWHVodp
# I8UwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAsrTOpmu+HTq1aXFwvlhjF
# 8p2nUCNNCEX/OWLHNDMmtzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAACEUUYOZtDz/xsAAEAAAIRMCIEINZGqrJQ3d9F3kvhmzVa0Rr8
# 2pTIr8oa3ZHbfQZVkLuBMA0GCSqGSIb3DQEBCwUABIICAMCfKoZ2RatzijrliMFU
# yiTpGvAbvHwGVkHoY5SKaptGKlAdUGLfunP7tGrZHPS69Rt4hbCwjfyD7dsLkE9F
# NP1Fn8PcUMZIhm5O+jl2qLsK4/HK05HEfrU5lqj5zff4GyxBoyXSi5gMxcys6pg9
# maPtmxrGym9W5LOtATUKno84j52gCuJL76gVEPuBD28ETjs86XVlO8ZGgxRSFbav
# /DkzzP5R9xIbewjvZIlY6ZNWFZDNxqitlnqVA0yll4eHI7yEFy4DS46flIkl2wG3
# lo2B4tvx4B9gk3ed8Bq7xbeYI1Fu74tBRFbPoJ24om4ABOZwoxJBULMYrPz/S/x9
# yFBn9uUyyhZWwg2ub09augWomgqUgTVHyzviNeDU3mcQeiFEXwdxLZi98DilMf/k
# 69fr8zAU3U2K+rAXfOba4OAn5ccOjUxG0FbZldCL+U4KYf7Gfub1SeXCeiNeNV3s
# nIsa1657pjrc5K27UkmVRvLYif5zmQYRviY5GB19IUhEzOxOob3VCzba7OvEDTSK
# BXO01niGM/UML53ZZFV3xJ7Sc7WTFNLtDc3L+grQpzk2fXLzvaCng3CjlChGDzXO
# N/IALhgY4X25Uuh1twdRzI3fjuuD/HWtfSYUg22f/VoylYloMg8KitD4bv2edtmf
# LYBSHZwAfF9sNO//tnJVJ47g
# SIG # End signature block
