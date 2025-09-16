param(
    [Parameter(Mandatory = $true)]
    [string]$XmlPath,

    [string]$InternetMessageId,

    [string]$Subject,

    [string]$CsvPath
)

# Load the XML file
try {
    $x = Import-Clixml -Path $XmlPath
} catch {
    Write-Error "❌ Failed to load file: $XmlPath"
    exit 1
}

# Convert and flatten
$AuditData = @()
$x | ForEach-Object { $AuditData += ($_.AuditData | ConvertFrom-Json) }

$Flattened = $AuditData | ForEach-Object {
    $record = $_
    foreach ($item in $record.AffectedItems) {
        [PSCustomObject]@{
            CreationTime        = $record.CreationTime
            Operation           = $record.Operation
            UserId              = $record.UserId
            AppId               = $record.AppId
            ClientAppId         = $record.ClientAppId
            ClientIPAddress     = $record.ClientIPAddress
            ClientProcessName   = $record.ClientProcessName
            ClientInfoString    = $record.ClientInfoString
            ClientRequestId     = $record.ClientRequestId
            Workload            = $record.Workload
            ResultStatus        = $record.ResultStatus
            Subject             = $item.Subject
            InternetMessageId   = $item.InternetMessageId
            FolderPath          = $record.Folder.Path
            DestFolderPath      = $record.DestFolder.Path
            Attachments         = ($item.Attachments -join ", ")
            LogonUserSid        = $record.LogonUserSid
            MailboxOwnerSid     = $record.MailboxOwnerSid
            SessionId           = $record.SessionId
            MailboxOwnerUPN     = $record.MailboxOwnerUPN
            ExternalAccess      = $record.ExternalAccess
            InternalLogonType   = $record.InternalLogonType
            LogonType           = $record.LogonType
        }
    }
}

# Apply optional filters
if ($InternetMessageId) {
    $Flattened = $Flattened | Where-Object { $_.InternetMessageId -eq $InternetMessageId }
}

if ($Subject) {
    $Flattened = $Flattened | Where-Object { $_.Subject -like "*$Subject*" }
}

# Group and summarize
$Summary = $Flattened | Group-Object InternetMessageId | ForEach-Object {
    $group = $_.Group
    $first = $group | Select-Object -First 1

    [PSCustomObject]@{
        CreationTime        = $first.CreationTime
        Operation           = $first.Operation
        UserId              = $first.UserId
        AppId               = $first.AppId
        ClientAppId         = $first.ClientAppId
        ClientIPAddress     = $first.ClientIPAddress
        ClientProcessName   = $first.ClientProcessName
        ClientInfoString    = $first.ClientInfoString
        ClientRequestId     = $first.ClientRequestId
        Workload            = $first.Workload
        ResultStatus        = $first.ResultStatus
        Subject             = $first.Subject
        InternetMessageId   = $_.Name
        FolderPath          = $first.FolderPath
        DestFolderPath      = $first.DestFolderPath
        Attachments         = $first.Attachments
        LogonUserSid        = $first.LogonUserSid
        MailboxOwnerSid     = $first.MailboxOwnerSid
        SessionId           = $first.SessionId
        MailboxOwnerUPN     = $first.MailboxOwnerUPN
        ExternalAccess      = $first.ExternalAccess
        InternalLogonType   = $first.InternalLogonType
        LogonType           = $first.LogonType
        Occurrences         = $group.Count
    }
}

# Output or export
if ($CsvPath) {
    $Summary | Sort-Object CreationTime | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n✅ Exported to CSV: $CsvPath"
} else {
    $Summary | Sort-Object CreationTime | Format-List
}
