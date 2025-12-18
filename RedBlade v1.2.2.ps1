# ========== RedBlade v1.2.2 - by Luis Montealegre ==========

# ========== Session Initialization ==========
$CaseInput = Read-Host "Do you have a case number? (Press Enter to skip)"
if ([string]::IsNullOrWhiteSpace($CaseInput)) {
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $SessionFolder = "RedBlade_Session_$Timestamp"
}
else {
    $SessionFolder = "RedBlade_$CaseInput"
}

$LogFolder = "$env:USERPROFILE\Downloads\$SessionFolder"
if (!(Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force }

$exit_redblade = $false
$ExecutedFunctions = @()

# ========== Logging ==========
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogLine = "$Timestamp [$Level] - $Message"
    Add-Content -Path "$LogFolder\RedBlade_Log.txt" -Value $LogLine
    Write-Host $LogLine -ForegroundColor Green
}

# ========== Functions ==========
function Get-NetworkMessageID {
    param ($Headers)
    if ($Headers -match "(?i)(Message-ID|network-message-id):\\s*<?([^>\\s]+)>?") {
        return $matches[2]
    }
    return $null
}

function Get-URLsFromBody {
    param ($Body)
    if (-not $Body) { return $null }
    [regex]::Matches($Body, "https?://[^\\s<>]+") | ForEach-Object { $_.Value } | Sort-Object -Unique
}

function Save-TXTResult {
    param ($Output, $FilePath)
    try {
        $Output | Out-File -FilePath $FilePath -Force
        Write-Log "Saved output to $FilePath"
    }
    catch {
        Write-Log "Error saving file: $($_.Exception.Message)" "ERROR"
    }
}

function Expand-Zip {
    param (
        [string]$ZipPath,
        [string]$Destination
    )
    try {
        Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force
        Write-Log "Native extraction succeeded: $ZipPath"
    }
    catch {
        Write-Log "Native extraction failed for: $ZipPath"
        $password = Read-Host "Enter password for $($ZipPath)"
        $SevenZipPath = "C:\\Program Files\\7-Zip\\7z.exe"
        try {
            & "$SevenZipPath" x "`"$ZipPath`"" -p"$password" -o"`"$Destination`"" -y | Out-Null
            Write-Log "Extracted with password using 7-Zip: $ZipPath"
        }
        catch {
            Write-Log "7-Zip extraction failed for: $ZipPath" "ERROR"
            Write-Host "Extraction failed for $ZipPath" -ForegroundColor Red
        }
    }
}

function Expand-ADVfiles {
    param ($FolderPath)
    $Archives = Get-ChildItem -Path $FolderPath -Recurse -File -Include *.zip, *.tar.gz, *.rar
    foreach ($Archive in $Archives) {
        $Destination = Join-Path $Archive.DirectoryName ($Archive.BaseName + "_extracted")
        Expand-Zip -ZipPath $Archive.FullName -Destination $Destination
    }
}

function GetEmailHeaders {
    param ($FolderPath)
    $EmailFiles = Get-ChildItem $FolderPath -Recurse -File | Where-Object { $_.Extension -match "(\\.msg|\\.eml)$" }
    $Outlook = New-Object -ComObject Outlook.Application
    $HeadersOutputPath = "$FolderPath\\Extracted_Headers.txt"
    if (Test-Path $HeadersOutputPath) { Remove-Item $HeadersOutputPath }

    foreach ($EmailFile in $EmailFiles) {
        try {
            $Headers = $null
            if ($EmailFile.Extension -eq ".eml") {
                $Headers = Get-Content $EmailFile.FullName -Raw
            }
            elseif ($EmailFile.Extension -eq ".msg") {
                $MailItem = $Outlook.CreateItemFromTemplate($EmailFile.FullName)
                $PropertyAccessor = $MailItem.PropertyAccessor
                $Headers = $PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
            }
            if ($Headers) {
                Add-Content $HeadersOutputPath "`n===== $($EmailFile.Name) =====`n$Headers`n"
                Write-Log "Extracted headers from $($EmailFile.Name)"
            }
            else {
                Write-Log "No headers found in $($EmailFile.Name)" "WARN"
            }
        }
        catch {
            Write-Log "Error extracting headers from $($EmailFile.Name): $($_.Exception.Message)" "ERROR"
        }
    }
    Write-Log "Saved all headers to $HeadersOutputPath"
}

# ========== Menu Loop ==========
while (-not $exit_redblade) {
    Write-Host "`n=== RedBlade Central Menu | Version 1.2.2 ===" -ForegroundColor Red
    Write-Host "1. Scan Emails for NMIDs and URLs"
    Write-Host "2. Check DKIM for a Domain"
    Write-Host "3. Check DMARC & SPF Records"
    Write-Host "4. Run WHOIS Lookup"
    Write-Host "5. Unzip Advanced files (Fallback for TAR/RAR)"
    Write-Host "6. Check MX Records for Domain"
    Write-Host "7. Extract headers from emails"
    Write-Host "0. Exit"
    $selection = Read-Host "Choose an option (0-7)"

    switch ($selection) {
        '1' {
            $ExecutedFunctions += "Scan Emails"
            $FolderPath = Read-Host "Enter folder path containing emails"
    
            if (!(Test-Path $FolderPath)) {
                Write-Log "Directory does not exist: $FolderPath" "ERROR"
                break
            }

            # Get all .eml and .msg files (case-insensitive, includes hidden/system files)
            $EmailFiles = Get-ChildItem -Path $FolderPath -Recurse -File -Force | Where-Object {
                $_.Extension.ToLower() -in ".eml", ".msg"
            }

            Write-Host "Total email files found: $($EmailFiles.Count)" -ForegroundColor Cyan
            if ($EmailFiles.Count -eq 0) {
                Write-Log "No .eml or .msg files found in $FolderPath" "WARN"
                break
            }

            $URLsOutputPath = "$LogFolder\Extracted_URLs.txt"
            if (Test-Path $URLsOutputPath) { Remove-Item $URLsOutputPath }

            $Outlook = New-Object -ComObject Outlook.Application
            $Excel = New-Object -ComObject Excel.Application
            $Excel.Visible = $false
            $Workbook = $Excel.Workbooks.Add()
            $Worksheet = $Workbook.Worksheets.Item(1)
            $Worksheet.Cells.Item(1, 1) = "File Name"
            $Worksheet.Cells.Item(1, 2) = "Network Message ID"
            $Worksheet.Cells.Item(1, 3) = "Extracted URLs"

            $Row = 2
            $MissingMessageIDs = @()
            $MissingURLs = @()
            $FoundURLs = $false

            foreach ($EmailFile in $EmailFiles) {
                try {
                    $MessageID = $null
                    $URLs = $null

                    if ($EmailFile.Extension.ToLower() -eq ".eml") {
                        $Headers = Get-Content $EmailFile.FullName -Raw
                        $MessageID = Get-NetworkMessageID $Headers
                        $Body = $Headers
                        $URLs = Get-URLsFromBody $Body
                    }
                    elseif ($EmailFile.Extension.ToLower() -eq ".msg") {
                        $MailItem = $Outlook.CreateItemFromTemplate($EmailFile.FullName)
                        $PropertyAccessor = $MailItem.PropertyAccessor
                        $Headers = $PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
                        $MessageID = Get-NetworkMessageID $Headers
                        $Body = $MailItem.Body
                        $URLs = Get-URLsFromBody $Body
                    }

                    if (-not $MessageID) { $MissingMessageIDs += $EmailFile.Name }
                    if (-not $URLs -or $URLs.Count -eq 0) { $MissingURLs += $EmailFile.Name }
                    else {
                        $FoundURLs = $true
                        Add-Content $URLsOutputPath "$($EmailFile.Name): $($URLs -join ', ')"
                    }

                    $Worksheet.Cells.Item($Row, 1) = $EmailFile.Name
                    $Worksheet.Cells.Item($Row, 2) = $MessageID
                    $Worksheet.Cells.Item($Row, 3) = $URLs -join ", "
                    $Row++
                }
                catch {
                    Write-Log "Could not process $($EmailFile.Name): $($_.Exception.Message)" "ERROR"
                }
            }

            $OutputPath = "$LogFolder\Scanned_Email_NMIDs_URLs.xlsx"
            if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
            $Workbook.SaveAs($OutputPath)
            $Workbook.Close()
            $Excel.Quit()

            Write-Log "Saved Excel: $OutputPath"
            Write-Log "Saved URLs: $URLsOutputPath"
            if ($MissingMessageIDs.Count -gt 0) { Write-Log "Files missing NMIDs: $($MissingMessageIDs -join ', ')" }
            if ($MissingURLs.Count -gt 0) { Write-Log "Files missing URLs: $($MissingURLs -join ', ')" }

            Pause
        }
        '2' {
            $ExecutedFunctions += "Check DKIM"
            $Domain = Read-Host "Enter domain to check DKIM"
            $Selectors = @("selector1", "selector2")
            $Results = @()
            foreach ($Selector in $Selectors) {
                $QueryName = "$Selector._domainkey.$Domain"
                try {
                    $NativeResult = Resolve-DnsName -Name $QueryName -Type TXT -ErrorAction Stop
                    foreach ($Record in $NativeResult) {
                        $Results += "$QueryName `n$($Record.Strings -join "`n")`n"
                    }
                }
                catch {
                    Write-Log "Native DNS failed for $QueryName"
                    $URL = "https://dns.google/resolve?name=$QueryName&type=TXT"
                    try {
                        $Response = Invoke-RestMethod -Uri $URL -Method Get
                        if ($Response.Answer) {
                            foreach ($Answer in $Response.Answer) {
                                $Results += "$QueryName `n$($Answer.data)`n"
                            }
                        }
                    }
                    catch {
                        Write-Log "Google DNS failed for $QueryName"
                    }
                }
            }
            Save-TXTResult $Results "$LogFolder\DKIM_$Domain.txt"
            Pause
        }
        '3' {
            $ExecutedFunctions += "Check DMARC/SPF"
            $Domain = Read-Host "Enter domain for DMARC/SPF check"
            try {
                $DMARC = nslookup -type=txt "_dmarc.$Domain"
                $SPF = nslookup -type=txt "$Domain"
                $Output = @("DMARC Record:", $DMARC, "", "SPF Record:", $SPF)
                Save-TXTResult $Output "$LogFolder\DMARC_SPF_$Domain.txt"
            }
            catch {
                Write-Log "DMARC/SPF lookup failed"
            }
            Pause
        }
        '4' {
            $ExecutedFunctions += "WHOIS Lookup"
            $Domain = Read-Host "Enter domain for WHOIS lookup"
            try {
                $WHOIS = Invoke-RestMethod -Uri "https://rdap.org/domain/$Domain"
                $Summary = @"
Domain: $($WHOIS.ldhName)
Status: $($WHOIS.status -join ', ')
Registrar: $($WHOIS.entities[0].vcardArray[1][1][3])
"@
                Save-TXTResult $Summary "$LogFolder\WHOIS_$Domain.txt"
            }
            catch {
                Write-Log "WHOIS lookup failed"
            }
            Pause
        }
        '5' {
            $ExecutedFunctions += "Advanced Extraction"
            $FolderPath = Read-Host "Enter folder path"
            Expand-ADVfiles -FolderPath $FolderPath
        }
        '6' {
            $ExecutedFunctions += "Check MX Records"
            $Domain = Read-Host "Enter domain to check MX records"
            try {
                $MXRecords = Resolve-DnsName -Name $Domain -Type MX
                $Output = $MXRecords | ForEach-Object { "Preference: $($_.Preference), Exchange: $($_.NameExchange)" }
                Save-TXTResult $Output "$LogFolder\MX_$Domain.txt"
            }
            catch {
                Write-Log "MX record lookup failed"
            }
            Pause
        }
        '7' {
            $ExecutedFunctions += "Extract headers from emails"
            $FolderPath = Read-Host "Enter folder path containing .eml or .msg files"
    
            if (!(Test-Path $FolderPath)) {
                Write-Log "Directory does not exist: $FolderPath" "ERROR"
                break
            }

            $EmailFiles = Get-ChildItem $FolderPath -Recurse -File -Force | Where-Object {
                $_.Extension.ToLower() -in ".eml", ".msg"
            }

            if ($EmailFiles.Count -eq 0) {
                Write-Log "No .eml or .msg files found in $FolderPath" "WARN"
                break
            }

            $Outlook = New-Object -ComObject Outlook.Application
            $HeadersOutputPath = "$LogFolder\Extracted_Headers.txt"

            if (Test-Path $HeadersOutputPath) { Remove-Item $HeadersOutputPath -Force }

            foreach ($EmailFile in $EmailFiles) {
                try {
                    $Headers = $null
                    if ($EmailFile.Extension.ToLower() -eq ".eml") {
                        $Headers = Get-Content $EmailFile.FullName -Raw
                    }
                    elseif ($EmailFile.Extension.ToLower() -eq ".msg") {
                        $MailItem = $Outlook.CreateItemFromTemplate($EmailFile.FullName)
                        $PropertyAccessor = $MailItem.PropertyAccessor
                        $Headers = $PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
                    }

                    if ($Headers) {
                        Add-Content $HeadersOutputPath "`n===== $($EmailFile.Name) =====`n$Headers`n"
                        Write-Log "Extracted headers from $($EmailFile.Name)"
                    }
                    else {
                        Write-Log "No headers found in $($EmailFile.Name)" "WARN"
                    }
                }
                catch {
                    Write-Log "Error extracting headers from $($EmailFile.Name): $($_.Exception.Message)" "ERROR"
                }
            }

            if (Test-Path $HeadersOutputPath) {
                Write-Log "Saved all headers to $HeadersOutputPath"
                Write-Host "Headers saved to: $HeadersOutputPath" -ForegroundColor Green
            }
            else {
                Write-Log "Header extraction completed, but no output file was created" "ERROR"
                Write-Host "No headers were extracted or saved." -ForegroundColor Yellow
            }

            Pause
        }
        '0' {
            $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $SummaryPath = "$LogFolder\RedBlade_Summary_$Timestamp.txt"

            $SummaryContent = @()
            $SummaryContent += "`n==== RedBlade Session Summary ===="
            $SummaryContent += "Timestamp: $(Get-Date)"
            $SummaryContent += "Executed Functions: $($ExecutedFunctions -join ', ')"
            $SummaryContent += ""

            # Include contents from known output files — skip extraction logs unless needed
            $PossibleFiles = @(
                "$LogFolder\DKIM_*.txt",
                "$LogFolder\DMARC_SPF_*.txt",
                "$LogFolder\WHOIS_*.txt",
                "$LogFolder\MX_*.txt"
            )

            foreach ($pattern in $PossibleFiles) {
                $Files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
                foreach ($File in $Files) {
                    $SummaryContent += "`n--- Contents of $($File.Name) ---"
                    try {
                        $FileContent = Get-Content $File.FullName -ErrorAction Stop
                        $SummaryContent += $FileContent
                    }
                    catch {
                        $SummaryContent += "[Error reading $($File.Name): $($_.Exception.Message)]"
                    }
                }
            }

            # Save and display summary
            $SummaryContent | Out-File -FilePath $SummaryPath -Force
            Write-Log "Saved session summary to $SummaryPath"
            Write-Host "`n===== SESSION SUMMARY =====" -ForegroundColor Red
            $SummaryContent | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }

            Write-Host "`nExiting RedBlade..." -ForegroundColor Red
            $exit_redblade = $true
        }
    }
}
