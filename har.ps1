## Store .HAR file
$har = "C:\Users\fnepomuceno\Downloads\nologs.har"

## Convert from JSON
$CaseData = Get-Content $har | ConvertFrom-JSON
<##for ($i=0; $i -lt 16; $i++){
    try {
        (($casedata.log.entries)[$i]).request.postdata.text | ConvertFrom-Json
    }
    catch {
        $i++
    } 
}
##>
$entries=($CaseData.log.entries |? {$_.Request -like "*/api/auth/IsInRoles?cache=true*"})
$entries.count
$cases=($entries | % {($_.response.content.text|ConvertFrom-Json) }).CurrentPage

$cases # Return all loaded cases with details
$cases |Sort-Object lastModifiedDateTime -Descending |ft Name,createdDateTime,lastModifiedDateTime # Return summary table

$cases |? {[DateTime]$_.lastModifiedDateTime -ge ((Get-Date).AddDays(-60))} |Sort-Object lastModifiedDateTime -Descending |ft Name,createdDateTime,lastModifiedDateTime # filter only cases modified in last x days, sort and return table
#>