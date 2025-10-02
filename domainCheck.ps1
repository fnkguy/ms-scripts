# inform target domain
$domain= Read-Host "domain"

## MX
Write-Host "MX" -BackgroundColor Yellow -ForegroundColor Black
# query domain's dns host for mx record
Resolve-DnsName -Name $domain -type mx | Format-Table

## SPF
write-host "SPF" -BackgroundColor Yellow -ForegroundColor Black
# query domain's dns host for all txt records and filter for spf records
Resolve-DnsName -Name $domain -type txt | where-Object {$_.Strings -match "spf"} | Format-Table

## DMARC
Write-Host "DMARC" -BackgroundColor Yellow -ForegroundColor Black 
# query domain's dns host for dmarc record
Resolve-DnsName -Name _dmarc.$domain -type txt | Format-Table

## DKIM
Write-host "DKIM" -BackgroundColor Yellow -ForegroundColor Black
# if domain is using 'spf.protection.outlook.com' in SPF, it is likely that they are using microsoft's DKIM signatures as well
if ((Resolve-DnsName -Name $domain -type txt | where-Object {$_.Strings -match "spf"}).Strings -match "spf.protection.outlook.com") {
    # query domain's dns host for a microsoft dkim record
    Resolve-DnsName -Name "selector1._domainkey.$domain" -Type txt
} else {
    Write-Host "Microsoft DKIM signature (selector1) not found."
    # if dkim is not signed by Microsoft, inform selector used in the dkim-signature header.
    try {
        $selector= Read-Host "provide a different selector"
        # query domain's dns host for a non-microsoft dkim record
        Resolve-DnsName -Name "$selector._domainkey.$domain" -Type txt -ErrorAction SilentlyContinue
    }
    finally {
        # if no microsoft or non-microsoft dkim record is found
        Write-Host "DKIM record not found." -ForegroundColor black -BackgroundColor red
    }
}
