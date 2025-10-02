# inform target domain
$domain= Read-Host "domain"
# query domain's dns host for all txt records and filter for spf records
Resolve-DnsName -Name $domain -type txt | where-Object {$_.Strings -match "spf"}