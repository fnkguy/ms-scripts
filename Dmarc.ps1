# inform target domain
$domain= Read-Host "domain"
# query domain's dns host for dmarc record
Resolve-DnsName -Name _dmarc.$domain -type txt