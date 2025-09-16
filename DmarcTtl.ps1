# inform target domain
$domain= Read-Host "domain"
# query domain's dns host for dmarc record
Resolve-DnsName -type txt _dmarc.$domain