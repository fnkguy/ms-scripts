# inform target domain
$domain= Read-Host "domain"
# query domain's dns host for mx record
Resolve-DnsName -Name $domain -type mx 