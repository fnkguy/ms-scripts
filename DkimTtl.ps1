# inform selector used in the dkim-signature header
$selector= Read-Host "selector"
# inform target domain used in the dkim-signature header
$domain= Read-Host "domain"
# query domain's dns host for the dkim public key record
Resolve-DnsName -Type txt "$selector._domainkey.$domain"
