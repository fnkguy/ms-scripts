# inform target domain used in the dkim-signature header
$domain= Read-Host "domain"
# inform selector used in the dkim-signature header
$selector= Read-Host "selector"
# query domain's dns host for the dkim public key record
Resolve-DnsName -Name "$selector._domainkey.$domain" -Type txt 
