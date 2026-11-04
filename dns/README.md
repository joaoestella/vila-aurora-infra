# Zona DNS do domínio fictício
Os registros SPF/DKIM/DMARC são gerados por `phishing/gerar_dkim.sh` em `phishing/dns_records.txt`
(a chave privada DKIM vai para `dns/keys/`, fora do Git). Rode `make pki` para gerar os seus.
