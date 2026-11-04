#!/usr/bin/env bash
# Gera a chave DKIM e os registros SPF/DKIM/DMARC do domínio fictício (RT-10).
# A chave privada vai para dns/keys/ (fora do Git). Os registros ficam em phishing/dns_records.txt.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"
DOM="${MAIL_DOMAIN:-vilaaurora.example}"; SEL="${DKIM_SELECTOR:-vila2026}"
KD="$ROOT/dns/keys"; mkdir -p "$KD"; umask 077
openssl genrsa -out "$KD/$SEL.private" 2048 2>/dev/null
PUB=$(openssl rsa -in "$KD/$SEL.private" -pubout 2>/dev/null | grep -v "^-----" | tr -d '\n')
cat > "$HERE/dns_records.txt" <<DNS
; Registros DNS do domínio $DOM (fictício, laboratório) - RT-10
; --- SPF: só o servidor de envio autorizado pode mandar e-mail; o resto falha (-all)
$DOM.                 IN TXT  "v=spf1 ip4:203.0.113.25 -all"
; --- DKIM: chave pública que valida a assinatura das mensagens
$SEL._domainkey.$DOM. IN TXT  "v=DKIM1; k=rsa; p=$PUB"
; --- DMARC: política quarentena, com relatórios agregados
_dmarc.$DOM.          IN TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOM; ruf=mailto:dmarc@$DOM; fo=1; adkim=s; aspf=s; pct=100"
DNS
echo "chave DKIM em $KD/$SEL.private (fora do Git); registros em $HERE/dns_records.txt"
