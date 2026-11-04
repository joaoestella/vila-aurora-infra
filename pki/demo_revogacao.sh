#!/usr/bin/env bash
# Demonstração de revogação (RT-05): emite um certificado de teste, valida, revoga e mostra que a CRL o barra.
# Não mexe nos dispositivos do lab: usa um certificado temporário (demo-sensor-99).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"
export PKI_OUT="${PKI_OUT:-$ROOT/certs-src}"
N=demo-sensor-99
echo "== 1. emitir certificado X.509 do dispositivo $N =="
bash "$HERE/ca.sh" issue $N device >/dev/null
openssl x509 -in "$PKI_OUT/certs/$N/$N.crt" -noout -subject -serial -dates
echo; echo "== 2. validar contra a CA e a CRL (esperado: OK) =="
bash "$HERE/ca.sh" verify $N
echo; echo "== 3. dispositivo roubado: revogar (motivo keyCompromise) =="
bash "$HERE/ca.sh" revoke $N keyCompromise
echo; echo "== 4. validar de novo contra a CRL nova (esperado: recusado) =="
openssl verify -crl_check -CAfile <(cat "$PKI_OUT/certs/ca-chain.crt" "$PKI_OUT/certs/issuing.crl") "$PKI_OUT/certs/$N/$N.revoked-"*.crt 2>&1 | tail -3 || true
echo; echo "== 5. registro de auditoria da PKI =="
tail -3 "$PKI_OUT/pki-audit.log"
