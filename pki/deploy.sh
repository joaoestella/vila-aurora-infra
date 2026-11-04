#!/usr/bin/env bash
# Distribui os certificados: cada nó recebe só o próprio par (chave + certificado), a cadeia e a CRL.
# Uso: bash pki/deploy.sh <destino>   (cria <destino>/<espaco>/edge e <destino>/<espaco>/devices, <destino>/cloud)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="${PKI_OUT:-$HERE/out}"; DEST="$1"
cp1() { mkdir -p "$2"; cp "$OUT/certs/$1/$1.crt" "$OUT/certs/$1/$1.key" "$2/"; cp "$OUT/certs/ca-chain.crt" "$OUT/certs/issuing.crl" "$2/"; }
tail -n +2 "$HERE/inventory.csv" | while IFS=, read -r nome tipo espaco desc sans; do
  [ -z "$nome" ] && continue
  case "$tipo" in
    edge) cp1 "$nome" "$DEST/$espaco/edge" ;;
    device) cp1 "$nome" "$DEST/$espaco/devices" ;;
    server|service) cp1 "$nome" "$DEST/cloud" ;;
  esac
done
cp "$OUT/certs/ca-chain.crt" "$OUT/certs/issuing.crl" "$DEST/cloud/"
chmod -R go-rwx "$DEST" 2>/dev/null || true
echo "certificados distribuídos em $DEST"
