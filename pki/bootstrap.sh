#!/usr/bin/env bash
# Cria a CA e emite um certificado único para cada item do inventário.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
bash "$HERE/ca.sh" init
tail -n +2 "$HERE/inventory.csv" | while IFS=, read -r nome tipo espaco desc sans; do
  [ -z "$nome" ] && continue
  sans="${sans//;/,}"
  if [ -f "${PKI_OUT:-$HERE/out}/certs/$nome/$nome.crt" ]; then echo "já existe: $nome"; continue; fi
  bash "$HERE/ca.sh" issue "$nome" "$tipo" "$sans"
done
