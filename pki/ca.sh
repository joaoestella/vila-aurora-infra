#!/usr/bin/env bash
# CA própria da Rede Vila Aurora (OpenSSL). Uso:
#   bash pki/ca.sh init                      cria raiz (P-384) e CA emissora (P-256)
#   bash pki/ca.sh issue <nome> <device|edge|server> [SANs]   emite certificado único
#   bash pki/ca.sh revoke <nome> [motivo]    revoga e publica nova CRL
#   bash pki/ca.sh rotate <nome> <tipo> [SANs]  emite par novo e revoga o antigo
#   bash pki/ca.sh crl | list | verify <nome>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PKI_OUT="${PKI_OUT:-$HERE/out}"
CNF="$HERE/openssl.cnf"
LOG="${PKI_LOG:-$PKI_OUT/pki-audit.log}"
umask 077
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
audit() { mkdir -p "$PKI_OUT"; printf '{"ts":"%s","src":"pki","event":"%s","name":"%s","detail":"%s"}\n' "$(ts)" "$1" "$2" "${3:-}" >> "$LOG"; }
prep() { mkdir -p "$PKI_OUT/$1/newcerts"; touch "$PKI_OUT/$1/index.txt"; [ -f "$PKI_OUT/$1/serial" ] || openssl rand -hex 8 > "$PKI_OUT/$1/serial"; [ -f "$PKI_OUT/$1/crlnumber" ] || echo 1000 > "$PKI_OUT/$1/crlnumber"; }

cmd_init() {
  if [ -f "$PKI_OUT/root/root.crt" ]; then echo "CA já existe em $PKI_OUT"; return 0; fi
  prep root; prep issuing; mkdir -p "$PKI_OUT/certs"
  openssl ecparam -name secp384r1 -genkey -noout -out "$PKI_OUT/root/root.key"
  openssl req -config "$CNF" -new -x509 -key "$PKI_OUT/root/root.key" -sha384 -days 3650 \
    -subj "/O=Rede Vila Aurora (LAB)/CN=Vila Aurora Root CA" -extensions v3_root -out "$PKI_OUT/root/root.crt"
  openssl ecparam -name prime256v1 -genkey -noout -out "$PKI_OUT/issuing/issuing.key"
  openssl req -config "$CNF" -new -key "$PKI_OUT/issuing/issuing.key" \
    -subj "/O=Rede Vila Aurora (LAB)/CN=Vila Aurora Issuing CA" -out "$PKI_OUT/issuing/issuing.csr"
  openssl ca -batch -config "$CNF" -name root -extensions v3_issuing -days 1095 \
    -in "$PKI_OUT/issuing/issuing.csr" -out "$PKI_OUT/issuing/issuing.crt" 2>/dev/null
  cat "$PKI_OUT/issuing/issuing.crt" "$PKI_OUT/root/root.crt" > "$PKI_OUT/certs/ca-chain.crt"
  cp "$PKI_OUT/root/root.crt" "$PKI_OUT/certs/root.crt"
  cmd_crl >/dev/null
  audit ca_init "Vila Aurora Issuing CA"
  echo "CA criada. Raiz: $PKI_OUT/root/root.crt (guardar a chave raiz offline)"
}

cmd_issue() {
  local name="$1" type="${2:-device}" sans="${3:-}"
  local d="$PKI_OUT/certs/$name"; mkdir -p "$d"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/$name.key"
  local ext="v3_$type" extfile; extfile="$(mktemp)"
  if [ -n "$sans" ]; then printf 'subjectAltName=%s\n' "$sans" > "$extfile"; else printf 'subjectAltName=DNS:%s\n' "$name" > "$extfile"; fi
  openssl req -config "$CNF" -new -key "$d/$name.key" -subj "/O=Rede Vila Aurora (LAB)/OU=$type/CN=$name" \
    -addext "$(cat "$extfile")" -out "$d/$name.csr"
  local days=365; [ "$type" = device ] && days="${DEVICE_DAYS:-90}"
  openssl ca -batch -config "$CNF" -extensions "$ext" -days "$days" -in "$d/$name.csr" -out "$d/$name.crt" 2>/dev/null
  rm -f "$extfile" "$d/$name.csr"
  cp "$PKI_OUT/certs/ca-chain.crt" "$d/ca-chain.crt"
  local serial fp; serial=$(openssl x509 -in "$d/$name.crt" -noout -serial | cut -d= -f2)
  fp=$(openssl x509 -in "$d/$name.crt" -noout -fingerprint -sha256 | cut -d= -f2)
  audit cert_issued "$name" "type=$type serial=$serial sha256=$fp days=$days"
  echo "$name serial=$serial"
}

cmd_crl() {
  openssl ca -config "$CNF" -gencrl -out "$PKI_OUT/certs/issuing.crl" 2>/dev/null
  openssl ca -config "$CNF" -name root -gencrl -out "$PKI_OUT/certs/root.crl" 2>/dev/null
  cat "$PKI_OUT/certs/issuing.crl" "$PKI_OUT/certs/root.crl" > "$PKI_OUT/certs/crl-chain.pem"
  echo "CRL publicada: $PKI_OUT/certs/issuing.crl"
}

cmd_revoke() {
  local name="$1" reason="${2:-keyCompromise}"
  openssl ca -config "$CNF" -revoke "$PKI_OUT/certs/$name/$name.crt" -crl_reason "$reason" 2>/dev/null
  local serial; serial=$(openssl x509 -in "$PKI_OUT/certs/$name/$name.crt" -noout -serial | cut -d= -f2)
  mv "$PKI_OUT/certs/$name/$name.crt" "$PKI_OUT/certs/$name/$name.revoked-$serial.crt"
  cmd_crl
  audit cert_revoked "$name" "serial=$serial reason=$reason"
  echo "$name revogado (serial $serial, motivo $reason)"
}

cmd_rotate() {
  local name="$1" type="${2:-device}" sans="${3:-}"
  local old="$PKI_OUT/certs/$name/$name.crt" oldserial=""
  if [ -f "$old" ]; then oldserial=$(openssl x509 -in "$old" -noout -serial | cut -d= -f2); cp "$old" "$PKI_OUT/certs/$name/$name.old.crt"; fi
  cmd_issue "$name" "$type" "$sans"
  if [ -n "$oldserial" ]; then
    openssl ca -config "$CNF" -revoke "$PKI_OUT/certs/$name/$name.old.crt" -crl_reason superseded 2>/dev/null
    rm -f "$PKI_OUT/certs/$name/$name.old.crt"; cmd_crl >/dev/null
    audit cert_rotated "$name" "old_serial=$oldserial"
    echo "rotação concluída: serial antigo $oldserial revogado como superseded"
  fi
}

cmd_list() { awk -F'\t' '{st=($1=="V")?"válido":($1=="R")?"REVOGADO":$1; print st"\t"$4"\t"$6}' "$PKI_OUT/issuing/index.txt"; }
cmd_verify() { openssl verify -crl_check -CAfile <(cat "$PKI_OUT/certs/ca-chain.crt" "$PKI_OUT/certs/issuing.crl") "$PKI_OUT/certs/$1/$1.crt"; }

c="${1:-}"; shift || true
case "$c" in
  init) cmd_init ;; issue) cmd_issue "$@" ;; revoke) cmd_revoke "$@" ;; rotate) cmd_rotate "$@" ;;
  crl) cmd_crl ;; list) cmd_list ;; verify) cmd_verify "$@" ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
