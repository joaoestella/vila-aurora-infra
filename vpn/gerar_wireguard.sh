#!/usr/bin/env bash
# Gera a malha WireGuard da Rede Vila Aurora (RT-06) com segmentação (RT-07).
# Chaves ficam em vpn/out/ (fora do Git). Os .conf de exemplo, sem chave, ficam em vpn/exemplos/.
#
# Plano de endereços (segmentos distintos, menor privilégio entre eles):
#   10.13.0.0/24  gateway/serviços de nuvem (hub)
#   10.13.1.0/24  nós de borda (um /32 por espaço)        -> falam só com a nuvem (10.13.0.10)
#   10.13.9.0/24  operadores/admin (acesso administrativo) -> falam só com serviços admin, via MFA
# Dispositivos IoT NÃO entram na VPN: ficam na LAN de cada espaço, atrás do nó de borda (segmentação física).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$HERE/out"; EX="$HERE/exemplos"
mkdir -p "$OUT" "$EX"; umask 077
WG=/tmp/root/usr/bin/wg; command -v wg >/dev/null 2>&1 && WG=wg
key(){ "$WG" genkey; }; pub(){ echo "$1" | "$WG" pubkey; }
declare -A PRIV PUB IP
gen(){ PRIV[$1]=$(key); PUB[$1]=$(pub "${PRIV[$1]}"); IP[$1]=$2; }
gen hub 10.13.0.10
for e in centro escola ubs horta abrigo; do gen "edge-$e" "10.13.1.$((RANDOM%200+10))"; done
for o in ana.coord rui.coord bruno.tec; do gen "op-$o" "10.13.9.$((RANDOM%200+10))"; done
ENDPOINT="${VPN_ENDPOINT:-vpn.vilaaurora.example:51820}"
# ---- servidor (hub) ----
{
echo "[Interface]"; echo "# gateway de nuvem (hub) - segmenta borda (10.13.1.0/24) e admin (10.13.9.0/24)"
echo "Address = 10.13.0.10/24"; echo "ListenPort = 51820"; echo "PrivateKey = ${PRIV[hub]}"
echo "# menor privilégio entre segmentos aplicado por nftables (ver vpn/nftables.conf)"
for e in centro escola ubs horta abrigo; do
  echo; echo "[Peer]"; echo "# nó de borda $e - só alcança os serviços de nuvem"
  echo "PublicKey = ${PUB[edge-$e]}"; echo "AllowedIPs = ${IP[edge-$e]}/32"
done
for o in ana.coord rui.coord bruno.tec; do
  echo; echo "[Peer]"; echo "# operador $o - acesso administrativo (habilitado por tempo via vpngate + MFA)"
  echo "PublicKey = ${PUB[op-$o]}"; echo "AllowedIPs = ${IP[op-$o]}/32"
done
} > "$OUT/wg-hub.conf"
# ---- peers de borda ----
for e in centro escola ubs horta abrigo; do
{
echo "[Interface]"; echo "Address = ${IP[edge-$e]}/32"; echo "PrivateKey = ${PRIV[edge-$e]}"
echo "[Peer]"; echo "# só o hub; a borda não fala com outras bordas nem com operadores"
echo "PublicKey = ${PUB[hub]}"; echo "Endpoint = $ENDPOINT"
echo "AllowedIPs = 10.13.0.10/32"; echo "PersistentKeepalive = 25"
} > "$OUT/wg-edge-$e.conf"
done
# ---- peers de operador ----
for o in ana.coord rui.coord bruno.tec; do
{
echo "[Interface]"; echo "Address = ${IP[op-$o]}/32"; echo "PrivateKey = ${PRIV[op-$o]}"
echo "[Peer]"; echo "PublicKey = ${PUB[hub]}"; echo "Endpoint = $ENDPOINT"
echo "# operador alcança só os serviços administrativos (painel/aprovação), nunca a rede IoT"
echo "AllowedIPs = 10.13.0.10/32"; echo "PersistentKeepalive = 25"
} > "$OUT/wg-op-$o.conf"
done
# versão de exemplo (sem chaves) para o Git
sed 's/^PrivateKey = .*/PrivateKey = <GERADA_LOCALMENTE_NAO_VERSIONAR>/' "$OUT/wg-hub.conf" > "$EX/wg-hub.conf.exemplo"
sed 's/^PrivateKey = .*/PrivateKey = <GERADA_LOCALMENTE>/' "$OUT/wg-edge-ubs.conf" > "$EX/wg-edge-ubs.conf.exemplo"
echo "WireGuard gerado em $OUT (chaves reais, fora do Git). Exemplos em $EX."
"$WG" --version 2>/dev/null | head -1 || true
