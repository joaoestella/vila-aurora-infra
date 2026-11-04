#!/usr/bin/env bash
# Laboratório da Rede Vila Aurora SEM Docker (WSL/Ubuntu). Sobe tudo como processos normais.
# Uso: bash scripts/lab.sh up | down | status | incidente | sqli | caos [minutos] | alertas | cenario-frio
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB_HOME:-$HOME/.vila-lab}"            # fora do /mnt (NTFS não aceita permissões do Postgres)
PGBIN="${PGBIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | tail -1)}"
MOSQ="${MOSQ:-$(command -v mosquitto || echo /usr/sbin/mosquitto)}"
MPUB="${MPUB:-$(command -v mosquitto_pub || echo /usr/bin/mosquitto_pub)}"
PY="${PY:-python3}"
PGPORT=15432; PGSOCK="$LAB/pgsock"; export PGPASSWORD=lab-admin
LOGD="$LAB/log"; PIDD="$LAB/pids"; CERTS="$REPO/certs"; CC="$CERTS/cloud"; S=ubs
psqlA(){ "$PGBIN/psql" -h 127.0.0.1 -p $PGPORT -U postgres "$@"; }
need(){ [ -d "$CERTS/$S/edge" ] && [ -f "$REPO/keys/cmd-signer.key" ] || { echo "Rode antes: make pki"; exit 1; }; }
start(){ local n=$1; shift; ( "$@" >"$LOGD/$n.out" 2>&1 & echo $! >"$PIDD/$n.pid" ); }

up() {
  need; mkdir -p "$LAB" "$LOGD" "$PIDD" "$PGSOCK" "$LAB/run/$S/data/mosquitto" "$LAB/data" "$LAB/scenario"
  [ -n "${PGBIN:-}" ] || { echo "Postgres não encontrado (sudo apt install postgresql)"; exit 1; }
  if [ ! -d "$LAB/pgdata" ]; then
    echo "[1/5] criando o banco..."
    "$PGBIN/initdb" -D "$LAB/pgdata" -U postgres --auth=trust >"$LAB/initdb.log" 2>&1 || { tail "$LAB/initdb.log"; exit 1; }
    cat >>"$LAB/pgdata/postgresql.conf" <<C
listen_addresses='127.0.0.1'
port=$PGPORT
unix_socket_directories='$PGSOCK'
password_encryption=scram-sha-256
log_connections=on
log_statement='all'
C
    sed -i 's/^host.*all.*all.*127.0.0.1\/32.*trust/host all all 127.0.0.1\/32 scram-sha-256/' "$LAB/pgdata/pg_hba.conf"
    NEW=1
  fi
  "$PGBIN/pg_ctl" -D "$LAB/pgdata" -l "$LAB/pg.out" -w start >/dev/null 2>&1 || true
  if [ "${NEW:-}" = 1 ]; then
    "$PGBIN/psql" -h "$PGSOCK" -p $PGPORT -U postgres -q <<SQL
ALTER ROLE postgres PASSWORD 'lab-admin';
CREATE ROLE ingest_app LOGIN PASSWORD 'lab-ingest'; CREATE ROLE panel_app LOGIN PASSWORD 'lab-panel';
CREATE ROLE approval_app LOGIN PASSWORD 'lab-approval'; CREATE ROLE auditor_ro LOGIN PASSWORD 'lab-auditor';
CREATE ROLE painel_legado LOGIN PASSWORD 'lab-legado' SUPERUSER;
CREATE DATABASE vila; CREATE DATABASE vila_legado OWNER painel_legado;
SQL
    for f in "$REPO"/cloud/db/0*.sql "$REPO"/cloud/db/1*.sql; do [ -f "$f" ] && psqlA -q -v ON_ERROR_STOP=1 -f "$f" >/dev/null; done
    ADMIN_DSN_VILA="host=127.0.0.1 port=$PGPORT dbname=vila user=postgres password=lab-admin" \
    ADMIN_DSN_LEGADO="host=127.0.0.1 port=$PGPORT dbname=vila_legado user=postgres password=lab-admin" \
    SECRETS_OUT="$REPO/secrets/operadores-lab.txt" $PY "$REPO/cloud/db/seed.py"
  fi
  echo "[2/5] broker MQTT e serviços de nuvem..."
  sed -e "s#__NODE__#edge-$S#g;s#__ACL__#$LAB/run/$S/acl#;s#__DATA__#$LAB/run/$S/data#g;s#__BIND__#127.0.0.1#;s#__CERTS__#$CERTS/$S/edge#g;s#__LOGDIR__#$LOGD#;s#__SPACE__#$S#" \
      "$REPO/edge/mosquitto.conf.tmpl" | sed 's/^listener 8883/listener 18883/' >"$LAB/run/$S/mosquitto.conf"
  export LOG_DIR="$LOGD" LOG_STDOUT=0 PYTHONUNBUFFERED=1
  EDGEENV=(SPACE=$S CERT_DIR="$CERTS/$S/edge" BROKER_PORT=18883 CLOUD_URL=https://127.0.0.1:18443 DATA_DIR="$LAB/run/$S/data"
           POLICY_FILE="$REPO/edge/policies/$S.json" CMD_PUBKEY="$REPO/keys/cmd-signer.pub" ACL_PATH="$LAB/run/$S/acl"
           CRL_PATH="$CERTS/$S/edge/issuing.crl" PSEUDO_KEY_FILE="$REPO/secrets/pseudo.key" LOCAL_PORT=18080 METRICS_S=6 SEND_EVERY_S=2 CRL_SYNC_S=15)
  env "${EDGEENV[@]}" $PY "$REPO/edge/edge_agent.py" --write-acl
  start mosq "$MOSQ" -c "$LAB/run/$S/mosquitto.conf"
  start approval env DB_DSN="host=127.0.0.1 port=$PGPORT dbname=vila user=approval_app password=lab-approval" CERT_DIR="$CC" CMD_PRIVKEY="$REPO/keys/cmd-signer.key" POLICY_DIR="$REPO/edge/policies" PORT=18444 BIND=127.0.0.1 $PY "$REPO/soar/approval.py"
  start pkiapi env CERT_DIR="$CC" CA_SH="$REPO/pki/ca.sh" PKI_OUT="$REPO/certs-src" PORT=18446 BIND=127.0.0.1 $PY "$REPO/cloud/pkiapi/app.py"
  start vpngate env CERT_DIR="$CC" VPN_SESS="$LAB/data/vpn_sessions.json" PORT=18445 BIND=127.0.0.1 $PY "$REPO/vpn/vpngate.py"
  start soar env DB_DSN="host=127.0.0.1 port=$PGPORT dbname=vila user=approval_app password=lab-approval" CERT_DIR="$CC" APPROVAL_URL=https://127.0.0.1:18444 PKIAPI_URL=https://127.0.0.1:18446 VPNGATE_URL=https://127.0.0.1:18445 FIREWALL_FILE="$LAB/data/blocklist.txt" PORT=18447 BIND=127.0.0.1 $PY "$REPO/soar/responder.py"
  start ingest env DB_DSN="host=127.0.0.1 port=$PGPORT dbname=vila user=ingest_app password=lab-ingest" CERT_DIR="$CC" CRL_PATH="$CC/issuing.crl" PORT=18443 BIND=127.0.0.1 $PY "$REPO/cloud/ingest/app.py"
  start panel env DB_DSN="host=127.0.0.1 port=$PGPORT dbname=vila user=panel_app password=lab-panel" CERT_DIR="$CC" APPROVAL_URL=https://127.0.0.1:18444 VPNGATE_URL=https://127.0.0.1:18445 COOKIE_SECURE=0 PORT=18000 BIND=127.0.0.1 SESSION_KEY=labkey $PY "$REPO/cloud/panel/app.py"
  start legado env DB_DSN="host=127.0.0.1 port=$PGPORT dbname=vila_legado user=painel_legado password=lab-legado" PORT=18081 BIND=127.0.0.1 $PY "$REPO/cloud/panel_legado/app.py"
  start siem env LOG_DIR="$LOGD" SOAR_URL=https://127.0.0.1:18447 CA="$CC/ca-chain.crt" SIEM_CERT="$CC/svc-soar.crt" SIEM_KEY="$CC/svc-soar.key" SIEM_STATE="$LAB/data/siem_state.json" $PY "$REPO/siem/detector.py"
  sleep 2
  echo "[3/5] nó de borda e dispositivos do UBS..."
  start edge env "${EDGEENV[@]}" $PY "$REPO/edge/edge_agent.py"
  sleep 1
  start sim env SPACE=$S CERT_DIR="$CERTS/$S/devices" BROKER_HOST=127.0.0.1 BROKER_PORT=18883 TELEMETRY_S=2 POLICY_FILE="$REPO/edge/policies/$S.json" DATA_DIR="$LAB/run/$S/simdata" SCENARIO_DIR="$LAB/scenario" $PY "$REPO/devices/sim_device.py"
  sleep 6; status
  cat <<M

Pronto. Abra no navegador do Windows:
  Painel de supervisão (corrigido):  http://localhost:18000   (login em secrets/operadores-lab.txt, com senha + código TOTP)
  Página local da borda (UBS):       http://localhost:18080   (funciona mesmo sem a nuvem)
  Painel LEGADO (vulnerável):        http://localhost:18081   (usuário coord.voluntarios / Primavera2026)
Comandos:  bash scripts/lab.sh incidente | sqli | caos 1 | cenario-frio | alertas | down
M
}
down() {
  for f in "$PIDD"/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; done
  pkill -f "$LAB/run/$S/mosquitto.conf" 2>/dev/null
  "$PGBIN/pg_ctl" -D "$LAB/pgdata" stop -m fast >/dev/null 2>&1; echo "tudo parado."
}
status() {
  echo "== serviços =="
  for n in mosq approval pkiapi vpngate soar ingest panel legado siem edge sim; do
    if [ -f "$PIDD/$n.pid" ] && kill -0 "$(cat "$PIDD/$n.pid")" 2>/dev/null; then printf "  %-9s no ar\n" $n; else printf "  %-9s PARADO (veja %s/%s.out)\n" $n "$LOGD" $n; fi
  done
  n=$(psqlA -d vila -tAc "select count(*) from telemetria" 2>/dev/null || echo "?"); echo "== leituras gravadas na nuvem: $n =="
}
cenario-frio(){ echo '{"cold_excursion":{"until":9999999999,"peak":12}}' >"$LAB/scenario/$S.json"; echo "excursão de temperatura ligada: veja a sirene em http://localhost:18080 ('bash scripts/lab.sh alertas'); para desligar: bash scripts/lab.sh cenario-frio-off"; }
cenario-frio-off(){ echo '{}' >"$LAB/scenario/$S.json"; echo desligado; }
alertas() {
  echo "== alertas do SIEM =="; grep -h '"event": "alert"' "$LOGD/alerts.log" 2>/dev/null | $PY -c "import sys,json
for l in sys.stdin:
  a=json.loads(l); print(f\"  {a['rule']}/{a['sev']:6} {a['title']} [{a['attack']}]\")"
  echo "== respostas do SOAR =="; grep -h soar_playbook_done "$LOGD/soar.log" 2>/dev/null | $PY -c "import sys,json
for l in sys.stdin:
  a=json.loads(l); print('  ',a['rule'],a['actions'])"
  echo "== IPs bloqueados =="; cat "$LAB/data/blocklist.txt" 2>/dev/null | sed 's/^/  /'
  echo "== alarmes locais da borda =="; grep -h '"local_alarm"' "$LOGD/edge-$S.log" 2>/dev/null | tail -2 | cut -c1-200
}
incidente() {
  echo "== R3: dispositivo com certificado falso tenta entrar no broker =="
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$LAB/fake.key" -out "$LAB/fake.crt" -subj /CN=ubs-tmp-01 -days 1 2>/dev/null
  "$MPUB" -h 127.0.0.1 -p 18883 --cafile "$CC/ca-chain.crt" --cert "$LAB/fake.crt" --key "$LAB/fake.key" -t va/ubs-tmp-01/telemetry -m x 2>&1 | tail -1
  echo "== R1: força bruta na VPN =="
  for i in 1 2 3 4 5; do $PY - <<PY
import ssl,json,urllib.request
c=ssl.create_default_context(cafile="$CC/ca-chain.crt");c.load_cert_chain("$CC/svc-panel.crt","$CC/svc-panel.key")
urllib.request.urlopen(urllib.request.Request("https://127.0.0.1:18445/auth",data=json.dumps({"ok":False,"user":"coord.voluntarios","ip":"203.0.113.66","mfa":False}).encode(),headers={"Content-Type":"application/json"}),context=c,timeout=5).read()
PY
  done
  echo "== reproduzindo o INC-VA-0712 =="
  mkdir -p "$LAB/evid"
  LEGADO_URL=http://127.0.0.1:18081 PANEL_URL=http://127.0.0.1:18000 OPS="$REPO/secrets/operadores-lab.txt" EVID_OUT="$LAB/evid" LOG_DIR="$LOGD" \
  LEGACY_DSN="host=127.0.0.1 port=$PGPORT dbname=vila_legado user=painel_legado password=lab-legado" $PY "$REPO/forense/reproduzir_incidente.py"
  echo "== comando forjado direto no banco (o que a SQLi faria) =="
  psqlA -d vila -q -c "INSERT INTO comandos (cmd_id,espaco,dispositivo,acao,impacto,pedido_por,assinado,status) VALUES (gen_random_uuid(),'ubs','ubs-ace-01','unlock_all','high','atacante-sqli','{\"space\":\"ubs\",\"device\":\"ubs-ace-01\",\"action\":\"unlock_all\",\"impact\":\"high\",\"sig\":\"ZmFrZQ==\"}','pendente');"
  sleep 7; grep -h cloud_command_rejected "$LOGD/edge-$S.log" | tail -1 | $PY -c "import sys,json;a=json.loads(sys.stdin.read() or '{}');print('  borda recusou:',a.get('device'),a.get('action'),'motivo =',a.get('reason'))"
  sleep 3; alertas; echo; echo "Evidências com hash em: $LAB/evid  (cadeia_de_custodia.json)"
}
sqli() {
  curl -s -o /dev/null -c "$LAB/lc.txt" --data-urlencode usuario=coord.voluntarios --data-urlencode senha=Primavera2026 http://127.0.0.1:18081/login
  req(){ curl -s -b "$LAB/lc.txt" -G http://127.0.0.1:18081/historico --data-urlencode "busca=$1"; }
  echo "## LEGADO (vulnerável)"
  echo -n "busca normal 'Aurora' -> linhas: "; req "Aurora" | grep -o "<tr>" | wc -l
  echo -n "payload OR 1=1        -> linhas: "; req "zzz%' OR '1'='1' -- " | grep -o "<tr>" | wc -l
  echo -n "UNION versão/usuário  -> "; req "zzz%' UNION SELECT NULL,version(),current_user,NULL,NULL,NULL -- " | grep -oE "PostgreSQL [0-9.]+|painel_legado" | head -2 | tr '\n' ' '; echo
  echo -n "erro vaza detalhe?    -> "; req "x'" | grep -oE "Erro no banco" | head -1
  echo "## CORRIGIDO (mesmos payloads)"
  $PY - <<PY
import re,requests,pyotp
for l in open("$REPO/secrets/operadores-lab.txt"):
    p=l.strip().split(";")
    if p[0]=="davi.aud": s2,t2=p[2],p[3]
s=requests.Session(); b="http://127.0.0.1:18000"
c=lambda r:re.search(r'name="csrf" value="([^"]+)"',r.text).group(1)
r=s.get(b+"/login"); r=s.post(b+"/login",data={"csrf":c(r),"login":"davi.aud","senha":s2})
r=s.post(b+"/mfa",data={"csrf":c(r),"codigo":pyotp.TOTP(t2).now()})
for pl in ["Aurora","zzz%' OR '1'='1' -- ","zzz%' UNION SELECT NULL,version(),current_user,NULL,NULL,NULL -- ","x'"]:
    rr=s.get(b+"/acessos",params={"q":pl}); m=re.search(r"Pedido inválido|\d+ resultado",rr.text)
    print(f"  payload [{pl[:34]}] -> HTTP {rr.status_code} {m.group(0) if m else ''}")
PY
}
caos() {
  local m="${1:-30}"; echo "teste de caos: link derrubado por $m min (a borda continua; veja http://localhost:18080)"
  CHAOS_MIN="$m" EDGE_URL=http://127.0.0.1:18080 CHAOS_OUT="$LAB/evid/caos.json" \
  CHAOS_DOWN_CMD="kill -STOP $(cat "$PIDD/ingest.pid")" CHAOS_UP_CMD="kill -CONT $(cat "$PIDD/ingest.pid")" \
  PSQL_CMD="$PGBIN/psql -h 127.0.0.1 -p $PGPORT -U postgres -d vila" $PY "$REPO/caos/chaos_test.py"
}
case "${1:-}" in up) up;; down) down;; status) status;; incidente) incidente;; sqli) sqli;; caos) shift; caos "${1:-30}";; alertas) alertas;; cenario-frio) cenario-frio;; cenario-frio-off) cenario-frio-off;;
  *) sed -n '2,3p' "$0";; esac
