"""Agente do nó de borda da Rede Vila Aurora.

Funções (RT-01, RT-02, RT-03):
  * conecta no broker MQTT local com certificado próprio (mTLS);
  * aplica as regras locais sem depender da nuvem (câmara fria, intertravamento da bomba, alagamento);
  * guarda toda leitura num buffer SQLite (store-and-forward) e envia em lote para a nuvem por HTTPS mTLS;
  * reconcilia com a nuvem quando o link volta (pede a lista do que falta e reenvia);
  * só executa comando de atuador assinado pelo serviço de aprovação e dentro da política local;
  * expõe uma página local simples para quem está no espaço quando a internet cai.
"""
import json, os, signal, sqlite3, ssl, subprocess, sys, threading, time, hmac, hashlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request, urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
sys.path.insert(0, "/app/common")
from vlog import VLog, utcnow          # noqa: E402
import cmdsig                          # noqa: E402
import paho.mqtt.client as mqtt        # noqa: E402

E = os.environ.get
SPACE = E("SPACE", "ubs")
NODE = E("NODE_NAME", f"edge-{SPACE}")
CERT_DIR = E("CERT_DIR", "/pki")
BROKER = E("BROKER_HOST", "127.0.0.1")
BROKER_PORT = int(E("BROKER_PORT", "8883"))
CLOUD = E("CLOUD_URL", "https://ingest.vila.lab:8443")
DATA = E("DATA_DIR", "/data")
POLICY = E("POLICY_FILE", f"/app/policies/{SPACE}.json")
CMD_PUB = E("CMD_PUBKEY", "/keys/cmd-signer.pub")
CRL_PATH = E("CRL_PATH", f"{CERT_DIR}/issuing.crl")
ACL_PATH = E("ACL_PATH", "/mosquitto/acl")
PSEUDO_KEY = E("PSEUDO_KEY_FILE", "/secrets/pseudo.key")
LOCAL_PORT = int(E("LOCAL_PORT", "8080"))
SEND_EVERY = float(E("SEND_EVERY_S", "2"))
BATCH = int(E("BATCH", "200"))

log = VLog(f"edge-{SPACE}")
os.makedirs(DATA, exist_ok=True)

def hour_local():
    # horário de operação em America/Sao_Paulo (UTC-3, sem horário de verão)
    return (datetime.now(timezone.utc).hour - 3) % 24

def in_window(h, win):
    a, b = win
    return a <= h < b if a < b else (h >= a or h < b)

# ----------------------------------------------------------------- política local
def load_policy():
    pol = json.load(open(POLICY, encoding="utf-8"))
    sig = POLICY + ".sig"
    if E("POLICY_PUBKEY") and os.path.exists(E("POLICY_PUBKEY")):
        import base64
        pub = cmdsig.load_public(E("POLICY_PUBKEY"))
        try:
            pub.verify(base64.b64decode(open(sig).read()), open(POLICY, "rb").read())
            log("policy_loaded", signed=True, version=pol.get("version"))
        except Exception:
            log("policy_signature_invalid", sev="critical", file=POLICY)
            raise SystemExit("política sem assinatura válida")
    else:
        log("policy_loaded", signed=False, version=pol.get("version"))
    return pol

POL = load_policy()
DEVS = POL["devices"]

# ----------------------------------------------------------------- buffer SQLite
db = sqlite3.connect(os.path.join(DATA, "buffer.sqlite"), check_same_thread=False, isolation_level=None)
db.execute("PRAGMA journal_mode=WAL")
db.execute("""CREATE TABLE IF NOT EXISTS outbox(msg_id TEXT PRIMARY KEY, device TEXT, seq INTEGER, kind TEXT,
              ts TEXT, payload TEXT, created REAL, sent_at REAL)""")
db.execute("CREATE INDEX IF NOT EXISTS ix_unsent ON outbox(sent_at)")
db.execute("CREATE TABLE IF NOT EXISTS linklog(t REAL, state TEXT)")
dblock = threading.Lock()

def enqueue(kind, device, seq, ts, payload):
    mid = payload.get("msg_id") or f"{device}-{kind}-{seq}"
    payload["msg_id"] = mid
    with dblock:
        db.execute("INSERT OR IGNORE INTO outbox VALUES(?,?,?,?,?,?,?,NULL)",
                   (mid, device, seq, kind, ts, json.dumps(payload, ensure_ascii=False), time.time()))

_evseq = [int(time.time() * 1000)]
def local_event(name, sev="warning", **kw):
    """Evento gerado pela borda (alarme local, comando recusado...). Vai para o log e para a nuvem."""
    _evseq[0] += 1
    rec = log(name, sev=sev, space=SPACE, **kw)
    enqueue("event", NODE, _evseq[0], rec["ts"], {"kind": "event", "space": SPACE, "device": NODE, "event": name, "sev": sev, "data": kw, "ts": rec["ts"]})

# ----------------------------------------------------------------- estado local
STATE = {"devices": {}, "alarms": {}, "wan_up": None, "wan_down_since": None, "outages": [],
         "isolated": set(), "last_sent": None, "started": time.time()}
_cold = {"bad": 0}

# ----------------------------------------------------------------- MQTT
cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=NODE, clean_session=False)
cli.tls_set(ca_certs=f"{CERT_DIR}/ca-chain.crt", certfile=f"{CERT_DIR}/{NODE}.crt", keyfile=f"{CERT_DIR}/{NODE}.key",
            tls_version=ssl.PROTOCOL_TLS_CLIENT)

def actuate(device, action, params=None, origin="local", reason=""):
    msg = {"action": action, "params": params or {}, "origin": origin, "reason": reason, "ts": utcnow()}
    cli.publish(f"va/{device}/cmd", json.dumps(msg), qos=1)
    log("actuator_command", device=device, action=action, origin=origin, reason=reason, hour=hour_local(), space=SPACE)

def rule_cold_chain(dev, vals):
    r = POL.get("rules", {}).get("cold_chain")
    if not r or r["device"] != dev or "temp_c" not in vals:
        return
    t = vals["temp_c"]
    ok = r["min_c"] <= t <= r["max_c"]
    _cold["bad"] = 0 if ok else _cold["bad"] + 1
    on = STATE["alarms"].get("cold_chain")
    if not ok and _cold["bad"] >= r.get("consecutive", 2) and not on:
        STATE["alarms"]["cold_chain"] = {"since": utcnow(), "temp_c": t}
        local_event("local_alarm", sev="critical", rule="cold_chain", device=dev, temp_c=t,
                    msg=f"Câmara fria fora da faixa segura ({t} °C). Verificar porta e energia.", wan_up=STATE["wan_up"])
        if r.get("siren"):
            actuate(r["siren"], "alarm_on", origin="local_rule", reason="cold_chain")
    elif ok and on:
        STATE["alarms"].pop("cold_chain", None)
        local_event("local_alarm_cleared", sev="info", rule="cold_chain", device=dev, temp_c=t)
        if r.get("siren"):
            actuate(r["siren"], "alarm_off", origin="local_rule", reason="cold_chain")

def rule_flood(dev, vals):
    r = POL.get("rules", {}).get("flood")
    if not r or r["device"] != dev:
        return
    w = vals.get("water_cm", 0)
    on = STATE["alarms"].get("flood")
    if w >= r["max_cm"] and not on:
        STATE["alarms"]["flood"] = {"since": utcnow(), "water_cm": w}
        local_event("local_alarm", sev="critical", rule="flood", device=dev, water_cm=w,
                    msg=f"Água no abrigo ({w} cm). Acionar Defesa Civil.", wan_up=STATE["wan_up"])
        if r.get("siren"):
            actuate(r["siren"], "alarm_on", origin="local_rule", reason="flood")
    elif w < r["max_cm"] * 0.5 and on:
        STATE["alarms"].pop("flood", None)
        local_event("local_alarm_cleared", sev="info", rule="flood", device=dev, water_cm=w)

def rule_pump(dev, vals):
    for r in POL.get("rules", {}).get("pump_interlock", []):
        if r["level_device"] != dev or "level_pct" not in vals:
            continue
        lvl = vals["level_pct"]
        running = STATE["devices"].get(r["pump"], {}).get("values", {}).get("running")
        if lvl < r["start_below_pct"] and not running:
            actuate(r["pump"], "on", origin="local_rule", reason=f"intertravamento: nível {lvl:.0f}% < {r['start_below_pct']}%")
            local_event("interlock", sev="warning", rule="pump_interlock", device=r["pump"], level_pct=lvl, action="on")
        elif lvl > r["stop_above_pct"] and running:
            actuate(r["pump"], "off", origin="local_rule", reason=f"reservatório cheio ({lvl:.0f}%)")

def pseudonymize(badge):
    key = open(PSEUDO_KEY, "rb").read() if os.path.exists(PSEUDO_KEY) else b"lab-only"
    return "ps_" + hmac.new(key, badge.encode(), hashlib.sha256).hexdigest()[:16]

def on_connect(c, u, flags, rc, props=None):
    log("broker_connected", rc=str(rc))
    c.subscribe([("va/+/telemetry", 1), ("va/+/state", 1), ("va/+/event", 1)])

def on_message(c, u, m):
    try:
        parts = m.topic.split("/")
        dev, kind = parts[1], parts[2]
        if dev in STATE["isolated"]:
            log("isolated_device_message_dropped", sev="warning", device=dev)
            return
        p = json.loads(m.payload)
        if dev not in DEVS:
            local_event("unknown_device", sev="high", device=dev)
            return
        if kind == "event" and "badge" in p.get("values", {}):
            v = p["values"]
            v["badge"] = pseudonymize(v["badge"])   # minimização: o crachá não sai da borda em claro
            h = hour_local()
            ah = POL.get("rules", {}).get("access_hours")
            if ah and not in_window(h, ah) and v.get("result") == "granted":
                local_event("access_off_hours", sev="warning", device=dev, badge=v["badge"], door=v.get("door"), hour=h)
        STATE["devices"][dev] = {"values": p.get("values", {}), "ts": p.get("ts"), "kind": kind}
        p["space"] = SPACE
        p["kind"] = kind
        enqueue(kind, dev, int(p.get("seq", 0)), p.get("ts") or utcnow(), p)
        vals = p.get("values", {})
        rule_cold_chain(dev, vals); rule_flood(dev, vals); rule_pump(dev, vals)
    except Exception as ex:
        log("message_error", sev="warning", topic=m.topic, err=str(ex))

cli.on_connect = on_connect
cli.on_message = on_message

# ----------------------------------------------------------------- HTTPS mTLS para a nuvem
def cloud_ctx():
    ctx = ssl.create_default_context(cafile=f"{CERT_DIR}/ca-chain.crt")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(f"{CERT_DIR}/{NODE}.crt", f"{CERT_DIR}/{NODE}.key")
    return ctx
CTX = cloud_ctx()
BYTES = {"tx": 0, "rx": 0}

def api(method, path, body=None, timeout=5):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CLOUD + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
        raw = r.read()
        BYTES["tx"] += len(data or b"") + 300
        BYTES["rx"] += len(raw)
        return json.loads(raw or b"{}")

def set_link(up):
    prev = STATE["wan_up"]
    if prev == up:
        return
    STATE["wan_up"] = up
    with dblock:
        db.execute("INSERT INTO linklog VALUES(?,?)", (time.time(), "up" if up else "down"))
    if not up:
        STATE["wan_down_since"] = time.time()
        log("wan_down", sev="warning", space=SPACE, backlog=backlog())
    else:
        dur = time.time() - STATE["wan_down_since"] if STATE["wan_down_since"] else 0
        if STATE["wan_down_since"]:
            STATE["outages"].append({"start": STATE["wan_down_since"], "end": time.time(), "dur_s": round(dur, 1)})
        STATE["wan_down_since"] = None
        log("wan_up", space=SPACE, outage_s=round(dur, 1), backlog=backlog())
        if dur > 0:
            threading.Thread(target=reconcile, daemon=True).start()

def backlog():
    with dblock:
        return db.execute("SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL").fetchone()[0]

def forwarder():
    while True:
        try:
            with dblock:
                rows = db.execute("SELECT msg_id,payload FROM outbox WHERE sent_at IS NULL ORDER BY created LIMIT ?", (BATCH,)).fetchall()
            if not rows:
                api("GET", "/api/v1/health")
                set_link(True)
                time.sleep(SEND_EVERY)
                continue
            r = api("POST", "/api/v1/telemetry", {"space": SPACE, "items": [json.loads(p) for _, p in rows]})
            now = time.time()
            with dblock:
                db.executemany("UPDATE outbox SET sent_at=? WHERE msg_id=?", [(now, mid) for mid, _ in rows])
            STATE["last_sent"] = now
            set_link(True)
            if len(rows) == BATCH:
                continue
        except Exception as ex:
            if STATE["wan_up"] is not False:
                log("cloud_unreachable", sev="warning", err=type(ex).__name__)
            set_link(False)
        time.sleep(SEND_EVERY)

def reconcile():
    """Depois de uma queda: confere com a nuvem, por dispositivo, se todos os seq chegaram."""
    try:
        since = time.time() - 6 * 3600
        with dblock:
            rows = db.execute("SELECT device, MIN(seq), MAX(seq), COUNT(*) FROM outbox WHERE kind='telemetry' AND created>? GROUP BY device", (since,)).fetchall()
        summary = {d: {"min": a, "max": b, "count": n} for d, a, b, n in rows}
        r = api("POST", "/api/v1/reconcile", {"space": SPACE, "devices": summary}, timeout=15)
        missing = r.get("missing", {})
        resent = 0
        for dev, seqs in missing.items():
            for s in seqs:
                with dblock:
                    db.execute("UPDATE outbox SET sent_at=NULL WHERE device=? AND seq=? AND kind='telemetry'", (dev, s))
                resent += 1
        log("reconcile_done", space=SPACE, devices=len(summary), missing_reported=resent, cloud_counts=r.get("counts"))
    except Exception as ex:
        log("reconcile_error", sev="warning", err=str(ex))

# ----------------------------------------------------------------- comandos vindos da nuvem
CMDKEY = cmdsig.load_public(CMD_PUB) if os.path.exists(CMD_PUB) else None
SEEN = set()

def check_command(c):
    ok, why = cmdsig.verify(c, CMDKEY) if CMDKEY else (False, "sem_chave_publica")
    if not ok:
        return False, why
    if c["cmd_id"] in SEEN:
        return False, "replay"
    if c.get("space") != SPACE:
        return False, "espaco_errado"
    pol = POL.get("actuators", {}).get(c.get("device"))
    if not pol:
        return False, "dispositivo_nao_atuavel"
    impact = pol["actions"].get(c.get("action"))
    if impact is None:
        return False, "acao_nao_permitida"
    if impact == "high" and not c.get("approved_by"):
        return False, "alto_impacto_sem_aprovacao"
    if c.get("impact") != impact:
        return False, "impacto_divergente"
    win = pol.get("allowed_hours")
    if win and not in_window(hour_local(), win) and impact != "low" and not c.get("approved_by"):
        return False, "fora_da_janela"
    return True, "ok"

def soar_action(c):
    """Ações de resposta automática de baixo risco enviadas pelo SOAR (também assinadas)."""
    a, p = c["action"], c.get("params", {})
    if a == "isolate_device":
        d = p["target"]; STATE["isolated"].add(d)
        rewrite_acl(); reload_broker()
        local_event("device_isolated", sev="high", device=d, by=c.get("requested_by"))
    elif a == "release_device":
        STATE["isolated"].discard(p["target"]); rewrite_acl(); reload_broker()
        local_event("device_released", sev="info", device=p["target"], by=c.get("requested_by"))
    elif a == "safe_mode":
        actuate(p["target"], "safe_mode", origin="soar", reason="modo seguro: controle local automático")
        local_event("actuator_safe_mode", sev="high", device=p["target"])

def rewrite_acl():
    lines = [f"user {NODE}", "topic readwrite va/#", ""]
    for d in DEVS:
        if d in STATE["isolated"]:
            lines.append(f"# {d} ISOLADO pelo SOAR em {utcnow()}")
            continue
        lines += [f"user {d}", f"topic write va/{d}/telemetry", f"topic write va/{d}/state",
                  f"topic write va/{d}/event", f"topic read va/{d}/cmd", ""]
    try:
        open(ACL_PATH, "w").write("\n".join(lines) + "\n")
    except Exception as ex:
        log("acl_write_error", sev="warning", err=str(ex))

def reload_broker():
    try:
        pid = subprocess.run(["pgrep", "-x", "mosquitto"], capture_output=True, text=True).stdout.split()
        for p in pid:
            os.kill(int(p), signal.SIGHUP)
        log("broker_reloaded", pids=pid)
    except Exception as ex:
        log("broker_reload_error", sev="warning", err=str(ex))

def command_poller():
    while True:
        time.sleep(3)
        if not STATE["wan_up"]:
            continue
        try:
            r = api("GET", f"/api/v1/commands?space={SPACE}")
        except Exception:
            continue
        for c in r.get("commands", []):
            ok, why = check_command(c)
            status = "executed" if ok else "rejected"
            if ok:
                SEEN.add(c["cmd_id"])
                if c["action"] in ("isolate_device", "release_device", "safe_mode") and c.get("device") == NODE:
                    soar_action(c)
                else:
                    actuate(c["device"], c["action"], c.get("params"), origin=f"cloud:{c.get('requested_by')}", reason=c.get("params", {}).get("motivo", ""))
                log("cloud_command_accepted", device=c["device"], action=c["action"], impact=c.get("impact"),
                    requested_by=c.get("requested_by"), approved_by=c.get("approved_by"), hour=hour_local(), space=SPACE)
            else:
                local_event("cloud_command_rejected", sev="high", device=c.get("device"), action=c.get("action"),
                            reason=why, requested_by=c.get("requested_by"), hour=hour_local(), cmd_id=c.get("cmd_id"))
            try:
                api("POST", f"/api/v1/commands/{c.get('cmd_id')}/ack", {"status": status, "reason": why})
            except Exception:
                pass

def crl_sync():
    """Baixa a CRL publicada; se mudou, grava e manda o broker recarregar (revogação, RT-05)."""
    while True:
        time.sleep(int(E("CRL_SYNC_S", "20")))
        if not STATE["wan_up"]:
            continue
        try:
            req = urllib.request.Request(CLOUD + "/api/v1/crl")
            with urllib.request.urlopen(req, context=CTX, timeout=5) as r:
                crl = r.read()
            old = open(CRL_PATH, "rb").read() if os.path.exists(CRL_PATH) else b""
            if crl and crl != old:
                open(CRL_PATH, "wb").write(crl)
                log("crl_updated", sev="info", bytes=len(crl), sha256=hashlib.sha256(crl).hexdigest())
                reload_broker()
        except Exception:
            pass

# ----------------------------------------------------------------- métricas do nó
def metrics_loop():
    import psutil
    pr = psutil.Process()
    while True:
        time.sleep(int(E("METRICS_S", "15")))
        try:
            mem = pr.memory_info().rss / 1e6
            cpu = pr.cpu_percent(interval=None)
            bro = [p for p in psutil.process_iter(["name"]) if p.info["name"] == "mosquitto"]
            bcpu = sum(p.cpu_percent(interval=None) for p in bro)
            bmem = sum(p.memory_info().rss for p in bro) / 1e6
            log("node_metrics", space=SPACE, cpu_pct=round(cpu + bcpu, 2), mem_mb=round(mem + bmem, 1),
                tx_bytes=BYTES["tx"], rx_bytes=BYTES["rx"], backlog=backlog(), wan_up=STATE["wan_up"],
                alarms=list(STATE["alarms"].keys()))
        except Exception as ex:
            log("metrics_error", err=str(ex))

# ----------------------------------------------------------------- página local
NOMES = POL.get("labels", {})
class Local(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        if self.path.startswith("/status.json"):
            body = json.dumps({"space": SPACE, "wan_up": STATE["wan_up"], "backlog": backlog(), "alarms": STATE["alarms"],
                               "devices": STATE["devices"], "outages": STATE["outages"], "isolated": sorted(STATE["isolated"])},
                              ensure_ascii=False, default=str).encode()
            ct = "application/json"
        else:
            cards = []
            for d, s in STATE["devices"].items():
                v = ", ".join(f"{k}: {val}" for k, val in s["values"].items())
                cards.append(f"<li><strong>{NOMES.get(d, d)}</strong><br>{v}</li>")
            al = "".join(f"<p class='alerta' role='alert'>ALERTA: {a}</p>" for a in STATE["alarms"]) or "<p>Nenhum alarme agora.</p>"
            net = "Internet: funcionando" if STATE["wan_up"] else "Internet: FORA DO AR. O sistema continua funcionando aqui."
            body = (f"<!doctype html><html lang='pt-BR'><meta charset='utf-8'><meta http-equiv='refresh' content='10'>"
                    f"<title>Painel local {SPACE}</title><style>body{{font:18px/1.5 sans-serif;background:#fff;color:#111;max-width:46rem;margin:auto;padding:1rem}}"
                    f".alerta{{background:#8b0000;color:#fff;padding:.6rem;font-weight:bold}}li{{margin:.5rem 0}}</style>"
                    f"<h1>Painel local: {POL.get('name', SPACE)}</h1><p>{net}</p>{al}<ul>{''.join(cards)}</ul>"
                    f"<p>Dados guardados para enviar: {backlog()}</p></html>").encode()
            ct = "text/html; charset=utf-8"
        self.send_response(200); self.send_header("Content-Type", ct); self.end_headers(); self.wfile.write(body)

def main():
    rewrite_acl()
    log("edge_start", space=SPACE, node=NODE, cloud=CLOUD, policy_version=POL.get("version"))
    cli.connect_async(BROKER, BROKER_PORT, keepalive=30)
    cli.loop_start()
    for fn in (forwarder, command_poller, crl_sync, metrics_loop):
        threading.Thread(target=fn, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", LOCAL_PORT), Local)
    signal.signal(signal.SIGTERM, lambda *a: (log("edge_stop", space=SPACE), os._exit(0)))
    srv.serve_forever()

if __name__ == "__main__":
    if "--write-acl" in sys.argv:
        rewrite_acl()
        sys.exit(0)
    main()
