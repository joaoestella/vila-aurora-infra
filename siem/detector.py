"""SIEM leve próprio da Rede Vila Aurora (alternativa ao Wazuh quando o orçamento não permite 8 GB só para o SIEM).
Lê os logs JSON de LOG_DIR e o CSV do Postgres, normaliza e aplica as regras de detecção (RT-12, RT-13).
Em paralelo, o repositório traz a configuração do Wazuh (siem/wazuh/) para quem tiver recurso; as duas rotas
usam os mesmos campos de log, então as regras são equivalentes.

Regras (RT-13):
  R1  login VPN anômalo (IP novo / fora de horário / país improvável / força bruta de MFA)
  R2  padrão de SQL Injection na aplicação web
  R3  dispositivo sem certificado válido no broker (TLS recusado / revogado)
  R4  comando de atuador fora do horário ou do perfil esperado
Cada alerta sai em JSON (alerts.log), com severidade e técnica MITRE ATT&CK, e pode disparar o SOAR.
"""
import glob, json, os, re, time, csv, io
from collections import defaultdict, deque
from datetime import datetime, timezone

E = os.environ.get
LOGDIR = E("LOG_DIR", "/var/log/vila")
ALERTS = os.path.join(LOGDIR, "alerts.log")
STATE = E("SIEM_STATE", "/tmp/siem_state.json")
SOAR_URL = E("SOAR_URL")
HOME_IPS = set(filter(None, E("HOME_IPS", "172.31.0.0/16,127.0.0.1,10.13.0.0/24").split(",")))

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def emit(rule, sev, title, attack, **ctx):
    a = {"ts": now(), "src": "siem", "event": "alert", "rule": rule, "sev": sev, "title": title,
         "attack": attack, **ctx}
    with open(ALERTS, "a", encoding="utf-8") as f:
        f.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")
    print(f"[ALERTA {rule}/{sev}] {title} :: {json.dumps(ctx, ensure_ascii=False, default=str)}", flush=True)
    if SOAR_URL and sev in ("high", "critical"):
        try:
            import urllib.request, ssl
            ctx_ = ssl.create_default_context(cafile=E("CA", "/pki/ca-chain.crt"))
            ctx_.load_cert_chain(E("SIEM_CERT", "/pki/svc-soar.crt"), E("SIEM_KEY", "/pki/svc-soar.key"))
            body = json.dumps({"rule": rule, "alert": a}).encode()
            req = urllib.request.Request(SOAR_URL + "/event", data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, context=ctx_, timeout=5)
        except Exception as ex:
            print("soar indisponível:", ex, flush=True)

SQLI = re.compile(r"(\bunion\b.*\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|information_schema|--\s|/\*|\bsleep\s*\(|pg_sleep|xp_cmdshell|'\s*or\s*'1'\s*=\s*'1|%27|\bconcat\s*\()", re.I)

def hour_sp(ts):
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (t.hour - 3) % 24
    except Exception:
        return None

class Detector:
    def __init__(self):
        self.vpn_fail = defaultdict(lambda: deque(maxlen=20))
        self.seen_ip = defaultdict(set)
        self.load_state()

    def load_state(self):
        try:
            s = json.load(open(STATE))
            self.seen_ip = defaultdict(set, {k: set(v) for k, v in s.get("seen_ip", {}).items()})
        except Exception:
            pass

    def save_state(self):
        json.dump({"seen_ip": {k: sorted(v) for k, v in self.seen_ip.items()}}, open(STATE, "w"))

    # R1 ---------------------------------------------------------------
    def vpn(self, r):
        ev, user, ip = r.get("event"), r.get("user", "?"), r.get("ip", "?")
        h = hour_sp(r.get("ts", ""))
        if ev == "vpn_login_failed":
            dq = self.vpn_fail[user]
            dq.append(time.time())
            recent = [t for t in dq if time.time() - t < 300]
            if len(recent) >= 5:
                emit("R1", "high", f"Força bruta de autenticação VPN para {user}", "T1110",
                     user=user, ip=ip, tentativas=len(recent), host=r.get("host"))
                dq.clear()
        if ev == "vpn_login_success":
            known = self.seen_ip[user]
            flags = []
            if ip not in known and known:
                flags.append("IP nunca visto para este usuário")
            if h is not None and (h >= 23 or h < 5):
                flags.append(f"horário incomum ({h}h)")
            if r.get("geo") and r.get("geo") not in ("BR", "local"):
                flags.append(f"origem {r.get('geo')}")
            if r.get("mfa") is False:
                flags.append("sem MFA")
            self.seen_ip[user].add(ip)
            if flags:
                emit("R1", "high" if len(flags) >= 2 or r.get("mfa") is False else "medium",
                     f"Login VPN anômalo de {user}", "T1133/T1078", user=user, ip=ip, hora=h, motivos=flags, host=r.get("host"))

    # R2 ---------------------------------------------------------------
    def web(self, r):
        if r.get("src") not in ("panel", "panel_legado", "web"):
            return
        blob = json.dumps(r.get("params", {}), ensure_ascii=False) + " " + str(r.get("query", "")) + " " + str(r.get("path", ""))
        if SQLI.search(blob):
            emit("R2", "high", "Padrão de SQL Injection na aplicação web", "T1190",
                 ip=r.get("ip"), user=r.get("user"), path=r.get("path"), amostra=blob[:160], status=r.get("status"), host=r.get("host"))

    # R3 ---------------------------------------------------------------
    def broker(self, line):
        if "certificate verify failed" in line or "peer did not return a certificate" in line or "unknown CA" in line:
            emit("R3", "high", "Dispositivo sem certificado válido tentou conectar no broker", "T1078.004/T1557",
                 evidencia=line.strip()[-160:])

    # R4 ---------------------------------------------------------------
    def actuator(self, r):
        ev = r.get("event")
        if ev == "cloud_command_rejected":
            emit("R4", "high", "Comando de atuador recusado pela borda", "T0831/T1565",
                 device=r.get("device"), action=r.get("action"), reason=r.get("reason"),
                 requested_by=r.get("requested_by"), hora=r.get("hour"), space=r.get("space"), host=r.get("host"))
        elif ev == "actuator_command":
            h = r.get("hour")
            susp = []
            if r.get("origin", "").startswith("cloud") and h is not None and (h >= 22 or h < 5):
                susp.append(f"comando pela nuvem em horário incomum ({h}h)")
            if susp:
                emit("R4", "medium", "Comando de atuador em horário incomum", "T0831",
                     device=r.get("device"), action=r.get("action"), origin=r.get("origin"), motivos=susp, space=r.get("space"))

    def feed_json(self, r):
        self.vpn(r); self.web(r); self.actuator(r)

det = Detector()

def tail_files():
    pos = {}
    pats = [os.path.join(LOGDIR, p) for p in ("panel.log", "panel_legado_access.log", "vpngate.log", "edge-*.log", "ingest.log", "mosquitto-*.log")]
    oneshot = E("ONESHOT") == "1"
    while True:
        for pat in pats:
            for fn in glob.glob(pat):
                try:
                    sz = os.path.getsize(fn)
                    start = pos.get(fn, 0 if oneshot else sz)
                    if sz < start:
                        start = 0
                    with open(fn, "r", errors="replace") as f:
                        f.seek(start)
                        for line in f:
                            line = line.rstrip("\n")
                            if not line:
                                continue
                            if "mosquitto-" in fn:
                                det.broker(line)
                            elif line.startswith("{"):
                                try:
                                    det.feed_json(json.loads(line))
                                except Exception:
                                    pass
                        pos[fn] = f.tell()
                except FileNotFoundError:
                    pass
        det.save_state()
        if oneshot:
            return
        time.sleep(float(E("SIEM_POLL", "1")))

if __name__ == "__main__":
    print(f"SIEM leve observando {LOGDIR}", flush=True)
    tail_files()
