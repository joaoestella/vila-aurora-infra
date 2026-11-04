"""SOAR: respostas automatizadas de BAIXO risco (RT-15).
Recebe alertas do SIEM (mTLS, só svc-soar/siem) e executa playbooks de baixo impacto:
  * isolar dispositivo no broker (ACL), revogar certificado, encerrar sessão VPN, bloquear IP, pôr atuador em modo seguro.
Ações de ALTO impacto (desligar bomba, liberar todas as portas, desligar gerador) NÃO são feitas aqui: o SOAR
apenas abre um pedido de aprovação no serviço de aprovação, que exige decisão humana com MFA.
Toda ação é assinada (via serviço de aprovação) e registrada."""
import json, os, ssl, sys, time, urllib.request
from flask import Flask, request, abort, g
import psycopg2

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
sys.path.insert(0, "/app/common")
from vlog import VLog  # noqa

E = os.environ.get
log = VLog("soar")
app = Flask(__name__)
CERT_DIR = E("CERT_DIR", "/pki")
APPROVAL = E("APPROVAL_URL", "https://approval:9443")
PKIAPI = E("PKIAPI_URL", "https://pkiapi:9444")
VPNGATE = E("VPNGATE_URL", "https://vpngate:9445")
FW = E("FIREWALL_FILE", "/data/blocklist.txt")
DSN = E("DB_DSN", "host=db dbname=vila user=approval_app")

# mapa alerta -> playbook. "auto" = executa sozinho (baixo risco). "approval" = abre pedido humano.
PLAYBOOKS = {
    "R1": {"mode": "auto", "actions": ["end_vpn_session", "block_ip"]},       # login VPN anômalo
    "R2": {"mode": "auto", "actions": ["block_ip"]},                          # SQL injection
    "R3": {"mode": "auto", "actions": ["revoke_cert"]},                       # dispositivo sem cert válido
    "R4": {"mode": "auto", "actions": ["safe_mode_actuator"]},               # comando de atuador suspeito
}

def ctx_client():
    c = ssl.create_default_context(cafile=f"{CERT_DIR}/ca-chain.crt")
    c.load_cert_chain(f"{CERT_DIR}/svc-soar.crt", f"{CERT_DIR}/svc-soar.key")
    return c

def call(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx_client(), timeout=8) as r:
        return json.loads(r.read() or b"{}")

def db():
    if "db" not in g:
        g.db = psycopg2.connect(DSN); g.db.autocommit = True
    return g.db

def audit(action, detail):
    try:
        db().cursor().execute("INSERT INTO auditoria (ator,acao,detalhe) VALUES ('soar',%s,%s)", (action, json.dumps(detail, default=str)))
    except Exception:
        pass

def block_ip(ip, why):
    if not ip:
        return "sem_ip"
    os.makedirs(os.path.dirname(FW), exist_ok=True)
    cur = set(open(FW).read().split()) if os.path.exists(FW) else set()
    cur.add(ip)
    open(FW, "w").write("\n".join(sorted(cur)) + "\n")
    log("soar_block_ip", sev="high", ip=ip, why=why)
    return "bloqueado"

def end_vpn_session(user, ip):
    try:
        r = call(VPNGATE, "/kill", {"user": user, "ip": ip, "by": "soar"})
        log("soar_end_vpn", sev="high", user=user, ip=ip, result=r.get("status"))
        return r.get("status", "ok")
    except Exception as ex:
        log("soar_end_vpn_error", sev="warning", err=str(ex)); return "indisponivel"

def revoke_cert(name, why):
    try:
        r = call(PKIAPI, "/revoke", {"name": name, "reason": "keyCompromise", "by": "soar", "why": why})
        log("soar_revoke_cert", sev="high", name=name, result=r.get("status"))
        return r.get("status", "ok")
    except Exception as ex:
        log("soar_revoke_error", sev="warning", err=str(ex)); return "indisponivel"

def safe_mode_actuator(space, device):
    try:
        r = call(APPROVAL, "/request", {"space": space, "device": f"edge-{space}", "action": "safe_mode",
                                        "params": {"target": device, "motivo": "resposta automática do SOAR"}, "requested_by": "soar"})
        log("soar_safe_mode", sev="high", space=space, device=device, result=r.get("status"))
        return r.get("status", "ok")
    except Exception as ex:
        log("soar_safe_mode_error", sev="warning", err=str(ex)); return "indisponivel"

def request_high_impact(space, device, action, why):
    r = call(APPROVAL, "/request", {"space": space, "device": device, "action": action,
                                    "params": {"motivo": f"SOAR sugere (ALTO impacto, requer humano): {why}"}, "requested_by": "soar"})
    log("soar_high_impact_requested", sev="warning", space=space, device=device, action=action, approval=r.get("id"))
    return r

@app.before_request
def ident():
    sock = request.environ.get("werkzeug.socket")
    cert = sock.getpeercert() if sock else None
    g.cn = dict(x[0] for x in cert["subject"]).get("commonName") if cert else None
    if g.cn not in ("svc-soar", "svc-panel"):
        abort(403)

@app.post("/event")
def event():
    b = request.get_json(force=True)
    rule = b.get("rule")
    a = b.get("alert", {})
    pb = PLAYBOOKS.get(rule)
    if not pb:
        return {"status": "ignorado", "motivo": "sem playbook"}
    done = []
    for act in pb["actions"]:
        if act == "block_ip":
            done.append(("block_ip", block_ip(a.get("ip"), rule)))
        elif act == "end_vpn_session":
            done.append(("end_vpn_session", end_vpn_session(a.get("user"), a.get("ip"))))
        elif act == "revoke_cert" and a.get("device"):
            done.append(("revoke_cert", revoke_cert(a.get("device"), rule)))
        elif act == "safe_mode_actuator" and a.get("space") and a.get("device"):
            done.append(("safe_mode_actuator", safe_mode_actuator(a["space"], a["device"])))
    audit("playbook", {"rule": rule, "actions": done, "alert": {k: a.get(k) for k in ("ip", "user", "device", "title")}})
    log("soar_playbook_done", rule=rule, mode=pb["mode"], actions=done, alert_title=a.get("title"))
    return {"status": "executado", "actions": done}

@app.post("/recommend_high_impact")
def rec():
    if g.cn != "svc-panel":
        abort(403)
    b = request.get_json(force=True)
    return request_high_impact(b["space"], b["device"], b["action"], b.get("why", ""))

def ctx_server():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.load_cert_chain(f"{CERT_DIR}/svc-soar.crt", f"{CERT_DIR}/svc-soar.key")
    c.load_verify_locations(f"{CERT_DIR}/ca-chain.crt")
    c.verify_mode = ssl.CERT_REQUIRED
    return c

if __name__ == "__main__":
    from werkzeug.serving import make_server
    log("soar_start")
    make_server(E("BIND", "0.0.0.0"), int(E("PORT", "9446")), app, threaded=True, ssl_context=ctx_server()).serve_forever()
