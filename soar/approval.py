"""Serviço de aprovação e assinatura de comandos (RT-15).
* único componente com a chave privada que assina comandos de atuador (Ed25519);
* ação de baixo impacto: assina e entrega para a borda;
* ação de alto impacto: abre pedido de aprovação; só a coordenação aprova, com MFA, e quem pediu não aprova;
* aceita chamadas só de svc-panel e svc-soar (mTLS)."""
import json, os, ssl, sys, glob
import psycopg2
from flask import Flask, request, abort, g

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
sys.path.insert(0, "/app/common")
from vlog import VLog  # noqa: E402
import cmdsig           # noqa: E402

E = os.environ.get
log = VLog("approval")
app = Flask(__name__)
DSN = E("DB_DSN", "host=db dbname=vila user=approval_app")
KEY = cmdsig.load_private(E("CMD_PRIVKEY", "/keys/cmd-signer.key"))
POL = {}
for f in glob.glob(os.path.join(E("POLICY_DIR", "/app/policies"), "*.json")):
    p = json.load(open(f, encoding="utf-8"))
    POL[p["space"]] = p
CERT_DIR = E("CERT_DIR", "/pki")

def db():
    if "db" not in g:
        g.db = psycopg2.connect(DSN); g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def _c(e):
    c = g.pop("db", None)
    if c: c.close()

@app.before_request
def ident():
    sock = request.environ.get("werkzeug.socket")
    cert = sock.getpeercert() if sock else None
    g.cn = dict(x[0] for x in cert["subject"]).get("commonName") if cert else None
    if g.cn not in ("svc-panel", "svc-soar"):
        log("approval_forbidden", sev="high", cn=g.cn, ip=request.remote_addr)
        abort(403)

def impacto(space, device, action):
    return POL.get(space, {}).get("actuators", {}).get(device, {}).get("actions", {}).get(action)

def emitir(req, approved_by=None):
    cmd = cmdsig.sign({"space": req["space"], "device": req["device"], "action": req["action"], "params": req.get("params", {}),
                       "impact": req["impact"], "requested_by": req["requested_by"], "approved_by": approved_by}, KEY,
                      ttl=int(E("CMD_TTL_S", "300")))
    cur = db().cursor()
    cur.execute("INSERT INTO comandos (cmd_id,espaco,dispositivo,acao,impacto,pedido_por,aprovado_por,assinado) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (cmd["cmd_id"], cmd["space"], cmd["device"], cmd["action"], cmd["impact"], cmd["requested_by"], approved_by, json.dumps(cmd)))
    cur.execute("INSERT INTO auditoria (ator,acao,detalhe) VALUES (%s,%s,%s)", (req["requested_by"], "comando_assinado",
                json.dumps({"cmd_id": cmd["cmd_id"], "device": cmd["device"], "action": cmd["action"], "impact": cmd["impact"], "approved_by": approved_by})))
    log("command_signed", cmd_id=cmd["cmd_id"], space=cmd["space"], device=cmd["device"], action=cmd["action"], impact=cmd["impact"],
        requested_by=cmd["requested_by"], approved_by=approved_by, via=g.cn)
    return cmd

@app.post("/request")
def pedir():
    b = request.get_json(force=True)
    space, device, action = b.get("space"), b.get("device"), b.get("action")
    imp = impacto(space, device, action)
    if imp is None:
        log("command_request_invalid", sev="warning", space=space, device=device, action=action, by=b.get("requested_by"))
        return {"status": "recusado", "mensagem": "Ação não permitida para este equipamento."}, 400
    who = b.get("requested_by", "?")
    if g.cn == "svc-panel" and b.get("role") not in ("tecnico", "coordenacao"):
        abort(403)
    if g.cn == "svc-soar":
        who = "soar"
    req = {"space": space, "device": device, "action": action, "params": b.get("params", {}), "impact": imp, "requested_by": who}
    if imp == "low":
        cmd = emitir(req)
        return {"status": "enviado", "cmd_id": cmd["cmd_id"], "mensagem": "Comando de baixo impacto assinado e enviado para a borda."}
    cur = db().cursor()
    cur.execute("INSERT INTO aprovacoes (pedido,pedido_por,origem) VALUES (%s,%s,%s) RETURNING id",
                (json.dumps(req), who, "soar" if g.cn == "svc-soar" else "painel"))
    pid = cur.fetchone()[0]
    log("approval_requested", sev="warning", id=pid, space=space, device=device, action=action, requested_by=who, origin=g.cn)
    return {"status": "pendente", "id": pid, "mensagem": f"Ação de ALTO impacto: pedido #{pid} aguardando aprovação da coordenação."}

@app.post("/decide")
def decidir():
    if g.cn != "svc-panel":
        abort(403)
    b = request.get_json(force=True)
    if b.get("role") != "coordenacao" or not b.get("mfa"):
        abort(403)
    cur = db().cursor()
    cur.execute("UPDATE aprovacoes SET status='expirado' WHERE status='pendente' AND criado_em < now() - interval '30 minutes'")
    cur.execute("SELECT pedido, pedido_por, status FROM aprovacoes WHERE id=%s", (int(b["id"]),))
    r = cur.fetchone()
    if not r or r[2] != "pendente":
        return {"status": "invalido", "mensagem": "Pedido não está pendente (pode ter expirado)."}
    req, quem, _ = r
    if quem == b["decided_by"]:
        log("approval_self_denied", sev="warning", id=b["id"], user=quem)
        return {"status": "recusado", "mensagem": "Quem pediu não pode aprovar o próprio pedido."}
    novo = "aprovado" if b["decision"] == "aprovar" else "negado"
    cur.execute("UPDATE aprovacoes SET status=%s, decidido_por=%s, decidido_em=now() WHERE id=%s", (novo, b["decided_by"], int(b["id"])))
    log("approval_decided", sev="warning", id=b["id"], decision=novo, decided_by=b["decided_by"], requested_by=quem, action=req["action"], device=req["device"])
    if novo == "aprovado":
        cmd = emitir(req, approved_by=b["decided_by"])
        return {"status": "aprovado", "cmd_id": cmd["cmd_id"], "mensagem": "Aprovado. Comando assinado e enviado para a borda."}
    return {"status": "negado", "mensagem": "Pedido negado."}

def ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.load_cert_chain(f"{CERT_DIR}/svc-approval.crt", f"{CERT_DIR}/svc-approval.key")
    c.load_verify_locations(f"{CERT_DIR}/ca-chain.crt")
    c.verify_mode = ssl.CERT_REQUIRED
    return c

if __name__ == "__main__":
    from werkzeug.serving import make_server
    log("approval_start")
    make_server(E("BIND", "0.0.0.0"), int(E("PORT", "9443")), app, threaded=True, ssl_context=ctx()).serve_forever()
