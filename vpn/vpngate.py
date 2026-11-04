"""Portão de acesso administrativo por VPN (RT-06, RT-07).
O acesso administrativo remoto só existe pela VPN e só é liberado por tempo limitado após MFA.
Em vez de expor WireGuard direto, o painel chama este serviço (mTLS, só svc-panel), que:
  * registra a abertura de sessão (quem, quando, por quanto tempo) no formato do SIEM;
  * habilita o peer WireGuard do operador por N horas (no lab, grava em um arquivo de sessões);
  * permite ao SOAR encerrar a sessão (R1).
Também expõe /auth para registrar tentativas de login na VPN (sucesso/falha) que alimentam a regra R1."""
import json, os, ssl, sys, time
from datetime import datetime, timezone, timedelta
from flask import Flask, request, abort, g
sys.path.insert(0, "/app/common"); sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from vlog import VLog  # noqa
E = os.environ.get; log = VLog("vpngate"); app = Flask(__name__)
CERT_DIR = E("CERT_DIR", "/pki"); SESS = E("VPN_SESS", "/data/vpn_sessions.json")
def load():
    try: return json.load(open(SESS))
    except Exception: return {}
def save(s): os.makedirs(os.path.dirname(SESS), exist_ok=True); json.dump(s, open(SESS, "w"), default=str)
@app.before_request
def ident():
    sock = request.environ.get("werkzeug.socket"); cert = sock.getpeercert() if sock else None
    g.cn = dict(x[0] for x in cert["subject"]).get("commonName") if cert else None
    if g.cn not in ("svc-panel", "svc-soar"): abort(403)
@app.post("/open")
def open_():
    b = request.get_json(force=True)
    if not b.get("mfa"): 
        log("vpn_open_denied_no_mfa", sev="high", user=b.get("user")); abort(403)
    hrs = int(b.get("hours", 1)); s = load()
    s[b["user"]] = {"since": datetime.now(timezone.utc).isoformat(), "until": (datetime.now(timezone.utc) + timedelta(hours=hrs)).isoformat(),
                    "role": b.get("role"), "ip": b.get("ip")}
    save(s)
    log("vpn_session_opened", user=b["user"], role=b.get("role"), hours=hrs, ip=b.get("ip"), mfa=True)
    return {"status": "aberto", "mensagem": f"Acesso liberado por {hrs}h. Lembre de sair ao terminar."}
@app.post("/kill")
def kill():
    b = request.get_json(force=True); s = load(); u = b.get("user")
    if u in s: s.pop(u); save(s)
    log("vpn_session_killed", sev="high", user=u, by=b.get("by"), ip=b.get("ip"))
    return {"status": "encerrado"}
@app.post("/auth")
def auth():
    b = request.get_json(force=True)
    ev = "vpn_login_success" if b.get("ok") else "vpn_login_failed"
    log(ev, sev="info" if b.get("ok") else "warning", user=b.get("user"), ip=b.get("ip"), mfa=b.get("mfa"), geo=b.get("geo"))
    return {"status": "ok"}
def ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.load_cert_chain(f"{CERT_DIR}/svc-vpngate.crt", f"{CERT_DIR}/svc-vpngate.key")
    c.load_verify_locations(f"{CERT_DIR}/ca-chain.crt"); c.verify_mode = ssl.CERT_REQUIRED; return c
if __name__ == "__main__":
    from werkzeug.serving import make_server
    log("vpngate_start"); make_server(E("BIND", "0.0.0.0"), int(E("PORT", "9445")), app, threaded=True, ssl_context=ctx()).serve_forever()
