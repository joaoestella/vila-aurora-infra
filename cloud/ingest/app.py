"""API de ingestão da nuvem (RT-01, RT-02, RT-04).
Só aceita conexões HTTPS com certificado de cliente emitido pela CA do projeto (mTLS) e checa a CRL.
O CN do certificado (edge-<espaco>) precisa bater com o espaço dos dados enviados."""
import json, os, ssl, sys, threading, time
from datetime import datetime
from flask import Flask, request, jsonify, abort, g
import psycopg2, psycopg2.extras

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))
sys.path.insert(0, "/app/common")
from vlog import VLog  # noqa: E402

E = os.environ.get
log = VLog("ingest")
DSN = E("DB_DSN", "host=db dbname=vila user=ingest_app")
CERT_DIR = E("CERT_DIR", "/pki")
CRL = E("CRL_PATH", "/pki/issuing.crl")
app = Flask(__name__)

def db():
    if "db" not in g:
        g.db = psycopg2.connect(DSN)
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def close(e):
    c = g.pop("db", None)
    if c:
        c.close()

def peer():
    sock = request.environ.get("werkzeug.socket")
    cert = sock.getpeercert() if sock else None
    if not cert:
        abort(401)
    cn = dict(x[0] for x in cert["subject"]).get("commonName")
    return cn

@app.before_request
def auth():
    g.cn = peer()
    if not g.cn.startswith("edge-") and not g.cn.startswith("svc-"):
        log("ingest_forbidden_identity", sev="high", cn=g.cn, path=request.path, ip=request.remote_addr)
        abort(403)

def space_ok(space):
    if g.cn != f"edge-{space}":
        log("ingest_space_mismatch", sev="high", cn=g.cn, claimed=space, ip=request.remote_addr)
        abort(403)

@app.get("/api/v1/health")
def health():
    return {"ok": True, "cn": g.cn}

@app.post("/api/v1/telemetry")
def telemetry():
    body = request.get_json(force=True)
    space = body.get("space", "")
    space_ok(space)
    rows, acc = [], []
    for it in body.get("items", [])[:1000]:
        kind = it.get("kind") if it.get("kind") in ("telemetry", "state", "event") else "telemetry"
        dev = str(it.get("device", ""))[:64]
        rows.append((str(it["msg_id"])[:120], space, dev, int(it.get("seq", 0)), kind, it.get("ts"), json.dumps(it)))
        v = it.get("values", {})
        if "badge" in v:
            acc.append((it.get("ts"), space, v.get("door", "principal"), v["badge"], v.get("result", "granted")))
    cur = db().cursor()
    psycopg2.extras.execute_values(cur, "INSERT INTO telemetria (msg_id,espaco,dispositivo,seq,tipo,ts,payload) VALUES %s ON CONFLICT (msg_id) DO NOTHING", rows)
    new = cur.rowcount
    if acc:
        psycopg2.extras.execute_values(cur, "INSERT INTO acessos (ts,espaco,porta,cracha_ps,resultado) VALUES %s", acc)
    log("ingest_batch", space=space, items=len(rows), new=new, dup=len(rows) - max(new, 0), cn=g.cn)
    return {"accepted": len(rows), "new": new}

@app.post("/api/v1/reconcile")
def reconcile():
    body = request.get_json(force=True)
    space = body.get("space", "")
    space_ok(space)
    missing, counts = {}, {}
    cur = db().cursor()
    for dev, s in body.get("devices", {}).items():
        cur.execute("SELECT seq FROM telemetria WHERE dispositivo=%s AND espaco=%s AND tipo='telemetry' AND seq BETWEEN %s AND %s",
                    (dev, space, int(s["min"]), int(s["max"])))
        have = {r[0] for r in cur.fetchall()}
        counts[dev] = {"edge": s["count"], "cloud": len(have)}
        want = set(range(int(s["min"]), int(s["max"]) + 1))
        miss = sorted(want - have)
        if miss:
            missing[dev] = miss[:5000]
    log("reconcile", space=space, devices=len(counts), missing=sum(len(v) for v in missing.values()), counts=counts)
    return {"missing": missing, "counts": counts}

@app.get("/api/v1/commands")
def commands():
    space = request.args.get("space", "")
    space_ok(space)
    cur = db().cursor()
    cur.execute("SELECT assinado FROM comandos WHERE espaco=%s AND status='pendente' ORDER BY criado_em LIMIT 20", (space,))
    cmds = [r[0] for r in cur.fetchall()]
    if cmds:
        log("commands_delivered", space=space, n=len(cmds))
    return {"commands": cmds}

@app.post("/api/v1/commands/<cmd_id>/ack")
def ack(cmd_id):
    b = request.get_json(force=True)
    cur = db().cursor()
    cur.execute("UPDATE comandos SET status=%s, motivo_ack=%s, ack_em=now() WHERE cmd_id::text=%s AND espaco=%s",
                (b.get("status", "?")[:20], b.get("reason", "")[:80], cmd_id, g.cn.replace("edge-", "")))
    return {"ok": True}

@app.get("/api/v1/crl")
def crl():
    return open(CRL, "rb").read(), 200, {"Content-Type": "application/pkix-crl"}

def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(f"{CERT_DIR}/ingest.vila.lab.crt", f"{CERT_DIR}/ingest.vila.lab.key")
    ctx.load_verify_locations(f"{CERT_DIR}/ca-chain.crt")
    ctx.load_verify_locations(CRL)
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

class Holder:
    ctx = None

def crl_watch(server):
    last = os.path.getmtime(CRL)
    while True:
        time.sleep(10)
        try:
            m = os.path.getmtime(CRL)
            if m != last:
                last = m
                server.socket.context.load_verify_locations(CRL)
                log("crl_reloaded", sev="info")
        except Exception as ex:
            log("crl_reload_error", sev="warning", err=str(ex))

if __name__ == "__main__":
    from werkzeug.serving import make_server
    srv = make_server(E("BIND", "0.0.0.0"), int(E("PORT", "8443")), app, threaded=True, ssl_context=tls_context())
    threading.Thread(target=crl_watch, args=(srv,), daemon=True).start()
    log("ingest_start", port=E("PORT", "8443"))
    srv.serve_forever()
