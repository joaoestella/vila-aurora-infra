"""API mínima da CA emissora para revogação/rotação remota (RT-05), chamada só pelo SOAR via mTLS."""
import json, os, ssl, subprocess, sys
from flask import Flask, request, abort, g
sys.path.insert(0, "/app/common"); sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))
from vlog import VLog  # noqa
E = os.environ.get; log = VLog("pkiapi"); app = Flask(__name__)
CA_SH = E("CA_SH", "/pki-src/ca.sh"); CERT_DIR = E("CERT_DIR", "/pki")
@app.before_request
def ident():
    sock = request.environ.get("werkzeug.socket"); cert = sock.getpeercert() if sock else None
    g.cn = dict(x[0] for x in cert["subject"]).get("commonName") if cert else None
    if g.cn not in ("svc-soar", "svc-panel"): abort(403)
@app.post("/revoke")
def revoke():
    b = request.get_json(force=True); name = b.get("name", "")
    if not name or "/" in name or ".." in name: abort(400)
    r = subprocess.run(["bash", CA_SH, "revoke", name, b.get("reason", "keyCompromise")], capture_output=True, text=True, env={**os.environ})
    log("cert_revoked_api", sev="high", name=name, by=g.cn, why=b.get("why"), rc=r.returncode, out=r.stdout.strip()[-120:])
    return {"status": "revogado" if r.returncode == 0 else "erro", "saida": r.stdout.strip()[-200:]}
@app.get("/crl")
def crl():
    return open(f"{CERT_DIR}/issuing.crl", "rb").read(), 200, {"Content-Type": "application/pkix-crl"}
def ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.load_cert_chain(f"{CERT_DIR}/svc-pki.crt", f"{CERT_DIR}/svc-pki.key")
    c.load_verify_locations(f"{CERT_DIR}/ca-chain.crt"); c.verify_mode = ssl.CERT_REQUIRED; return c
if __name__ == "__main__":
    from werkzeug.serving import make_server
    log("pkiapi_start"); make_server(E("BIND", "0.0.0.0"), int(E("PORT", "9444")), app, threaded=True, ssl_context=ctx()).serve_forever()
