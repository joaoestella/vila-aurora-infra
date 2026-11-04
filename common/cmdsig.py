"""Assinatura de comandos de atuador (Ed25519).
Só o serviço de aprovação (SOAR/approval) tem a chave privada. A borda tem apenas a chave pública:
um comando gravado direto no banco (como no INC-VA-0712, via SQL Injection) não tem assinatura válida
e é recusado pelo nó de borda."""
import base64, json, time, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

FIELDS = ("cmd_id", "space", "device", "action", "params", "impact", "requested_by", "approved_by", "iat", "exp")

def canonical(cmd):
    body = {k: cmd.get(k) for k in FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def load_private(path):
    return serialization.load_pem_private_key(open(path, "rb").read(), password=None)

def load_public(path):
    return serialization.load_pem_public_key(open(path, "rb").read())

def new_keypair(priv_path, pub_path):
    k = Ed25519PrivateKey.generate()
    open(priv_path, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(pub_path, "wb").write(k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

def sign(cmd, priv, ttl=300):
    cmd = dict(cmd)
    cmd.setdefault("cmd_id", str(uuid.uuid4()))
    cmd.setdefault("params", {})
    cmd.setdefault("approved_by", None)
    now = int(time.time())
    cmd["iat"], cmd["exp"] = now, now + ttl
    cmd["sig"] = base64.b64encode(priv.sign(canonical(cmd))).decode()
    return cmd

def verify(cmd, pub):
    """Retorna (ok, motivo)."""
    sig = cmd.get("sig")
    if not sig:
        return False, "sem_assinatura"
    try:
        pub.verify(base64.b64decode(sig), canonical(cmd))
    except Exception:
        return False, "assinatura_invalida"
    if int(cmd.get("exp") or 0) < time.time():
        return False, "comando_expirado"
    return True, "ok"
