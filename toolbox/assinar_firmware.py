"""Diferencial: assinatura de firmware / atualização OTA assinada (Ed25519).
O dispositivo só aceita um firmware cujo manifesto esteja assinado pela chave de release do projeto.
  gerar-chave  -> cria a chave de release
  assinar <arquivo>   -> gera <arquivo>.manifesto.json assinado (versão + sha256 + assinatura)
  verificar <arquivo> <manifesto> <pub>  -> valida antes de "instalar"
"""
import base64, hashlib, json, sys, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()

def gerar(priv, pub):
    k = Ed25519PrivateKey.generate()
    open(priv, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(pub, "wb").write(k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print("chave de release criada")

def assinar(arq, priv, versao):
    k = serialization.load_pem_private_key(open(priv, "rb").read(), None)
    man = {"arquivo": arq.split("/")[-1], "versao": versao, "sha256": sha(arq), "iat": int(time.time())}
    body = json.dumps(man, sort_keys=True, separators=(",", ":")).encode()
    man["assinatura"] = base64.b64encode(k.sign(body)).decode()
    open(arq + ".manifesto.json", "w").write(json.dumps(man, indent=2))
    print(arq + ".manifesto.json gerado")

def verificar(arq, man_path, pub):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    man = json.load(open(man_path))
    sig = base64.b64decode(man.pop("assinatura"))
    body = json.dumps(man, sort_keys=True, separators=(",", ":")).encode()
    pk = serialization.load_pem_public_key(open(pub, "rb").read())
    try:
        pk.verify(sig, body)
    except Exception:
        print("REJEITADO: assinatura inválida"); return 1
    if man["sha256"] != sha(arq):
        print("REJEITADO: hash do firmware não confere (adulterado)"); return 1
    print(f"OK: firmware {man['versao']} íntegro e assinado -> pode instalar"); return 0

if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else ""
    if c == "gerar-chave": gerar(sys.argv[2], sys.argv[3])
    elif c == "assinar": assinar(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "1.0.0")
    elif c == "verificar": sys.exit(verificar(sys.argv[2], sys.argv[3], sys.argv[4]))
    else: print(__doc__)
