"""Testes automatizados dos controles de segurança (rodam sem subir a stack inteira)."""
import os, sys, json, subprocess, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
import cmdsig

def test_assinatura_comando_valida_e_rejeita():
    import tempfile
    d = tempfile.mkdtemp()
    cmdsig.new_keypair(f"{d}/k", f"{d}/k.pub")
    priv = cmdsig.load_private(f"{d}/k"); pub = cmdsig.load_public(f"{d}/k.pub")
    cmd = cmdsig.sign({"space": "ubs", "device": "ubs-ace-01", "action": "unlock_all", "impact": "high",
                       "requested_by": "ana", "approved_by": "rui"}, priv)
    ok, _ = cmdsig.verify(cmd, pub); assert ok
    # adulterar a ação invalida a assinatura (o que a SQLi faria ao gravar direto)
    cmd["action"] = "unlock_all_forcado"; ok, why = cmdsig.verify(cmd, pub)
    assert not ok and why == "assinatura_invalida"
    # comando sem assinatura é recusado
    ok, why = cmdsig.verify({"action": "x"}, pub); assert not ok and why == "sem_assinatura"

def test_comando_expira():
    import tempfile
    d = tempfile.mkdtemp(); cmdsig.new_keypair(f"{d}/k", f"{d}/k.pub")
    priv = cmdsig.load_private(f"{d}/k"); pub = cmdsig.load_public(f"{d}/k.pub")
    cmd = cmdsig.sign({"space": "ubs", "device": "x", "action": "y", "impact": "low", "requested_by": "a"}, priv, ttl=-1)
    ok, why = cmdsig.verify(cmd, pub); assert not ok and why == "comando_expirado"

def test_guardrails_llm_bloqueiam_tudo():
    out = subprocess.run([sys.executable, "ai/llm_guard.py"], capture_output=True, text=True,
                         env={**os.environ, "LLM_OUT": "/tmp/t_llm.json", "CASOS": "ai/prompt_injection_casos.json"})
    r = json.load(open("/tmp/t_llm.json"))
    assert r["taxa_bloqueio_malicioso"] == 1.0 and r["falsos_bloqueios_benignos"] == 0

def test_validacao_regex_sqli():
    import re
    RE_BUSCA = re.compile(r"^[A-Za-z0-9_ .-]{0,40}$")
    assert RE_BUSCA.fullmatch("Aurora")
    assert not RE_BUSCA.fullmatch("x' OR '1'='1")
    assert not RE_BUSCA.fullmatch("zzz%' UNION SELECT senha--")  # aspas e % barrados; texto puro vira busca literal (parametrizada)

def test_pseudonimizacao_determinista_e_irreversivel():
    import hmac, hashlib
    key = b"lab"; a = "ps_" + hmac.new(key, b"VA-0001", hashlib.sha256).hexdigest()[:16]
    b = "ps_" + hmac.new(key, b"VA-0001", hashlib.sha256).hexdigest()[:16]
    assert a == b and "VA-0001" not in a
