"""Demonstração de SPF/DKIM/DMARC (RT-10) com o domínio fictício vilaaurora.example. Só local, sem enviar e-mail."""
import re, sys, os, dkim
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOM, SEL = b"vilaaurora.example", b"vila2026"
regs = open(os.path.join(RAIZ, "phishing", "dns_records.txt"), encoding="utf-8").read()

def txt(nome):
    m = re.search(re.escape(nome) + r'\s+IN TXT\s+"(.*)"', regs)
    return m.group(1) if m else None

spf, dmarc = txt("vilaaurora.example."), txt("_dmarc.vilaaurora.example.")
dkim_pub = txt("vila2026._domainkey.vilaaurora.example.")
print("SPF   :", spf); print("DMARC :", dmarc); print("DKIM  : chave pública publicada (%d bytes)" % len(dkim_pub)); print()

def spf_ok(ip):
    return ip in re.findall(r"ip4:([\d.]+)", spf)
for ip in ("203.0.113.25", "203.0.113.66"):
    print(f"SPF para e-mail vindo de {ip}: {'PASS' if spf_ok(ip) else 'FAIL (-all: barrado)'}")
print()

msg = b"From: Coordenacao <coord@vilaaurora.example>\r\nTo: voluntario@exemplo.test\r\nSubject: Reuniao de sexta\r\n\r\nA reuniao de sexta continua as 19h na escola.\r\n"
priv = open(os.path.join(RAIZ, "dns", "keys", "vila2026.private"), "rb").read()
assinada = dkim.sign(msg, SEL, DOM, priv, include_headers=[b"from", b"to", b"subject"]) + msg
dns = lambda nome, timeout=5: dkim_pub.encode() if nome.startswith(b"vila2026._domainkey") else None
print("DKIM, mensagem original assinada pela coordenação:", "PASS" if dkim.verify(assinada, dnsfunc=dns) else "FAIL")
forjada = assinada.replace(b"19h na escola", b"19h neste link: http://acesso-falso.example")
print("DKIM, mesma mensagem alterada no caminho (golpe)  :", "PASS" if dkim.verify(forjada, dnsfunc=dns) else "FAIL (assinatura não bate)")
print("\nDMARC p=quarantine: o que falha em SPF/DKIM alinhado vai para a quarentena, não para a caixa de entrada.")
