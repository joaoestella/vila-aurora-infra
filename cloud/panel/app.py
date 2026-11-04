"""Painel de supervisão (versão CORRIGIDA) da Rede Vila Aurora.

Controles (RT-08, RT-09, RT-21):
  * toda consulta ao banco é parametrizada (psycopg2 com %s), nada de montar SQL com texto do usuário;
  * validação de entrada no servidor por lista de permissão (regex e valores fixos);
  * usuário de banco panel_app só com SELECT nas visões e INSERT na auditoria;
  * erro nunca mostra detalhe técnico: a pessoa vê um código, o detalhe vai para o log;
  * login com senha + TOTP (MFA), bloqueio após 5 falhas, perfis operador/tecnico/coordenacao/auditor;
  * comandos de atuador não são gravados pelo painel: vão para o serviço de aprovação, que assina;
  * HTML simples em português, contraste alto, navegação por teclado (WCAG 2.1 AA como referência).
"""
import json, os, re, secrets, ssl, sys, time, uuid
from functools import wraps
import urllib.request
import psycopg2, psycopg2.extras, pyotp
from flask import Flask, request, session, redirect, url_for, render_template_string, abort, g
from werkzeug.security import check_password_hash

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))
sys.path.insert(0, "/app/common")
from vlog import VLog  # noqa: E402

E = os.environ.get
log = VLog("panel")
app = Flask(__name__)
app.secret_key = E("SESSION_KEY") or secrets.token_bytes(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_SECURE=E("COOKIE_SECURE", "1") == "1", PERMANENT_SESSION_LIFETIME=1800)
DSN = E("DB_DSN", "host=db dbname=vila user=panel_app")
APPROVAL = E("APPROVAL_URL", "https://approval:9443")
VPNGATE = E("VPNGATE_URL", "https://vpngate:9445")
CERT_DIR = E("CERT_DIR", "/pki")
ESPACOS = {"centro": "Centro Comunitário", "escola": "Escola Municipal", "ubs": "UBS", "horta": "Horta e Cozinha", "abrigo": "Abrigo"}
PERFIS = ("operador", "tecnico", "coordenacao", "auditor")
RE_BUSCA = re.compile(r"^[A-Za-z0-9_ .-]{0,40}$")
RE_LOGIN = re.compile(r"^[a-z][a-z0-9.]{2,30}$")
RE_DEV = re.compile(r"^[a-z]{2,3}-[a-z]{3}-\d{2}$")

def db():
    if "db" not in g:
        g.db = psycopg2.connect(DSN, connect_timeout=5)
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def _close(e):
    c = g.pop("db", None)
    if c:
        c.close()

def q(sql, args=(), one=False):
    cur = db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, args)
    rows = cur.fetchall() if cur.description else []
    return (rows[0] if rows else None) if one else rows

def auditar(acao, **detalhe):
    try:
        db().cursor().execute("INSERT INTO auditoria (ator, acao, detalhe) VALUES (%s,%s,%s)",
                              (session.get("user", "anonimo"), acao, json.dumps(detalhe, default=str)))
    except Exception as ex:
        log("audit_error", sev="warning", err=str(ex))

def svc_ctx():
    ctx = ssl.create_default_context(cafile=f"{CERT_DIR}/ca-chain.crt")
    ctx.load_cert_chain(f"{CERT_DIR}/svc-panel.crt", f"{CERT_DIR}/svc-panel.key")
    return ctx

def svc_call(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=svc_ctx(), timeout=8) as r:
        return json.loads(r.read())

# ------------------------------------------------------------------ segurança HTTP
@app.before_request
def antes():
    g.rid = uuid.uuid4().hex[:10]
    g.t0 = time.time()
    if request.method == "POST":
        tok = session.get("csrf")
        if not tok or request.form.get("csrf") != tok:
            log("csrf_fail", sev="warning", path=request.path, ip=request.remote_addr)
            abort(400)

@app.after_request
def depois(resp):
    resp.headers.update({
        "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000", "Cache-Control": "no-store"})
    log("http_request", method=request.method, path=request.path, query=request.query_string.decode(errors="replace")[:500],
        params={k: v[:200] for k, v in request.values.items() if k not in ("senha", "codigo", "csrf")},
        status=resp.status_code, user=session.get("user"), role=session.get("perfil"),
        ip=request.headers.get("X-Real-IP", request.remote_addr), rid=g.get("rid"), ms=round((time.time() - g.get("t0", time.time())) * 1000))
    return resp

@app.errorhandler(Exception)
def erro(ex):
    code = getattr(ex, "code", 500)
    if code == 500:
        log("app_error", sev="error", rid=g.get("rid"), err=type(ex).__name__, detail=str(ex)[:300], path=request.path)
    msg = {400: "Pedido inválido.", 401: "Faça login para continuar.", 403: "Seu perfil não tem acesso a esta página.",
           404: "Página não encontrada.", 429: "Muitas tentativas. Espere alguns minutos."}.get(code, "Algo deu errado.")
    return pagina("Erro", f"<p role='alert'>{msg}</p><p>Se precisar de ajuda, informe o código <strong>{g.get('rid')}</strong> à coordenação.</p>"), code

def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]

def requer(*perfis):
    def deco(fn):
        @wraps(fn)
        def w(*a, **k):
            if not session.get("mfa_ok"):
                return redirect(url_for("login"))
            if perfis and session.get("perfil") not in perfis:
                log("rbac_denied", sev="warning", user=session.get("user"), role=session.get("perfil"), path=request.path)
                abort(403)
            return fn(*a, **k)
        return w
    return deco

# ------------------------------------------------------------------ layout acessível
BASE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ titulo }} | Painel Vila Aurora</title><style>
body{font:1.125rem/1.6 system-ui,Arial,sans-serif;color:#111;background:#fff;margin:0}
a{color:#0b3d91}a:focus,button:focus,input:focus,select:focus{outline:3px solid #b35900;outline-offset:2px}
.pular{position:absolute;left:-999px}.pular:focus{left:1rem;top:1rem;background:#fff;padding:.5rem}
header{background:#0b3d2e;color:#fff;padding:.8rem 1rem}header a{color:#fff}nav a{margin-right:1rem}
main{max-width:60rem;margin:auto;padding:1rem}button{font-size:1.1rem;padding:.55rem 1rem;background:#0b3d2e;color:#fff;border:0;border-radius:4px;cursor:pointer}
label{display:block;font-weight:600;margin-top:.8rem}input,select{font-size:1.1rem;padding:.45rem;border:2px solid #333;border-radius:4px;min-width:16rem}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #666;padding:.4rem;text-align:left}th{background:#e8efe9}
.card{border:2px solid #333;border-radius:6px;padding:.8rem;margin:.6rem 0}.alerta{border-color:#8b0000;background:#fdecec}
.ok{color:#0b5d1e;font-weight:700}.ruim{color:#8b0000;font-weight:700}
</style></head><body><a class="pular" href="#conteudo">Pular para o conteúdo</a>
<header><strong>Painel Vila Aurora</strong>{% if user %} &nbsp;|&nbsp; {{ user }} ({{ perfil }})
<nav aria-label="Menu principal"><a href="/">Início</a><a href="/acessos">Histórico de acessos</a><a href="/comandos">Comandos</a>
<a href="/aprovacoes">Aprovações</a><a href="/auditoria">Auditoria</a><a href="/vpn">Acesso VPN</a><a href="/sair">Sair</a></nav>{% endif %}</header>
<main id="conteudo" tabindex="-1"><h1>{{ titulo }}</h1>{{ corpo|safe }}</main></body></html>"""

def pagina(titulo, corpo):
    return render_template_string(BASE, titulo=titulo, corpo=corpo, user=session.get("user"), perfil=session.get("perfil"))

def render(titulo, tpl, **ctx):
    corpo = render_template_string(tpl, csrf=csrf(), **ctx)
    return pagina(titulo, corpo)

# ------------------------------------------------------------------ login + MFA
FALHAS_MAX = 5

@app.route("/login", methods=["GET", "POST"])
def login():
    erro_msg = ""
    if request.method == "POST":
        login_ = request.form.get("login", "").strip().lower()
        senha = request.form.get("senha", "")
        u = q("SELECT * FROM operadores WHERE login=%s AND ativo", (login_,), one=True) if RE_LOGIN.match(login_) else None
        if u and u["bloqueado_ate"] and u["bloqueado_ate"].timestamp() > time.time():
            log("login_locked", sev="warning", user=login_, ip=request.remote_addr)
            erro_msg = "Conta bloqueada por alguns minutos por excesso de tentativas."
        elif u and check_password_hash(u["senha_hash"], senha):
            session.clear(); session["pre_user"] = u["login"]
            log("login_password_ok", user=u["login"], ip=request.remote_addr)
            return redirect(url_for("mfa"))
        else:
            if u:
                f = u["falhas"] + 1
                db().cursor().execute("UPDATE operadores SET falhas=%s, bloqueado_ate=CASE WHEN %s>=%s THEN now()+interval '15 minutes' ELSE NULL END WHERE id=%s",
                                      (f, f, FALHAS_MAX, u["id"]))
            log("login_failed", sev="warning", user=login_[:40], ip=request.remote_addr)
            erro_msg = erro_msg or "Usuário ou senha incorretos."
    return render("Entrar", """{% if erro %}<p role="alert" class="ruim">{{ erro }}</p>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label for="login">Usuário</label><input id="login" name="login" autocomplete="username" required>
<label for="senha">Senha</label><input id="senha" name="senha" type="password" autocomplete="current-password" required>
<p><button>Continuar</button></p></form>
<p>Recebeu e-mail ou áudio pedindo para "atualizar o acesso"? Não clique. Ligue para a coordenação no número da lista impressa.</p>""", erro=erro_msg)

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "pre_user" not in session:
        return redirect(url_for("login"))
    msg = ""
    if request.method == "POST":
        u = q("SELECT * FROM operadores WHERE login=%s", (session["pre_user"],), one=True)
        code = request.form.get("codigo", "").strip()
        if u and re.fullmatch(r"\d{6}", code) and pyotp.TOTP(u["totp_secret"]).verify(code, valid_window=1):
            db().cursor().execute("UPDATE operadores SET falhas=0, bloqueado_ate=NULL WHERE id=%s", (u["id"],))
            session.clear(); session.update(user=u["login"], perfil=u["perfil"], nome=u["nome_exibicao"], mfa_ok=True)
            session.permanent = True
            log("login_success", user=u["login"], role=u["perfil"], ip=request.remote_addr, mfa=True)
            auditar("login", ip=request.remote_addr)
            return redirect(url_for("inicio"))
        log("mfa_failed", sev="warning", user=session.get("pre_user"), ip=request.remote_addr)
        msg = "Código incorreto. Veja o código de 6 números no aplicativo autenticador."
    return render("Confirmação em duas etapas", """{% if msg %}<p role="alert" class="ruim">{{ msg }}</p>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label for="codigo">Código de 6 números do aplicativo</label><input id="codigo" name="codigo" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>
<p><button>Entrar</button></p></form>""", msg=msg)

@app.get("/sair")
def sair():
    log("logout", user=session.get("user"))
    session.clear()
    return redirect(url_for("login"))

# ------------------------------------------------------------------ páginas
def descreve(dev, p):
    v = (p or {}).get("values", {})
    if "temp_c" in v and dev.startswith("ubs-tmp"):
        ok = 2 <= v["temp_c"] <= 8
        return f"{v['temp_c']} °C", ok, "Câmara fria de vacinas"
    if "level_pct" in v:
        return f"{v['level_pct']:.0f}% cheio", v["level_pct"] >= 30, "Reservatório de água"
    if "running" in v:
        return ("ligada" if v["running"] else "desligada") + (" (modo seguro)" if v.get("safe_mode") else ""), True, "Bomba"
    if "water_cm" in v:
        return f"{v['water_cm']} cm de água", v["water_cm"] < 10, "Sensor de alagamento"
    if "battery_pct" in v:
        return f"bateria {v['battery_pct']}%, solar {v['pv_w']} W", v["battery_pct"] >= 20, "Energia"
    if "pm25" in v:
        return f"PM2.5 {v['pm25']}, umidade {v['humidity_pct']}%", v["pm25"] < 35, "Ar"
    if "alarm" in v:
        return "tocando" if v["alarm"] else "desligada", not v["alarm"], "Sirene"
    return "sem dado", True, dev

@app.get("/")
@requer()
def inicio():
    rows = q("SELECT dispositivo, espaco, ts, payload FROM ultimas_leituras ORDER BY espaco, dispositivo")
    ev = q("SELECT ts, espaco, dispositivo, evento, sev FROM eventos WHERE ts > now() - interval '24 hours' AND sev IN ('critical','high') ORDER BY ts DESC LIMIT 10")
    cards = [{"esp": ESPACOS.get(r["espaco"], r["espaco"]), "dev": r["dispositivo"], "ts": r["ts"], **dict(zip(("txt", "ok", "nome"), descreve(r["dispositivo"], r["payload"])))} for r in rows]
    return render("Situação agora", """<h2>Alertas das últimas 24 horas</h2>
{% for e in ev %}<div class="card alerta" role="alert"><strong>ALERTA</strong> {{ e.evento }} em {{ e.espaco }} ({{ e.dispositivo }}), {{ e.ts.strftime('%d/%m %H:%M') }} UTC</div>{% else %}<p class="ok">Nenhum alerta importante.</p>{% endfor %}
<h2>Equipamentos</h2>{% for c in cards %}<div class="card{% if not c.ok %} alerta{% endif %}"><strong>{{ c.esp }}: {{ c.nome }}</strong><br>
{% if c.ok %}<span class="ok">Normal</span>{% else %}<span class="ruim">Atenção</span>{% endif %}: {{ c.txt }}<br><small>Última leitura {{ c.ts.strftime('%d/%m %H:%M:%S') }} UTC</small></div>{% endfor %}""", ev=ev, cards=cards)

@app.get("/acessos")
@requer("tecnico", "coordenacao", "auditor")
def acessos():
    busca = request.args.get("q", "")
    esp = request.args.get("espaco", "")
    if not RE_BUSCA.fullmatch(busca) or (esp and esp not in ESPACOS):
        log("input_rejected", sev="warning", field="q/espaco", value=busca[:120], user=session.get("user"), ip=request.remote_addr)
        abort(400)
    sql = "SELECT ts, espaco, porta, cracha_ps, resultado FROM acessos WHERE (cracha_ps ILIKE %s OR porta ILIKE %s OR resultado ILIKE %s)"
    args = [f"%{busca}%"] * 3
    if esp:
        sql += " AND espaco = %s"; args.append(esp)
    rows = q(sql + " ORDER BY ts DESC LIMIT 100", args)
    return render("Histórico de acessos", """<form method="get" role="search"><label for="q">Buscar por crachá (pseudônimo), porta ou resultado</label>
<input id="q" name="q" value="{{ busca }}" maxlength="40"><label for="espaco">Espaço</label><select id="espaco" name="espaco"><option value="">Todos</option>
{% for k, v in espacos.items() %}<option value="{{ k }}" {% if k == esp %}selected{% endif %}>{{ v }}</option>{% endfor %}</select><p><button>Buscar</button></p></form>
<p>Os crachás aparecem como pseudônimo. Só a coordenação, com registro, pode pedir a reidentificação.</p>
<table><caption>{{ rows|length }} resultado(s)</caption><tr><th scope="col">Quando (UTC)</th><th scope="col">Espaço</th><th scope="col">Porta</th><th scope="col">Crachá</th><th scope="col">Resultado</th></tr>
{% for r in rows %}<tr><td>{{ r.ts.strftime('%d/%m/%Y %H:%M') }}</td><td>{{ r.espaco }}</td><td>{{ r.porta }}</td><td>{{ r.cracha_ps }}</td><td>{{ 'liberado' if r.resultado=='granted' else 'negado' }}</td></tr>{% endfor %}</table>""",
                  busca=busca, esp=esp, espacos=ESPACOS, rows=rows)

ACOES = {"esc-bom-01": ["on", "off", "safe_mode"], "hrt-bom-01": ["on", "off", "safe_mode"], "ubs-ace-01": ["unlock_once", "lock", "unlock_all"],
         "cc-ace-01": ["unlock_once", "lock", "unlock_all"], "abr-ace-01": ["unlock_once", "lock", "unlock_all"], "abr-ene-01": ["generator_on", "generator_off"]}

@app.route("/comandos", methods=["GET", "POST"])
@requer("tecnico", "coordenacao")
def comandos():
    msg = ""
    if request.method == "POST":
        dev, acao, motivo = request.form.get("dispositivo", ""), request.form.get("acao", ""), request.form.get("motivo", "")[:120]
        if dev not in ACOES or acao not in ACOES[dev] or not re.fullmatch(r"[\w .,À-ú-]{3,120}", motivo):
            abort(400)
        espaco = {"esc": "escola", "hrt": "horta", "ubs": "ubs", "cc": "centro", "abr": "abrigo"}[dev.split("-")[0]]
        try:
            r = svc_call(APPROVAL, "/request", {"space": espaco, "device": dev, "action": acao, "params": {"motivo": motivo},
                                                "requested_by": session["user"], "role": session["perfil"]})
            msg = r.get("mensagem", "Pedido registrado.")
            auditar("pedido_comando", dispositivo=dev, acao=acao, resultado=r.get("status"))
        except Exception as ex:
            log("approval_unreachable", sev="warning", err=type(ex).__name__)
            msg = "Serviço de aprovação indisponível. Na borda, o controle local continua funcionando."
    rows = q("SELECT criado_em, espaco, dispositivo, acao, impacto, pedido_por, aprovado_por, status, motivo_ack FROM comandos ORDER BY criado_em DESC LIMIT 20")
    return render("Comandos", """{% if msg %}<p role="status" aria-live="polite"><strong>{{ msg }}</strong></p>{% endif %}
<p>Ações de baixo impacto vão direto para a borda. Ações de alto impacto (desligar bomba, liberar todas as portas, desligar gerador) precisam de aprovação de outra pessoa da coordenação.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><label for="dispositivo">Equipamento</label><select id="dispositivo" name="dispositivo">
{% for d in acoes %}<option>{{ d }}</option>{% endfor %}</select><label for="acao">Ação</label><select id="acao" name="acao">
{% for a in todas %}<option>{{ a }}</option>{% endfor %}</select><label for="motivo">Motivo (obrigatório)</label><input id="motivo" name="motivo" required maxlength="120"><p><button>Enviar pedido</button></p></form>
<table><caption>Últimos comandos</caption><tr><th>Quando</th><th>Equipamento</th><th>Ação</th><th>Impacto</th><th>Pedido</th><th>Aprovado</th><th>Situação</th></tr>
{% for r in rows %}<tr><td>{{ r.criado_em.strftime('%d/%m %H:%M') }}</td><td>{{ r.dispositivo }}</td><td>{{ r.acao }}</td><td>{{ r.impacto }}</td><td>{{ r.pedido_por }}</td><td>{{ r.aprovado_por or '-' }}</td><td>{{ r.status }} {{ r.motivo_ack or '' }}</td></tr>{% endfor %}</table>""",
                  msg=msg, acoes=ACOES, todas=sorted({a for v in ACOES.values() for a in v}), rows=rows)

@app.route("/aprovacoes", methods=["GET", "POST"])
@requer("coordenacao", "auditor")
def aprovacoes():
    msg = ""
    if request.method == "POST":
        if session.get("perfil") != "coordenacao":
            abort(403)
        u = q("SELECT totp_secret FROM operadores WHERE login=%s", (session["user"],), one=True)
        code = request.form.get("codigo", "")
        if not (re.fullmatch(r"\d{6}", code) and pyotp.TOTP(u["totp_secret"]).verify(code, valid_window=1)):
            log("stepup_failed", sev="warning", user=session["user"])
            msg = "Código de confirmação incorreto."
        else:
            try:
                pid = int(request.form.get("id", "0"))
            except ValueError:
                abort(400)
            decisao = request.form.get("decisao")
            if decisao not in ("aprovar", "negar"):
                abort(400)
            r = svc_call(APPROVAL, "/decide", {"id": pid, "decision": decisao, "decided_by": session["user"], "role": session["perfil"], "mfa": True})
            msg = r.get("mensagem", "")
            auditar("decisao_aprovacao", id=pid, decisao=decisao, resultado=r.get("status"))
    rows = q("SELECT id, pedido, pedido_por, origem, status, decidido_por, criado_em FROM aprovacoes ORDER BY criado_em DESC LIMIT 30")
    return render("Aprovações de alto impacto", """{% if msg %}<p role="status"><strong>{{ msg }}</strong></p>{% endif %}
<p>Regra de duas pessoas: quem pediu não pode aprovar. Para decidir, digite o código do aplicativo autenticador de novo.</p>
{% for r in rows %}<div class="card {% if r.status=='pendente' %}alerta{% endif %}"><strong>#{{ r.id }} {{ r.pedido.device }}: {{ r.pedido.action }}</strong> pedido por {{ r.pedido_por }} ({{ r.origem }}) em {{ r.criado_em.strftime('%d/%m %H:%M') }}<br>Motivo: {{ r.pedido.params.motivo }}<br>Situação: {{ r.status }} {{ r.decidido_por or '' }}
{% if r.status=='pendente' and perfil=='coordenacao' %}<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="id" value="{{ r.id }}">
<label for="c{{ r.id }}">Código do autenticador</label><input id="c{{ r.id }}" name="codigo" inputmode="numeric" pattern="[0-9]{6}" required>
<p><button name="decisao" value="aprovar">Aprovar</button> <button name="decisao" value="negar">Negar</button></p></form>{% endif %}</div>{% else %}<p>Nenhum pedido.</p>{% endfor %}""",
                  msg=msg, rows=rows, perfil=session.get("perfil"))

@app.get("/auditoria")
@requer("auditor", "coordenacao")
def auditoria():
    rows = q("SELECT ts, espaco, dispositivo, evento, sev, dados FROM eventos ORDER BY ts DESC LIMIT 50")
    return render("Auditoria e eventos", """<table><caption>Últimos 50 eventos da borda</caption><tr><th>Quando (UTC)</th><th>Espaço</th><th>Origem</th><th>Evento</th><th>Gravidade</th></tr>
{% for r in rows %}<tr><td>{{ r.ts.strftime('%d/%m %H:%M:%S') }}</td><td>{{ r.espaco }}</td><td>{{ r.dispositivo }}</td><td>{{ r.evento }}</td><td>{{ r.sev }}</td></tr>{% endfor %}</table>""", rows=rows)

@app.route("/vpn", methods=["GET", "POST"])
@requer("tecnico", "coordenacao")
def vpn():
    msg = ""
    if request.method == "POST":
        u = q("SELECT totp_secret FROM operadores WHERE login=%s", (session["user"],), one=True)
        code = request.form.get("codigo", "")
        horas = request.form.get("horas", "1")
        if horas not in ("1", "2", "4") or not (re.fullmatch(r"\d{6}", code) and pyotp.TOTP(u["totp_secret"]).verify(code, valid_window=1)):
            log("vpn_mfa_failed", sev="warning", user=session["user"], ip=request.remote_addr)
            msg = "Código incorreto."
        else:
            try:
                r = svc_call(VPNGATE, "/open", {"user": session["user"], "role": session["perfil"], "hours": int(horas), "mfa": True, "ip": request.remote_addr})
                msg = r.get("mensagem", "")
            except Exception as ex:
                log("vpngate_unreachable", sev="warning", err=type(ex).__name__)
                msg = "Portão de VPN indisponível."
    return render("Acesso administrativo pela VPN", """{% if msg %}<p role="status"><strong>{{ msg }}</strong></p>{% endif %}
<p>O acesso administrativo só existe pela VPN e só fica aberto pelo tempo pedido, depois de confirmar o código do autenticador.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><label for="horas">Por quanto tempo</label><select id="horas" name="horas"><option>1</option><option>2</option><option>4</option></select>
<label for="codigo">Código do autenticador</label><input id="codigo" name="codigo" inputmode="numeric" pattern="[0-9]{6}" required><p><button>Liberar meu acesso</button></p></form>""", msg=msg)

if __name__ == "__main__":
    app.run(host=E("BIND", "0.0.0.0"), port=int(E("PORT", "8000")), debug=False)
