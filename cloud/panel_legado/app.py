"""PAINEL LEGADO (VULNERÁVEL DE PROPÓSITO). Usado só para reproduzir o INC-VA-0712 em laboratório isolado.
NÃO USAR EM PRODUÇÃO. Falhas presentes de propósito:
  * busca do histórico de acessos monta SQL concatenando o texto digitado (SQL Injection, CWE-89);
  * usuário de banco painel_legado é SUPERUSER e dono das tabelas;
  * mensagens de erro mostram o erro do banco (vazamento de detalhes);
  * login só com senha (MD5), sem MFA, sem bloqueio;
  * log em texto, horário local e relógio sem NTP (CLOCK_SKEW_S).
"""
import hashlib, os, time
from datetime import datetime, timedelta
import psycopg2
from flask import Flask, request, session, redirect

E = os.environ.get
app = Flask(__name__)
app.secret_key = E("LEGACY_SESSION_KEY", "segredo123")          # falha: segredo fixo
DSN = E("DB_DSN", "host=db dbname=vila_legado user=painel_legado")
LOG = os.path.join(E("LOG_DIR", "/var/log/vila"), "painel_legado_access.log")
SKEW = float(E("CLOCK_SKEW_S", "0"))
MAXLOG = int(E("LEGACY_LOG_MAX_BYTES", "200000"))

def agora_local():
    return datetime.utcnow() + timedelta(seconds=SKEW) - timedelta(hours=3)

@app.after_request
def acesso(resp):
    # log no formato "combined" com hora local, sem fuso; rotação que sobrescreve (falha forense)
    if os.path.exists(LOG) and os.path.getsize(LOG) > MAXLOG:
        open(LOG, "w").close()
    linha = f'{request.remote_addr} - {session.get("user", "-")} [{agora_local().strftime("%d/%b/%Y:%H:%M:%S")}] "{request.method} {request.full_path} HTTP/1.1" {resp.status_code} {resp.calculate_content_length() or 0} "-" "{request.headers.get("User-Agent", "-")}"\n'
    with open(LOG, "a") as f:
        f.write(linha)
    return resp

def con():
    c = psycopg2.connect(DSN)
    c.autocommit = True
    return c

@app.route("/", methods=["GET"])
def inicio():
    if "user" not in session:
        return redirect("/login")
    return ("<h1>Painel de Supervisão (legado)</h1><p>Usuário: " + session["user"] +
            "</p><ul><li><a href='/historico'>Histórico de acessos</a></li><li><a href='/bomba'>Agendamento da bomba</a></li></ul>")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, s = request.form.get("usuario", ""), request.form.get("senha", "")
        cur = con().cursor()
        cur.execute("SELECT login, perfil FROM usuarios WHERE login=%s AND senha_md5=%s", (u, hashlib.md5(s.encode()).hexdigest()))
        r = cur.fetchone()
        if r:
            session["user"] = r[0]
            return redirect("/")
        return "<p>Login inválido</p><a href='/login'>voltar</a>", 401
    return "<form method='post'>Usuário <input name='usuario'> Senha <input name='senha' type='password'><button>Entrar</button></form>"

@app.route("/historico")
def historico():
    if "user" not in session:
        return redirect("/login")
    busca = request.args.get("busca", "")
    sql = ("SELECT data_hora, espaco, porta, cracha, nome, resultado FROM historico_acessos "
           "WHERE nome ILIKE '%" + busca + "%' ORDER BY data_hora DESC LIMIT 50")     # VULNERÁVEL
    try:
        cur = con().cursor()
        cur.execute(sql)
        rows = cur.fetchall() if cur.description else []
    except Exception as ex:
        return f"<h1>Erro no banco</h1><pre>{ex}\n\nSQL: {sql}</pre>", 500             # vaza detalhe
    linhas = "".join(f"<tr>{''.join(f'<td>{c}</td>' for c in r)}</tr>" for r in rows)
    return f"<form>Buscar nome <input name='busca' value='{busca}'><button>Buscar</button></form><table>{linhas}</table>"

@app.route("/bomba")
def bomba():
    if "user" not in session:
        return redirect("/login")
    cur = con().cursor()
    cur.execute("SELECT espaco, bomba, hora_liga, hora_desliga, ativo FROM agendamento_bomba ORDER BY id")
    return "<h1>Agendamento</h1><table>" + "".join(f"<tr><td>{'</td><td>'.join(map(str, r))}</td></tr>" for r in cur.fetchall()) + "</table>"

if __name__ == "__main__":
    app.run(host=E("BIND", "0.0.0.0"), port=int(E("PORT", "8081")))
