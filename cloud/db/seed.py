"""Popula os bancos com dados 100% SINTÉTICOS e cria os operadores do laboratório.
As senhas e os segredos TOTP gerados vão para secrets/operadores-lab.txt (fora do Git)."""
import hashlib, os, random, secrets, string, sys
from datetime import datetime, timedelta, timezone
import psycopg2, pyotp
from werkzeug.security import generate_password_hash

E = os.environ.get
OUT = E("SECRETS_OUT", "/secrets/operadores-lab.txt")
rnd = random.Random(7)
NOMES = ["Aurora", "Benedito", "Cecília", "Damião", "Elza", "Firmino", "Glória", "Heitor", "Iracema", "Jurandir", "Lindalva",
         "Moacir", "Nair", "Orlando", "Penha", "Quitéria", "Raimundo", "Sebastiana", "Tobias", "Ubirajara", "Valdete", "Wanderley"]
SOBRE = ["Sintético", "Fictício", "de Teste", "Exemplo", "Simulado"]

def pw(n=14):
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n)) + "!9"

def novo():
    c = psycopg2.connect(E("ADMIN_DSN_VILA", "host=db dbname=vila user=postgres"))
    c.autocommit = True
    cur = c.cursor()
    linhas = ["# Operadores do laboratório (dados fictícios). Não versionar.", "login;perfil;senha;totp_secret"]
    for login, nome, perfil in [("ana.coord", "Ana (coordenação)", "coordenacao"), ("rui.coord", "Rui (coordenação)", "coordenacao"),
                                ("bruno.tec", "Bruno (técnico)", "tecnico"), ("carla.op", "Carla (operadora)", "operador"),
                                ("davi.aud", "Davi (auditor)", "auditor")]:
        senha, totp = E(f"PW_{login.replace('.', '_').upper()}") or pw(), pyotp.random_base32()
        cur.execute("INSERT INTO operadores (login,nome_exibicao,perfil,senha_hash,totp_secret) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (login) DO NOTHING",
                    (login, nome, perfil, generate_password_hash(senha), totp))
        if cur.rowcount:
            linhas.append(f"{login};{perfil};{senha};{totp}")
    if len(linhas) > 2:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        open(OUT, "a").write("\n".join(linhas) + "\n")
    print("operadores criados; credenciais em", OUT)

def legado():
    c = psycopg2.connect(E("ADMIN_DSN_LEGADO", "host=db dbname=vila_legado user=postgres"))
    c.autocommit = True
    cur = c.cursor()
    cur.execute("SELECT count(*) FROM usuarios")
    if cur.fetchone()[0]:
        return
    users = []
    for i in range(1, 61):
        n = f"{rnd.choice(NOMES)} {rnd.choice(SOBRE)}"
        perfil = "coordenacao" if i == 1 else ("voluntario" if i < 45 else "morador")
        login = "coord.voluntarios" if i == 1 else f"user{i:03d}"
        senha = E("LEGACY_COORD_PASS", "Primavera2026") if i == 1 else pw(8)
        users.append((n, f"SINT-{i:03d}.{rnd.randint(100,999)}.{rnd.randint(100,999)}-00", f"(19) 9{rnd.randint(1000,9999)}-{rnd.randint(1000,9999)}",
                      f"{login}@vilaaurora.example", login, hashlib.md5(senha.encode()).hexdigest(), perfil))
    cur.executemany("INSERT INTO usuarios (nome,cpf,telefone,email,login,senha_md5,perfil) VALUES (%s,%s,%s,%s,%s,%s,%s)", users)
    base = datetime(2026, 10, 1, 7, 0)
    hist = []
    for k in range(400):
        u = rnd.choice(users)
        hist.append((base + timedelta(minutes=rnd.randint(0, 60 * 24 * 30)), rnd.choice(["ubs", "escola", "centro", "abrigo", "horta"]),
                     "principal", f"VA-{rnd.randint(1,40):04d}", u[0], rnd.choice(["liberado"] * 9 + ["negado"])))
    cur.executemany("INSERT INTO historico_acessos (data_hora,espaco,porta,cracha,nome,resultado) VALUES (%s,%s,%s,%s,%s,%s)", hist)
    print("banco legado populado com dados sintéticos")

if __name__ == "__main__":
    novo()
    legado()
