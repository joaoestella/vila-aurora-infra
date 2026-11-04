"""Teste de caos controlado (RT-23) + métricas (RT-22).
Derruba o link WAN entre a borda e a nuvem por N minutos (padrão 30) e evidencia:
  * a borda continua operando (regras locais, página local, buffer enchendo);
  * ao voltar o link, o store-and-forward reenvia e a reconciliação zera a perda de dados.
No laboratório, 'derrubar o link' = bloquear o acesso da borda à API de ingestão. Aqui fazemos isso
parando/retomando o processo de ingestão (ou, no compose, com uma regra de firewall no serviço de borda).

Uso: python3 chaos_test.py --minutos 30 --saida /evidencias/runtime/caos.json
Mede disponibilidade, MTTD/MTTR aproximados pelos alertas, tempo de operação autônoma e perda na reconciliação.
"""
import argparse, json, os, signal, subprocess, time, urllib.request
from datetime import datetime, timezone

def now(): return datetime.now(timezone.utc).isoformat()

def edge_status(url):
    try:
        return json.load(urllib.request.urlopen(url + "/status.json", timeout=3))
    except Exception as e:
        return {"erro": str(e)}

def count_cloud(psql, db="vila"):
    out = subprocess.run(psql + ["-tAc", "SELECT count(*) FROM telemetria WHERE tipo='telemetry'"], capture_output=True, text=True)
    try: return int(out.stdout.strip())
    except Exception: return -1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutos", type=float, default=float(os.environ.get("CHAOS_MIN", "30")))
    ap.add_argument("--edge", default=os.environ.get("EDGE_URL", "http://127.0.0.1:18080"))
    ap.add_argument("--saida", default=os.environ.get("CHAOS_OUT", "/tmp/lab/evid/caos.json"))
    ap.add_argument("--down", default=os.environ.get("CHAOS_DOWN_CMD", ""))   # comando que derruba o link
    ap.add_argument("--up", default=os.environ.get("CHAOS_UP_CMD", ""))       # comando que restabelece
    ap.add_argument("--psql", default=os.environ.get("PSQL_CMD", ""))
    a = ap.parse_args()
    psql = a.psql.split() if a.psql else None
    rep = {"inicio": now(), "minutos_programados": a.minutos, "amostras": []}
    st0 = edge_status(a.edge)
    rep["backlog_inicial"] = st0.get("backlog")
    cloud0 = count_cloud(psql) if psql else None
    # derruba o link
    print(f"[{now()}] derrubando o link WAN por {a.minutos} min", flush=True)
    if a.down: os.system(a.down)
    t_down = time.time(); first_detect = None
    autonomous_ok = True
    end = t_down + a.minutos * 60
    while time.time() < end:
        s = edge_status(a.edge)
        online = s.get("wan_up")
        if online is False and first_detect is None:
            first_detect = time.time()
        if "erro" in s:    # a página local caiu => perdeu operação autônoma
            autonomous_ok = False
        rep["amostras"].append({"t": round(time.time() - t_down, 1), "wan_up": online, "backlog": s.get("backlog"), "alarms": s.get("alarms", {})})
        time.sleep(max(2, a.minutos * 60 / 60))
    peak_backlog = max((x["backlog"] or 0 for x in rep["amostras"]), default=0)
    # restabelece
    print(f"[{now()}] restabelecendo o link", flush=True)
    if a.up: os.system(a.up)
    t_up = time.time(); drained_at = None
    while time.time() - t_up < 180:
        s = edge_status(a.edge)
        if s.get("wan_up") and (s.get("backlog") or 0) == 0:
            drained_at = time.time(); break
        time.sleep(2)
    time.sleep(5)
    cloud1 = count_cloud(psql) if psql else None
    st1 = edge_status(a.edge)
    outages = st1.get("outages", [])
    dur = a.minutos * 60
    rep.update({
        "fim": now(),
        "operacao_autonoma_ok": autonomous_ok,
        "tempo_operacao_autonoma_s": round((t_up - t_down), 1),
        "backlog_pico": peak_backlog,
        "mttd_link_s": round((first_detect - t_down), 1) if first_detect else None,
        "tempo_reconciliacao_s": round((drained_at - t_up), 1) if drained_at else None,
        "backlog_final": st1.get("backlog"),
        "perda_dados": st1.get("backlog") if st1.get("backlog") else 0,
        "cloud_antes": cloud0, "cloud_depois": cloud1,
        "outages_registrados": outages,
    })
    # disponibilidade da janela observada (borda viva o tempo todo = 100% local)
    vivos = sum(1 for x in rep["amostras"] if "erro" not in x and x.get("backlog") is not None)
    rep["disponibilidade_local_pct"] = round(100 * vivos / max(1, len(rep["amostras"])), 2)
    os.makedirs(os.path.dirname(a.saida), exist_ok=True)
    json.dump(rep, open(a.saida, "w"), ensure_ascii=False, indent=2)
    print(json.dumps({k: rep[k] for k in ("operacao_autonoma_ok", "tempo_operacao_autonoma_s", "backlog_pico", "tempo_reconciliacao_s", "perda_dados", "disponibilidade_local_pct")}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
