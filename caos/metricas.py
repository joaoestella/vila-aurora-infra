"""Consolida as métricas do RT-22 a partir dos logs (node_metrics, alertas, caos)."""
import json, os, sys, glob, statistics as st
from datetime import datetime
LOG = os.environ.get("LOG_DIR", "/tmp/lab/log")
def jlines(path):
    if not os.path.exists(path): return []
    out = []
    for l in open(path, errors="replace"):
        l = l.strip()
        if l.startswith("{"):
            try: out.append(json.loads(l))
            except Exception: pass
    return out
def main():
    nm = [r for f in glob.glob(f"{LOG}/edge-*.log") for r in jlines(f) if r.get("event") == "node_metrics"]
    alerts = jlines(f"{LOG}/alerts.log")
    caos = json.load(open(os.environ.get("CHAOS_OUT", "/tmp/lab/evid/caos.json"))) if os.path.exists(os.environ.get("CHAOS_OUT", "/tmp/lab/evid/caos.json")) else {}
    m = {}
    if nm:
        m["cpu_pct_medio"] = round(st.mean(x["cpu_pct"] for x in nm), 2)
        m["cpu_pct_max"] = round(max(x["cpu_pct"] for x in nm), 2)
        m["mem_mb_medio"] = round(st.mean(x["mem_mb"] for x in nm), 1)
        m["mem_mb_max"] = round(max(x["mem_mb"] for x in nm), 1)
        tx = [x["tx_bytes"] for x in nm]; rx = [x["rx_bytes"] for x in nm]
        m["banda_tx_total_kb"] = round(max(tx) / 1024, 1)
        m["banda_rx_total_kb"] = round(max(rx) / 1024, 1)
        m["amostras_metricas"] = len(nm)
    m["alertas_total"] = len(alerts)
    m["alertas_por_regra"] = {}
    for a in alerts:
        m["alertas_por_regra"][a.get("rule")] = m["alertas_por_regra"].get(a.get("rule"), 0) + 1
    if caos:
        m["caos"] = {k: caos.get(k) for k in ("tempo_operacao_autonoma_s", "backlog_pico", "tempo_reconciliacao_s", "perda_dados", "disponibilidade_local_pct", "minutos_programados")}
    out = os.environ.get("METRICS_OUT", "/tmp/lab/evid/metricas.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(m, open(out, "w"), ensure_ascii=False, indent=2)
    print(json.dumps(m, ensure_ascii=False, indent=2))
if __name__ == "__main__":
    main()
