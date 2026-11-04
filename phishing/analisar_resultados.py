"""Lê o export de resultados do Gophish (CSV) e calcula as métricas da campanha (RT-11).
Uso: python3 analisar_resultados.py resultados_gophish.csv
Sem arquivo, usa um resultado sintético do laboratório para demonstração."""
import csv, json, os, sys
from collections import Counter
DEMO = [
    {"email": "aurora.volunteer@lab.vilaaurora.example", "status": "Submitted Data"},
    {"email": "benedito.volunteer@lab.vilaaurora.example", "status": "Clicked Link"},
    {"email": "cecilia.volunteer@lab.vilaaurora.example", "status": "Email Reported"},
    {"email": "damiao.volunteer@lab.vilaaurora.example", "status": "Email Opened"},
]
def load(path):
    if path and os.path.exists(path):
        return list(csv.DictReader(open(path)))
    return DEMO
def main():
    rows = load(sys.argv[1] if len(sys.argv) > 1 else None)
    n = len(rows)
    order = ["Email Sent", "Email Opened", "Clicked Link", "Submitted Data", "Email Reported"]
    rank = {s: i for i, s in enumerate(order)}
    c = Counter()
    for r in rows:
        st = r.get("status") or r.get("Status") or ""
        lvl = rank.get(st, 0)
        if lvl >= 1: c["abriram"] += 1
        if lvl >= 2: c["clicaram"] += 1
        if lvl >= 3: c["submeteram"] += 1
        if st == "Email Reported": c["reportaram"] += 1
    pct = lambda x: round(100 * x / n, 1) if n else 0
    rep = {"alvos": n, "taxa_abertura_%": pct(c["abriram"]), "taxa_clique_%": pct(c["clicaram"]),
           "taxa_submissao_%": pct(c["submeteram"]), "taxa_reporte_%": pct(c["reportaram"]),
           "observacao": "Somente contas fictícias; senhas não armazenadas. Meta: elevar a taxa de reporte e reduzir submissão após a conscientização."}
    out = os.environ.get("PHISH_OUT", "/tmp/lab/evid/phishing_metricas.json")
    os.makedirs(os.path.dirname(out), exist_ok=True); json.dump(rep, open(out, "w"), ensure_ascii=False, indent=2)
    print(json.dumps(rep, ensure_ascii=False, indent=2))
if __name__ == "__main__":
    main()
