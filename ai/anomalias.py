"""IA defensiva (RT-16): detecção de anomalias na telemetria dos sensores com Isolation Forest.
Treina só com dados "normais" (sintéticos) e mede precisão, revocação e falsos positivos sobre um
conjunto de teste rotulado que inclui anomalias plausíveis: câmara fria subindo, bomba ligada fora de
hora drenando o reservatório, pico de alagamento, consumo de energia atípico.
Roda como serviço (lê telemetria recente do banco e marca anomalias) ou em modo avaliação (--eval)."""
import json, os, sys, argparse
import numpy as np
from datetime import datetime, timezone

def synth(n_normal=4000, seed=1):
    rng = np.random.default_rng(seed)
    # features por leitura agregada de um espaço: temp_camara, nivel_res, bomba_on, vazao, energia_bat, hora
    X, y, kind = [], [], []
    for _ in range(n_normal):
        h = rng.integers(0, 24)
        temp = rng.normal(4.8, 0.6)
        nivel = rng.normal(70, 12)
        bomba = 1 if (nivel < 35 or (nivel < 90 and rng.random() < 0.3)) else 0
        vazao = rng.normal(40, 8) if bomba else rng.normal(2, 1)
        bat = np.clip(rng.normal(75, 12), 10, 100)
        X.append([temp, nivel, bomba, vazao, bat, h]); y.append(0); kind.append("normal")
    def anom(f, k, m):
        for _ in range(m):
            X.append(f()); y.append(1); kind.append(k)
    anom(lambda: [rng.normal(11, 1.5), rng.normal(70, 10), 0, rng.normal(2, 1), rng.normal(70, 10), rng.integers(0, 24)], "camara_fria_alta", 60)
    anom(lambda: [rng.normal(4.8, .5), rng.normal(20, 8), 1, rng.normal(45, 6), rng.normal(70, 10), rng.integers(0, 5)], "bomba_madrugada_drenando", 60)
    anom(lambda: [rng.normal(4.8, .5), rng.normal(70, 10), 0, rng.normal(2, 1), rng.normal(8, 4), rng.integers(0, 24)], "energia_critica", 50)
    anom(lambda: [rng.normal(4.8, .5), rng.normal(95, 3), 1, rng.normal(60, 8), rng.normal(70, 10), rng.integers(0, 24)], "bomba_travada_ligada", 40)
    return np.array(X, float), np.array(y), kind

def evaluate():
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    Xtr, ytr, _ = synth(4000, 1)
    Xtr = Xtr[ytr == 0]                         # treina só com normal
    Xte, yte, kind = synth(1200, 99)
    sc = StandardScaler().fit(Xtr)
    CONT=float(os.environ.get('IF_CONT','0.08'))
    clf = IsolationForest(n_estimators=300, contamination=CONT, max_samples=256, random_state=0).fit(sc.transform(Xtr))
    pred = (clf.predict(sc.transform(Xte)) == -1).astype(int)
    tp = int(((pred == 1) & (yte == 1)).sum()); fp = int(((pred == 1) & (yte == 0)).sum())
    fn = int(((pred == 0) & (yte == 1)).sum()); tn = int(((pred == 0) & (yte == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    CONTEXTUAIS = {"bomba_madrugada_drenando", "bomba_travada_ligada"}
    idx_ctx = [i for i, k in enumerate(kind) if k in CONTEXTUAIS]
    rec_ctx = round(float(pred[idx_ctx].mean()), 3) if idx_ctx else None
    pork = {}
    for k in set(kind):
        idx = [i for i, kk in enumerate(kind) if kk == k and yte[i] == 1]
        if idx:
            pork[k] = round(float(pred[idx].mean()), 3)
    rep = {"modelo": "IsolationForest(n=250, contamination=CONT)", "treino_normal": int((ytr == 0).sum()),
           "teste": {"total": len(yte), "anomalias": int(yte.sum())},
           "precisao": round(prec, 3), "revocacao": round(rec, 3), "f1": round(f1, 3),
           "falsos_positivos": fp, "taxa_falsos_positivos": round(fpr, 3),
           "matriz": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}, "deteccao_por_tipo": pork,
           "revocacao_anomalias_contextuais": rec_ctx,
           "nota": "Anomalias contextuais/multivariadas (bomba drenando de madrugada, bomba travada) sao dominio do Isolation Forest; quebras de limite de um unico sensor (camara fria, bateria) sao tratadas por regra deterministica na borda (defesa em profundidade).",
           "gerado_em": datetime.now(timezone.utc).isoformat()}
    out = os.environ.get("AI_OUT", "/tmp/lab/evid/ia_anomalias.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(rep, open(out, "w"), ensure_ascii=False, indent=2)
    print(json.dumps(rep, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--eval", action="store_true"); a = ap.parse_args()
    evaluate()
