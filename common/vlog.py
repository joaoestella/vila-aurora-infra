"""Log estruturado (JSON por linha, UTC com milissegundos) usado por todos os serviços.
Cada linha tem: ts, host, src, event, sev e campos livres. O SIEM (Wazuh) lê esses arquivos
com log_format json, então os nomes dos campos são o contrato com as regras de detecção."""
import json, os, socket, sys, threading, time
from datetime import datetime, timezone

_lock = threading.Lock()

def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

class VLog:
    def __init__(self, src, path=None, host=None, skew_s=0.0):
        self.src = src
        self.host = host or os.environ.get("NODE_NAME") or socket.gethostname()
        d = os.environ.get("LOG_DIR", "/var/log/vila")
        self.path = path or os.path.join(d, f"{src}.log")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        # skew_s só existe para reproduzir o cenário legado (relógios fora de sincronia)
        self.skew_s = float(os.environ.get("CLOCK_SKEW_S", skew_s) or 0)

    def _ts(self):
        if not self.skew_s:
            return utcnow()
        t = datetime.fromtimestamp(time.time() + self.skew_s, timezone.utc)
        return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def __call__(self, event, sev="info", **kw):
        rec = {"ts": self._ts(), "host": self.host, "src": self.src, "event": event, "sev": sev}
        rec.update(kw)
        line = json.dumps(rec, ensure_ascii=False, default=str)
        with _lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        if os.environ.get("LOG_STDOUT", "1") == "1":
            print(line, file=sys.stdout, flush=True)
        return rec
