"""Simulador dos dispositivos de campo de um espaço comunitário.
Cada dispositivo tem o próprio certificado X.509 e a própria conexão MQTT (mTLS), então não existe
segredo compartilhado entre eles (RT-04). Dados 100% sintéticos.

Injeção de cenários (laboratório): o arquivo SCENARIO_DIR/<espaco>.json pode conter, por exemplo,
  {"cold_excursion": {"until": <epoch>, "peak": 12}}  ou  {"flood": {"until": <epoch>, "cm": 25}}
"""
import json, math, os, random, ssl, sys, threading, time
from datetime import datetime, timezone
import paho.mqtt.client as mqtt

E = os.environ.get
SPACE = E("SPACE", "ubs")
CERT_DIR = E("CERT_DIR", "/pki")
BROKER = E("BROKER_HOST", "edge-ubs")
PORT = int(E("BROKER_PORT", "8883"))
PERIOD = float(E("TELEMETRY_S", "5"))
POLICY = E("POLICY_FILE", f"/app/policies/{SPACE}.json")
DATA = E("DATA_DIR", "/data")
SCEN = E("SCENARIO_DIR", "/scenario")
ONLY = [d for d in E("DEVICES", "").split(",") if d]
os.makedirs(DATA, exist_ok=True)
pol = json.load(open(POLICY, encoding="utf-8"))
DEVS = {d: v["type"] for d, v in pol["devices"].items() if not ONLY or d in ONLY}
rnd = random.Random(int(E("SEED", "42")) + hash(SPACE) % 1000)
W = {"level": 70.0, "pump": False, "battery": 80.0, "siren": False, "flood_cm": 0.0, "temp": 4.8, "safe": False}

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def scenario():
    try:
        s = json.load(open(os.path.join(SCEN, f"{SPACE}.json")))
        return {k: v for k, v in s.items() if v.get("until", 0) > time.time()}
    except Exception:
        return {}

class Dev:
    def __init__(self, name, kind):
        self.name, self.kind = name, kind
        self.seqf = os.path.join(DATA, f"{name}.seq")
        self.seq = int(open(self.seqf).read()) if os.path.exists(self.seqf) else 0
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=name, clean_session=False)
        c.tls_set(ca_certs=f"{CERT_DIR}/ca-chain.crt", certfile=f"{CERT_DIR}/{name}.crt", keyfile=f"{CERT_DIR}/{name}.key",
                  tls_version=ssl.PROTOCOL_TLS_CLIENT)
        c.max_queued_messages_set(2000)
        c.on_connect = lambda cl, u, f, rc, p=None: cl.subscribe(f"va/{name}/cmd", 1)
        c.on_message = self.on_cmd
        c.reconnect_delay_set(1, 30)
        self.c = c

    def on_cmd(self, c, u, m):
        try:
            cmd = json.loads(m.payload)
        except Exception:
            return
        a = cmd.get("action")
        if self.kind == "pump":
            if a == "on": W["pump"], W["safe"] = True, False
            elif a == "off": W["pump"], W["safe"] = False, False
            elif a == "safe_mode": W["safe"] = True
        elif self.kind == "siren":
            W["siren"] = a == "alarm_on"
        self.pub("state", self.values(), extra={"cmd": a, "origin": cmd.get("origin")})

    def values(self):
        s = scenario()
        h = (datetime.now(timezone.utc).hour - 3) % 24
        k = self.kind
        if k == "temperature":
            if "cold_excursion" in s:
                W["temp"] = min(s["cold_excursion"].get("peak", 12), W["temp"] + 0.6)
            else:
                W["temp"] += (4.8 - W["temp"]) * 0.3
            return {"temp_c": round(W["temp"] + rnd.gauss(0, 0.15), 2)}
        if k in ("level", "water_quality"):
            use = 0.10 if 6 <= h < 22 else 0.03
            if W["safe"]:
                W["pump"] = W["level"] < 40 or (W["pump"] and W["level"] < 90)
            W["level"] = max(0, min(100, W["level"] - use * PERIOD / 5 + (0.35 * PERIOD / 5 if W["pump"] else 0) + rnd.gauss(0, 0.05)))
            v = {"level_pct": round(W["level"], 2)}
            if k == "water_quality":
                v.update(turbidity_ntu=round(abs(rnd.gauss(0.8, 0.2)), 2), chlorine_mgl=round(abs(rnd.gauss(1.2, 0.1)), 2))
            return v
        if k == "pump":
            return {"running": W["pump"], "safe_mode": W["safe"]}
        if k == "energy":
            pv = max(0, math.sin(math.pi * (h - 6) / 12)) * 1800 if 6 <= h <= 18 else 0
            load = 600 + rnd.gauss(0, 40)
            W["battery"] = max(5, min(100, W["battery"] + (pv - load) / 36000 * PERIOD))
            return {"pv_w": round(pv), "load_w": round(load), "battery_pct": round(W["battery"], 1),
                    "generator": "on" if W["battery"] < 20 else "off"}
        if k == "flood":
            if "flood" in s:
                W["flood_cm"] = min(s["flood"].get("cm", 25), W["flood_cm"] + 2)
            else:
                W["flood_cm"] = max(0, W["flood_cm"] - 1)
            return {"water_cm": round(W["flood_cm"], 1)}
        if k == "air":
            return {"pm25": round(abs(rnd.gauss(14, 4)), 1), "humidity_pct": round(rnd.gauss(68, 5), 1), "temp_c": round(rnd.gauss(24, 1.5), 1)}
        if k == "siren":
            return {"alarm": W["siren"]}
        if k == "lock":
            return {"door": "principal", "locked": True}
        return {}

    def pub(self, kind, values, extra=None):
        self.seq += 1
        open(self.seqf, "w").write(str(self.seq))
        msg = {"msg_id": f"{self.name}-{kind}-{self.seq}", "device": self.name, "seq": self.seq, "ts": now(),
               "type": self.kind, "values": values}
        if extra:
            msg.update(extra)
        self.c.publish(f"va/{self.name}/{kind}", json.dumps(msg), qos=1)

    def run(self):
        self.c.connect_async(BROKER, PORT, keepalive=30)
        self.c.loop_start()
        time.sleep(rnd.random() * PERIOD)
        while True:
            if self.kind == "lock":
                if rnd.random() < PERIOD / 60:
                    badge = f"VA-{rnd.randint(1, 40):04d}"
                    self.pub("event", {"badge": badge, "door": "principal", "result": rnd.choice(["granted"] * 9 + ["denied"])})
                else:
                    self.pub("telemetry", self.values())
            else:
                self.pub("telemetry", self.values())
            time.sleep(PERIOD)

if __name__ == "__main__":
    print(f"simulando {len(DEVS)} dispositivos em {SPACE}: {', '.join(DEVS)}", flush=True)
    for n, k in DEVS.items():
        threading.Thread(target=Dev(n, k).run, daemon=True).start()
    while True:
        time.sleep(3600)
