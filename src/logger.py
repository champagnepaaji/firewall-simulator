import json
import os
from datetime import datetime

LOG_FILE = "logs.json"


def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return json.load(f)


def save_log(entry):
    logs = load_logs()
    logs.append(entry)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


def log_packet(packet, decision, rule_id=None):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "dst_port": packet.dst_port,
        "protocol": packet.protocol,
        "decision": decision,
        "rule_id": rule_id
    }
    save_log(entry)
