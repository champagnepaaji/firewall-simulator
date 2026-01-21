import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_FILE = os.path.join(BASE_DIR, "audit_log.json")

def _load():
    if not os.path.exists(AUDIT_FILE):
        return []
    with open(AUDIT_FILE, "r") as f:
        return json.load(f)

def _save(data):
    with open(AUDIT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def log_audit(user, action, rule_id, before=None, after=None):
    logs = _load()
    logs.append({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user": user,
        "action": action,
        "rule_id": rule_id,
        "before": before,
        "after": after
    })
    _save(logs)
